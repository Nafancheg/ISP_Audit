using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Bypass
{
    public enum BypassState
    {
        Disabled,
        Enabling,
        Enabled,
        Disabling,
        Faulted
    }

    public sealed class WinDivertBypassManager : IDisposable
    {
        private readonly object _sync = new();
        private WinDivertNative.SafeHandle? _rstHandle;
        private WinDivertNative.SafeHandle? _tlsHandle;
        private WinDivertNative.SafeHandle? _redirectHandle;
        private CancellationTokenSource? _cts;
        private Task? _rstTask;
        private Task? _tlsTask;
        private Task? _redirectTask;
        private BypassState _state = BypassState.Disabled;
        private Exception? _lastError;
        private IReadOnlyList<RuntimeRedirectRule> _runtimeRedirectRules = Array.Empty<RuntimeRedirectRule>();
        private BypassProfile _profile = BypassProfile.CreateDefault();

        public event EventHandler? StateChanged;

        public static bool IsPlatformSupported => OperatingSystem.IsWindows();

        public static bool HasAdministratorRights
        {
            get
            {
                if (!OperatingSystem.IsWindows()) return false;
                try
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    var principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
                catch
                {
                    return false;
                }
            }
        }

        public BypassState State
        {
            get
            {
                lock (_sync)
                {
                    return _state;
                }
            }
        }

        public Exception? LastError
        {
            get
            {
                lock (_sync)
                {
                    return _lastError;
                }
            }
        }

        public async Task EnableAsync(BypassProfile? profile = null, CancellationToken cancellationToken = default)
        {
            if (!IsPlatformSupported)
            {
                throw new PlatformNotSupportedException("WinDivert поддерживается только на Windows.");
            }
            if (!HasAdministratorRights)
            {
                throw new InvalidOperationException("Для работы WinDivert требуется запуск от имени администратора.");
            }

            lock (_sync)
            {
                if (_state == BypassState.Enabling || _state == BypassState.Enabled)
                {
                    return;
                }
                _state = BypassState.Enabling;
                _lastError = null;
            }
            OnStateChanged();

            profile ??= BypassProfile.CreateDefault();

            try
            {
                await Task.Run(() => Initialize(profile!, cancellationToken), cancellationToken).ConfigureAwait(false);
                lock (_sync)
                {
                    _state = BypassState.Enabled;
                }
                OnStateChanged();
            }
            catch (Exception ex)
            {
                lock (_sync)
                {
                    _state = BypassState.Faulted;
                    _lastError = ex;
                }
                OnStateChanged();
                await DisableAsync().ConfigureAwait(false);
                throw;
            }
        }

        public async Task DisableAsync()
        {
            WinDivertNative.SafeHandle? rstHandle;
            WinDivertNative.SafeHandle? tlsHandle;
            WinDivertNative.SafeHandle? redirectHandle;
            CancellationTokenSource? cts;
            Task? rstTask;
            Task? tlsTask;
            Task? redirectTask;

            bool raiseDisablingEvent = false;
            lock (_sync)
            {
                if (_state == BypassState.Disabled || _state == BypassState.Disabling)
                {
                    return;
                }
                _state = BypassState.Disabling;
                raiseDisablingEvent = true;

                rstHandle = _rstHandle;
                tlsHandle = _tlsHandle;
                redirectHandle = _redirectHandle;
                rstTask = _rstTask;
                tlsTask = _tlsTask;
                redirectTask = _redirectTask;
                cts = _cts;

                _rstHandle = null;
                _tlsHandle = null;
                _redirectHandle = null;
                _rstTask = null;
                _tlsTask = null;
                _redirectTask = null;
                _cts = null;
                _runtimeRedirectRules = Array.Empty<RuntimeRedirectRule>();
            }

            if (raiseDisablingEvent)
            {
                OnStateChanged();
            }

            try
            {
                cts?.Cancel();

                if (rstHandle != null && !rstHandle.IsInvalid)
                {
                    WinDivertNative.WinDivertShutdown(rstHandle, WinDivertNative.ShutdownHow.Both);
                }
                if (tlsHandle != null && !tlsHandle.IsInvalid)
                {
                    WinDivertNative.WinDivertShutdown(tlsHandle, WinDivertNative.ShutdownHow.Both);
                }
                if (redirectHandle != null && !redirectHandle.IsInvalid)
                {
                    WinDivertNative.WinDivertShutdown(redirectHandle, WinDivertNative.ShutdownHow.Both);
                }

                var tasks = new List<Task>();
                if (rstTask != null) tasks.Add(rstTask); // swallow errors later
                if (tlsTask != null) tasks.Add(tlsTask);
                if (redirectTask != null) tasks.Add(redirectTask);

                if (tasks.Count > 0)
                {
                    try
                    {
                        await Task.WhenAll(tasks.Select(t => t.ContinueWith(_ => { }, TaskScheduler.Default))).ConfigureAwait(false);
                    }
                    catch
                    {
                        // игнорируем ошибки при остановке
                    }
                }
            }
            finally
            {
                rstHandle?.Dispose();
                tlsHandle?.Dispose();
                redirectHandle?.Dispose();

                bool raiseDisabledEvent = false;
                lock (_sync)
                {
                    _state = BypassState.Disabled;
                    _lastError = null;
                    _profile = BypassProfile.CreateDefault();
                    raiseDisabledEvent = true;
                }
                if (raiseDisabledEvent)
                {
                    OnStateChanged();
                }
            }
        }

        private void Initialize(BypassProfile profile, CancellationToken cancellationToken)
        {
            if (!NativeLibrary.TryLoad("WinDivert.dll", out var libHandle))
            {
                throw new DllNotFoundException("WinDivert.dll не найден. Поместите библиотеку рядом с исполняемым файлом.");
            }
            NativeLibrary.Free(libHandle); // библиотека останется загруженной благодаря DllImport

            _profile = profile;
            _runtimeRedirectRules = BuildRuntimeRedirects(profile);
            _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            if (profile.DropTcpRst)
            {
                _rstHandle = WinDivertNative.Open("outbound and tcp.Rst == 1", WinDivertNative.Layer.Network, 0,
                    WinDivertNative.OpenFlags.Sniff | WinDivertNative.OpenFlags.Drop | WinDivertNative.OpenFlags.NoInstall);
                _rstTask = Task.Run(() => PumpPackets(_rstHandle!, _cts.Token), _cts.Token);
            }

            if (profile.FragmentTlsClientHello)
            {
                _tlsHandle = WinDivertNative.Open("outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0",
                    WinDivertNative.Layer.Network, 0, WinDivertNative.OpenFlags.NoInstall);
                _tlsTask = Task.Run(() => RunTlsFragmenter(_tlsHandle!, _cts.Token, profile), _cts.Token);
            }

            if (_runtimeRedirectRules.Count > 0)
            {
                _redirectHandle = WinDivertNative.Open(BuildRedirectFilter(_runtimeRedirectRules), WinDivertNative.Layer.Network, 0,
                    WinDivertNative.OpenFlags.NoInstall);
                _redirectTask = Task.Run(() => RunRedirector(_redirectHandle!, _cts.Token, _runtimeRedirectRules), _cts.Token);
            }
        }

        private static IReadOnlyList<RuntimeRedirectRule> BuildRuntimeRedirects(BypassProfile profile)
        {
            var result = new List<RuntimeRedirectRule>();
            foreach (var rule in profile.RedirectRules.Where(r => r.Enabled))
            {
                try
                {
                    var address = rule.GetRedirectAddress();
                    var hosts = new HashSet<IPAddress>();
                    foreach (var host in rule.Hosts)
                    {
                        try
                        {
                            foreach (var ip in Dns.GetHostAddresses(host))
                            {
                                if (ip.AddressFamily == address.AddressFamily)
                                {
                                    hosts.Add(ip);
                                }
                            }
                        }
                        catch
                        {
                            // игнорируем
                        }
                    }

                    result.Add(new RuntimeRedirectRule(rule, address, hosts));
                }
                catch
                {
                    // пропускаем некорректные правила
                }
            }
            return result;
        }

        private static string BuildRedirectFilter(IReadOnlyList<RuntimeRedirectRule> rules)
        {
            var parts = new List<string>();
            foreach (var group in rules.GroupBy(r => r.Rule.Protocol))
            {
                var portConditions = string.Join(" or ", group.Select(r => $"tcp.DstPort == {r.Rule.Port}").Distinct());
                if (group.Key == TransportProtocol.Udp)
                {
                    portConditions = string.Join(" or ", group.Select(r => $"udp.DstPort == {r.Rule.Port}").Distinct());
                    parts.Add("outbound and udp and (" + portConditions + ")");
                }
                else
                {
                    parts.Add("outbound and tcp and (" + portConditions + ")");
                }
            }

            return parts.Count == 0 ? "false" : string.Join(" or ", parts);
        }

        private static void PumpPackets(WinDivertNative.SafeHandle handle, CancellationToken token)
        {
            var buffer = new byte[WinDivertNative.MaxPacketSize];
            var addr = new WinDivertNative.Address();
            while (!token.IsCancellationRequested)
            {
                if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref addr, out _))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == WinDivertNative.ErrorOperationAborted)
                    {
                        break;
                    }
                }
            }
        }

        private static void RunTlsFragmenter(WinDivertNative.SafeHandle handle, CancellationToken token, BypassProfile profile)
        {
            var addr = new WinDivertNative.Address();
            var buffer = new byte[WinDivertNative.MaxPacketSize];
            var sessions = new ConcurrentDictionary<ConnectionKey, bool>();

            while (!token.IsCancellationRequested)
            {
                if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref addr, out var read))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == WinDivertNative.ErrorOperationAborted)
                    {
                        break;
                    }
                    continue;
                }

                int length = (int)read;
                if (!TryParseTcpPacket(buffer, length, out var ipHeaderLength, out var tcpHeaderLength, out var payloadOffset, out var payloadLength, out bool isIpv4))
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                if (!isIpv4)
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                if (payloadLength < profile.TlsFragmentThreshold)
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                if (!IsClientHello(buffer.AsSpan(payloadOffset, payloadLength)))
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                var key = CreateConnectionKey(buffer, ipHeaderLength, tcpHeaderLength, isIpv4);
                if (!sessions.TryAdd(key, true))
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                int firstLen = Math.Min(profile.TlsFirstFragmentSize, payloadLength - 1);
                int secondLen = payloadLength - firstLen;
                if (firstLen <= 0 || secondLen <= 0)
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                var firstPacket = new byte[ipHeaderLength + tcpHeaderLength + firstLen];
                Buffer.BlockCopy(buffer, 0, firstPacket, 0, ipHeaderLength + tcpHeaderLength + firstLen);
                AdjustPacketLengths(firstPacket, ipHeaderLength, tcpHeaderLength, firstLen, isIpv4);
                WinDivertNative.WinDivertHelperCalcChecksums(firstPacket, (uint)firstPacket.Length, ref addr, 0);
                WinDivertNative.WinDivertSend(handle, firstPacket, (uint)firstPacket.Length, ref addr, out _);

                var secondPacket = new byte[ipHeaderLength + tcpHeaderLength + secondLen];
                Buffer.BlockCopy(buffer, 0, secondPacket, 0, ipHeaderLength + tcpHeaderLength);
                Buffer.BlockCopy(buffer, payloadOffset + firstLen, secondPacket, ipHeaderLength + tcpHeaderLength, secondLen);
                IncrementTcpSequence(secondPacket, ipHeaderLength, (uint)firstLen);
                AdjustPacketLengths(secondPacket, ipHeaderLength, tcpHeaderLength, secondLen, isIpv4);
                WinDivertNative.WinDivertHelperCalcChecksums(secondPacket, (uint)secondPacket.Length, ref addr, 0);
                WinDivertNative.WinDivertSend(handle, secondPacket, (uint)secondPacket.Length, ref addr, out _);
            }
        }

        private static void RunRedirector(WinDivertNative.SafeHandle handle, CancellationToken token, IReadOnlyList<RuntimeRedirectRule> rules)
        {
            var buffer = new byte[WinDivertNative.MaxPacketSize];
            var addr = new WinDivertNative.Address();

            while (!token.IsCancellationRequested)
            {
                if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref addr, out var read))
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == WinDivertNative.ErrorOperationAborted)
                    {
                        break;
                    }
                    continue;
                }

                int length = (int)read;
                if (!TryParsePacket(buffer, length, out var protocol, out var ipHeaderLength, out var transportOffset, out var isIpv4))
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(transportOffset + 2, 2));
                var rule = rules.FirstOrDefault(r => r.Rule.Protocol == protocol && r.Rule.Port == dstPort);
                if (rule == null)
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                IPAddress destination = isIpv4
                    ? new IPAddress(BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(16, 4)))
                    : new IPAddress(buffer.AsSpan(24, 16).ToArray());

                if (rule.AllowedDestinations.Count > 0 && !rule.AllowedDestinations.Contains(destination))
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                if (destination.AddressFamily != rule.RedirectAddress.AddressFamily)
                {
                    WinDivertNative.WinDivertSend(handle, buffer, read, ref addr, out _);
                    continue;
                }

                if (rule.RedirectAddress.AddressFamily == AddressFamily.InterNetwork)
                {
                    var bytes = rule.RedirectAddress.GetAddressBytes();
                    Buffer.BlockCopy(bytes, 0, buffer, 16, 4);
                }
                else if (rule.RedirectAddress.AddressFamily == AddressFamily.InterNetworkV6)
                {
                    var bytes = rule.RedirectAddress.GetAddressBytes();
                    Buffer.BlockCopy(bytes, 0, buffer, 24, 16);
                }

                BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(transportOffset + 2, 2), rule.Rule.RedirectPort);

                WinDivertNative.WinDivertHelperCalcChecksums(buffer, (uint)length, ref addr, 0);
                WinDivertNative.WinDivertSend(handle, buffer, (uint)length, ref addr, out _);
            }
        }

        private static bool TryParseTcpPacket(byte[] buffer, int length, out int ipHeaderLength, out int tcpHeaderLength, out int payloadOffset, out int payloadLength, out bool isIpv4)
        {
            ipHeaderLength = tcpHeaderLength = payloadOffset = payloadLength = 0;
            isIpv4 = false;
            if (length < 40) return false;
            int version = buffer[0] >> 4;
            if (version == 4)
            {
                isIpv4 = true;
                ipHeaderLength = (buffer[0] & 0x0F) * 4;
                if (ipHeaderLength < 20 || length < ipHeaderLength + 20) return false;
                tcpHeaderLength = ((buffer[ipHeaderLength + 12] >> 4) & 0xF) * 4;
                if (tcpHeaderLength < 20) return false;
            }
            else if (version == 6)
            {
                isIpv4 = false;
                ipHeaderLength = 40;
                if (length < ipHeaderLength + 20) return false;
                tcpHeaderLength = ((buffer[ipHeaderLength + 12] >> 4) & 0xF) * 4;
                if (tcpHeaderLength < 20) return false;
            }
            else
            {
                return false;
            }

            payloadOffset = ipHeaderLength + tcpHeaderLength;
            if (payloadOffset > length) return false;
            payloadLength = length - payloadOffset;
            return true;
        }

        private static bool TryParsePacket(byte[] buffer, int length, out TransportProtocol protocol, out int ipHeaderLength, out int transportOffset, out bool isIpv4)
        {
            protocol = TransportProtocol.Tcp;
            ipHeaderLength = transportOffset = 0;
            isIpv4 = false;

            int version = buffer[0] >> 4;
            if (version == 4)
            {
                isIpv4 = true;
                ipHeaderLength = (buffer[0] & 0x0F) * 4;
                if (length < ipHeaderLength + 8) return false;
                int protocolNumber = buffer[9];
                if (protocolNumber == 6)
                {
                    protocol = TransportProtocol.Tcp;
                }
                else if (protocolNumber == 17)
                {
                    protocol = TransportProtocol.Udp;
                }
                else
                {
                    return false;
                }
            }
            else if (version == 6)
            {
                isIpv4 = false;
                ipHeaderLength = 40;
                if (length < ipHeaderLength + 8) return false;
                int nextHeader = buffer[6];
                if (nextHeader == 6)
                {
                    protocol = TransportProtocol.Tcp;
                }
                else if (nextHeader == 17)
                {
                    protocol = TransportProtocol.Udp;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            transportOffset = ipHeaderLength;
            return true;
        }

        private static ConnectionKey CreateConnectionKey(byte[] buffer, int ipHeaderLength, int tcpHeaderLength, bool isIpv4)
        {
            if (!isIpv4)
            {
                return ConnectionKey.Empty;
            }

            var srcIp = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(12, 4));
            var dstIp = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(16, 4));
            var srcPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength, 2));
            var dstPort = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(ipHeaderLength + 2, 2));

            return new ConnectionKey(srcIp, dstIp, srcPort, dstPort);
        }

        private static bool IsClientHello(ReadOnlySpan<byte> payload)
        {
            if (payload.Length < 7) return false;
            if (payload[0] != 0x16) return false; // TLS Handshake
            if (payload[5] != 0x01) return false; // ClientHello
            return true;
        }

        private static void AdjustPacketLengths(byte[] packet, int ipHeaderLength, int tcpHeaderLength, int payloadLength, bool isIpv4)
        {
            if (isIpv4)
            {
                ushort total = (ushort)(ipHeaderLength + tcpHeaderLength + payloadLength);
                packet[2] = (byte)(total >> 8);
                packet[3] = (byte)(total & 0xFF);
            }
            else
            {
                ushort payload = (ushort)(tcpHeaderLength + payloadLength);
                packet[4] = (byte)(payload >> 8);
                packet[5] = (byte)(payload & 0xFF);
            }
        }

        private static void IncrementTcpSequence(byte[] packet, int ipHeaderLength, uint delta)
        {
            int offset = ipHeaderLength + 4;
            uint sequence = BinaryPrimitives.ReadUInt32BigEndian(packet.AsSpan(offset, 4));
            sequence += delta;
            BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(offset, 4), sequence);
        }

        private void OnStateChanged()
        {
            StateChanged?.Invoke(this, EventArgs.Empty);
        }

        public void Dispose()
        {
            DisableAsync().GetAwaiter().GetResult();
        }

        private sealed record RuntimeRedirectRule(BypassRedirectRule Rule, IPAddress RedirectAddress, HashSet<IPAddress> AllowedDestinations);

        private readonly struct ConnectionKey : IEquatable<ConnectionKey>
        {
            public static readonly ConnectionKey Empty = new(0, 0, 0, 0);

            public readonly uint SrcIp;
            public readonly uint DstIp;
            public readonly ushort SrcPort;
            public readonly ushort DstPort;

            public ConnectionKey(uint srcIp, uint dstIp, ushort srcPort, ushort dstPort)
            {
                SrcIp = srcIp;
                DstIp = dstIp;
                SrcPort = srcPort;
                DstPort = dstPort;
            }

            public bool Equals(ConnectionKey other)
            {
                return SrcIp == other.SrcIp && DstIp == other.DstIp && SrcPort == other.SrcPort && DstPort == other.DstPort;
            }

            public override bool Equals(object? obj)
            {
                return obj is ConnectionKey other && Equals(other);
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(SrcIp, DstIp, SrcPort, DstPort);
            }
        }
    }
}
