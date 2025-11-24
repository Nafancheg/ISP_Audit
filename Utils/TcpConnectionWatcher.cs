using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace IspAudit.Utils
{
    /// <summary>
    /// Ключ соединения для маппинга (LocalPort, Protocol).
    /// Используется для сопоставления сетевой активности с PID процесса.
    /// </summary>
    public readonly record struct ConnectionKey(ushort LocalPort, TransportProtocol Protocol);

    /// <summary>
    /// Полная информация о соединении из таблицы TCP/UDP.
    /// </summary>
    public record struct TcpConnectionInfo(
        IPAddress LocalIp, 
        ushort LocalPort, 
        IPAddress RemoteIp, 
        ushort RemotePort, 
        TransportProtocol Protocol, 
        int ProcessId, 
        int State);

    /// <summary>
    /// Компонент для получения снапшотов активных TCP/UDP соединений и их PID.
    /// Использует IP Helper API (GetExtendedTcpTable/GetExtendedUdpTable).
    /// Заменяет функционал WinDivert Flow Layer в режиме Bypass.
    /// </summary>
    public class TcpConnectionWatcher
    {
        /// <summary>
        /// Получает текущий снапшот всех активных соединений (IPv4 и IPv6).
        /// </summary>
        public Task<List<TcpConnectionInfo>> GetSnapshotAsync(CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                var snapshot = new List<TcpConnectionInfo>();

                // IPv4 TCP
                foreach (var row in GetAllTcpConnections(afInet: true))
                {
                    if (row.ProcessId > 0)
                        snapshot.Add(row.ToInfo());
                }

                // IPv6 TCP
                foreach (var row in GetAllTcpConnections(afInet: false))
                {
                    if (row.ProcessId > 0)
                        snapshot.Add(row.ToInfo());
                }

                // IPv4 UDP
                foreach (var row in GetAllUdpConnections(afInet: true))
                {
                    if (row.ProcessId > 0)
                        snapshot.Add(row.ToInfo());
                }

                // IPv6 UDP
                foreach (var row in GetAllUdpConnections(afInet: false))
                {
                    if (row.ProcessId > 0)
                        snapshot.Add(row.ToInfo());
                }

                return snapshot;
            }, cancellationToken);
        }

        // --- IP Helper API P/Invoke ---

        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, TcpTableClass tblClass, uint reserved = 0);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int dwOutBufLen, bool sort, int ipVersion, UdpTableClass tblClass, uint reserved = 0);

        private enum TcpTableClass
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        private enum UdpTableClass
        {
            UDP_TABLE_BASIC,
            UDP_TABLE_OWNER_PID,
            UDP_TABLE_OWNER_MODULE
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public int owningPid;

            public ushort LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)localPort);
            public int ProcessId => owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;
            public uint localScopeId;
            public uint localPort;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddr;
            public uint remoteScopeId;
            public uint remotePort;
            public uint state;
            public int owningPid;

            public ushort LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)localPort);
            public int ProcessId => owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDPROW_OWNER_PID
        {
            public uint localAddr;
            public uint localPort;
            public int owningPid;

            public ushort LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)localPort);
            public int ProcessId => owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_UDP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;
            public uint localScopeId;
            public uint localPort;
            public int owningPid;

            public ushort LocalPort => (ushort)IPAddress.NetworkToHostOrder((short)localPort);
            public int ProcessId => owningPid;
        }

        private interface IConnectionRow
        {
            ushort LocalPort { get; }
            int ProcessId { get; }
            TcpConnectionInfo ToInfo();
        }

        private readonly struct TcpRowWrapper : IConnectionRow
        {
            private readonly MIB_TCPROW_OWNER_PID _row;
            public TcpRowWrapper(MIB_TCPROW_OWNER_PID row) => _row = row;
            public ushort LocalPort => _row.LocalPort;
            public int ProcessId => _row.ProcessId;
            public TcpConnectionInfo ToInfo()
            {
                return new TcpConnectionInfo(
                    new IPAddress(BitConverter.GetBytes(_row.localAddr)), // Network byte order? Usually host order in struct but let's check
                    _row.LocalPort,
                    new IPAddress(BitConverter.GetBytes(_row.remoteAddr)),
                    (ushort)IPAddress.NetworkToHostOrder((short)_row.remotePort),
                    TransportProtocol.TCP,
                    _row.ProcessId,
                    (int)_row.state
                );
            }
        }

        private readonly struct Tcp6RowWrapper : IConnectionRow
        {
            private readonly MIB_TCP6ROW_OWNER_PID _row;
            public Tcp6RowWrapper(MIB_TCP6ROW_OWNER_PID row) => _row = row;
            public ushort LocalPort => _row.LocalPort;
            public int ProcessId => _row.ProcessId;
            public TcpConnectionInfo ToInfo()
            {
                return new TcpConnectionInfo(
                    new IPAddress(_row.localAddr),
                    _row.LocalPort,
                    new IPAddress(_row.remoteAddr),
                    (ushort)IPAddress.NetworkToHostOrder((short)_row.remotePort),
                    TransportProtocol.TCP,
                    _row.ProcessId,
                    (int)_row.state
                );
            }
        }

        private readonly struct UdpRowWrapper : IConnectionRow
        {
            private readonly MIB_UDPROW_OWNER_PID _row;
            public UdpRowWrapper(MIB_UDPROW_OWNER_PID row) => _row = row;
            public ushort LocalPort => _row.LocalPort;
            public int ProcessId => _row.ProcessId;
            public TcpConnectionInfo ToInfo()
            {
                return new TcpConnectionInfo(
                    new IPAddress(BitConverter.GetBytes(_row.localAddr)),
                    _row.LocalPort,
                    IPAddress.Any, // UDP doesn't have remote in basic table usually, or it's 0.0.0.0
                    0,
                    TransportProtocol.UDP,
                    _row.ProcessId,
                    0
                );
            }
        }

        private readonly struct Udp6RowWrapper : IConnectionRow
        {
            private readonly MIB_UDP6ROW_OWNER_PID _row;
            public Udp6RowWrapper(MIB_UDP6ROW_OWNER_PID row) => _row = row;
            public ushort LocalPort => _row.LocalPort;
            public int ProcessId => _row.ProcessId;
            public TcpConnectionInfo ToInfo()
            {
                return new TcpConnectionInfo(
                    new IPAddress(_row.localAddr),
                    _row.LocalPort,
                    IPAddress.IPv6Any,
                    0,
                    TransportProtocol.UDP,
                    _row.ProcessId,
                    0
                );
            }
        }

        private static IEnumerable<IConnectionRow> GetAllTcpConnections(bool afInet)
        {
            int bufferSize = 0;
            int ipVersion = afInet ? AF_INET : AF_INET6;
            
            // Loop to handle buffer resizing
            for (int i = 0; i < 5; i++)
            {
                uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, ipVersion, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
                if (ret != 0 && ret != 122) // 122 = ERROR_INSUFFICIENT_BUFFER
                    yield break;

                IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    ret = GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, ipVersion, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);
                    if (ret == 122) continue; // Buffer too small, retry
                    if (ret != 0) yield break;

                    int numEntries = Marshal.ReadInt32(tcpTablePtr);
                    IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4); // Skip dwNumEntries

                    // Структуры имеют разный размер и layout для IPv4 и IPv6
                    if (afInet)
                    {
                        int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                        for (int j = 0; j < numEntries; j++)
                        {
                            var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                            yield return new TcpRowWrapper(row);
                            rowPtr = IntPtr.Add(rowPtr, rowSize);
                        }
                    }
                    else
                    {
                        int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
                        for (int j = 0; j < numEntries; j++)
                        {
                            var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                            yield return new Tcp6RowWrapper(row);
                            rowPtr = IntPtr.Add(rowPtr, rowSize);
                        }
                    }
                    yield break; // Success
                }
                finally
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                }
            }
        }

        private static IEnumerable<IConnectionRow> GetAllUdpConnections(bool afInet)
        {
            int bufferSize = 0;
            int ipVersion = afInet ? AF_INET : AF_INET6;
            
            for (int i = 0; i < 5; i++)
            {
                uint ret = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, ipVersion, UdpTableClass.UDP_TABLE_OWNER_PID);
                if (ret != 0 && ret != 122) yield break;

                IntPtr udpTablePtr = Marshal.AllocHGlobal(bufferSize);
                try
                {
                    ret = GetExtendedUdpTable(udpTablePtr, ref bufferSize, true, ipVersion, UdpTableClass.UDP_TABLE_OWNER_PID);
                    if (ret == 122) continue;
                    if (ret != 0) yield break;

                    int numEntries = Marshal.ReadInt32(udpTablePtr);
                    IntPtr rowPtr = IntPtr.Add(udpTablePtr, 4);

                    if (afInet)
                    {
                        int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
                        for (int j = 0; j < numEntries; j++)
                        {
                            var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                            yield return new UdpRowWrapper(row);
                            rowPtr = IntPtr.Add(rowPtr, rowSize);
                        }
                    }
                    else
                    {
                        int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
                        for (int j = 0; j < numEntries; j++)
                        {
                            var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                            yield return new Udp6RowWrapper(row);
                            rowPtr = IntPtr.Add(rowPtr, rowSize);
                        }
                    }
                    yield break;
                }
                finally
                {
                    Marshal.FreeHGlobal(udpTablePtr);
                }
            }
        }
    }
}
