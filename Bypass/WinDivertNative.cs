using System;
using System.ComponentModel;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace IspAudit.Bypass
{
    internal static class WinDivertNative
    {
        public const int ErrorOperationAborted = 995;
        public const int ErrorNoData = 232;
        public const int MaxPacketSize = 0xFFFF;

        public const byte WINDIVERT_EVENT_NETWORK_PACKET = 0;
        public const byte WINDIVERT_EVENT_FLOW_ESTABLISHED = 1;
        public const byte WINDIVERT_EVENT_FLOW_TEARDOWN = 2;

        [Flags]
        public enum OpenFlags : ulong
        {
            None = 0,
            Sniff = 1,
            Drop = 2,
            RecvOnly = 4,
            SendOnly = 8,
            NoInstall = 0x10,
            Fragments = 0x20,
            SynOnly = 0x40,
            Strict = 0x80
        }

        public enum Layer
        {
            Network = 0,
            NetworkForward = 1,
            Flow = 2,
            Socket = 3,
            Reflect = 4
        }

        public enum ShutdownHow : uint
        {
            Receive = 0,
            Send = 1,
            Both = 2
        }

        [StructLayout(LayoutKind.Explicit, Size = 80)]
        public struct Address
        {
            [FieldOffset(0)] public long Timestamp;
            
            // BitFields: Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1, IPChecksum:1, TCPChecksum:1, UDPChecksum:1
            [FieldOffset(8)] public ulong BitFields;

            [FieldOffset(16)] public NetworkData Network;
            [FieldOffset(16)] public FlowData Flow;
            [FieldOffset(16)] public SocketData Socket;

            public Layer Layer => (Layer)(BitFields & 0xFF);
            public byte Event => (byte)((BitFields >> 8) & 0xFF);
            public bool Sniffed => ((BitFields >> 16) & 1) != 0;
            public bool Outbound => ((BitFields >> 17) & 1) != 0;
            public bool Loopback => ((BitFields >> 18) & 1) != 0;
            public bool Impostor => ((BitFields >> 19) & 1) != 0;
            public bool IPv6 => ((BitFields >> 20) & 1) != 0;
            public bool IPChecksum => ((BitFields >> 21) & 1) != 0;
            public bool TCPChecksum => ((BitFields >> 22) & 1) != 0;
            public bool UDPChecksum => ((BitFields >> 23) & 1) != 0;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NetworkData
        {
            public uint IfIdx;
            public uint SubIfIdx;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FlowData
        {
            public ulong EndpointId;
            public ulong ParentEndpointId;
            public uint ProcessId;
            public uint LocalAddr1; public uint LocalAddr2; public uint LocalAddr3; public uint LocalAddr4;
            public uint RemoteAddr1; public uint RemoteAddr2; public uint RemoteAddr3; public uint RemoteAddr4;
            public ushort LocalPort;
            public ushort RemotePort;
            public byte Protocol;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SocketData
        {
            public ulong EndpointId;
            public ulong ParentEndpointId;
            public uint ProcessId;
            public uint LocalAddr1; public uint LocalAddr2; public uint LocalAddr3; public uint LocalAddr4;
            public uint RemoteAddr1; public uint RemoteAddr2; public uint RemoteAddr3; public uint RemoteAddr4;
            public ushort LocalPort;
            public ushort RemotePort;
            public byte Protocol;
        }

        public sealed class SafeHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            public SafeHandle() : base(true)
            {
            }

            protected override bool ReleaseHandle()
            {
                return WinDivertClose(handle);
            }
        }

        public static SafeHandle Open(string filter, Layer layer, short priority, OpenFlags flags)
        {
            var handle = WinDivertOpen(filter, layer, priority, flags);
            if (handle == null || handle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                throw new Win32Exception(error, $"WinDivertOpen не удалось: {error}");
            }

            return handle;
        }

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern SafeHandle WinDivertOpen(string filter, Layer layer, short priority, OpenFlags flags);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertRecv(SafeHandle handle, IntPtr pPacket, uint packetLen, ref Address address, IntPtr pReadLen);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertRecv(SafeHandle handle, byte[] packet, uint packetLen, ref Address address, out uint readLen);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertSend(SafeHandle handle, byte[] packet, uint packetLen, ref Address address, out uint sendLen);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertShutdown(SafeHandle handle, ShutdownHow how);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertClose(IntPtr handle);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertHelperCalcChecksums(byte[] packet, uint packetLen, ref Address address, ulong flags);
    }
}
