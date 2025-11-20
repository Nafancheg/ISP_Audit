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

        public enum Layer : uint
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

        [StructLayout(LayoutKind.Explicit, Size = 64)]
        public struct Address
        {
            [FieldOffset(0)] public ulong Timestamp;
            [FieldOffset(8)] public Layer Layer;
            [FieldOffset(12)] public byte Event;
            [FieldOffset(13)] public byte Sniffed;
            [FieldOffset(14)] public byte Outbound;
            [FieldOffset(15)] public byte Loopback;
            [FieldOffset(16)] public byte Impostor;
            [FieldOffset(17)] public byte IPv6;
            [FieldOffset(18)] public byte IPChecksum;
            [FieldOffset(19)] public byte TCPChecksum;
            [FieldOffset(20)] public byte UDPChecksum;
            [FieldOffset(21)] public byte Reserved1;
            [FieldOffset(22)] public ushort Reserved2;
            [FieldOffset(24)] public uint IfIdx;
            [FieldOffset(28)] public uint SubIfIdx;
            [FieldOffset(32)] public uint Reserved3;

            // SOCKET layer specific (union)
            [FieldOffset(36)] public SocketInfo Socket;

            public bool IsOutbound => Outbound != 0;
            public bool IsIPv6 => IPv6 != 0;
            public bool IsLoopback => Loopback != 0;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SocketInfo
        {
            public ulong EndpointId;
            public ulong ParentEndpointId;
            public uint ProcessId;
            public AddressV4 LocalAddr;
            public AddressV4 RemoteAddr;
            public ushort LocalPort;
            public ushort RemotePort;
            public byte Protocol;
            private byte _reserved1;
            private ushort _reserved2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct AddressV4
        {
            public uint Data;

            public override string ToString()
            {
                return $"{Data & 0xFF}.{(Data >> 8) & 0xFF}.{(Data >> 16) & 0xFF}.{(Data >> 24) & 0xFF}";
            }
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
