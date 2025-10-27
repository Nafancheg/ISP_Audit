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

        [StructLayout(LayoutKind.Sequential)]
        public struct Address
        {
            public ulong Timestamp;
            public Layer Layer;
            public byte Event;
            public byte Flags;
            public short Priority;
            public uint IfIdx;
            public uint SubIfIdx;
            public uint DirectionFlags;
            public ulong Reserved1;
            public ulong Reserved2;

            public bool IsOutbound => (DirectionFlags & 0x1) != 0;
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
