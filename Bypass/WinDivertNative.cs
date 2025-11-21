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
        public const byte WINDIVERT_EVENT_FLOW_DELETED = 2;

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

        [StructLayout(LayoutKind.Sequential)]
        public struct Address
        {
            public long Timestamp;

            // Объединённое поле для Layer/Event/флагов/Reserved1 (соответствует UINT32 битовым полям)
            public uint LayerEventFlags;

            // Reserved2
            public uint Reserved2;

            // Union данных слоя размером 64 байта
            public AddressData Data;

            public Layer Layer => (Layer)(LayerEventFlags & 0xFF);
            public byte Event => (byte)((LayerEventFlags >> 8) & 0xFF);
            public bool Sniffed => ((LayerEventFlags >> 16) & 1) != 0;
            public bool Outbound => ((LayerEventFlags >> 17) & 1) != 0;
            public bool Loopback => ((LayerEventFlags >> 18) & 1) != 0;
            public bool Impostor => ((LayerEventFlags >> 19) & 1) != 0;
            public bool IPv6 => ((LayerEventFlags >> 20) & 1) != 0;
            public bool IPChecksum => ((LayerEventFlags >> 21) & 1) != 0;
            public bool TCPChecksum => ((LayerEventFlags >> 22) & 1) != 0;
            public bool UDPChecksum => ((LayerEventFlags >> 23) & 1) != 0;
        }

        // Union для Network/Flow/Socket/Reflect, ровно 64 байта как в WINDIVERT_ADDRESS
        [StructLayout(LayoutKind.Explicit, Size = 64)]
        public struct AddressData
        {
            [FieldOffset(0)] public NetworkData Network;
            [FieldOffset(0)] public FlowData Flow;
            [FieldOffset(0)] public SocketData Socket;
            [FieldOffset(0)] public ReflectData Reflect;
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
            private byte _padding1;
            private ushort _padding2;
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
            private byte _padding1;
            private ushort _padding2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ReflectData
        {
            public long Timestamp;
            public uint ProcessId;
            public Layer Layer;
            public ulong Flags;
            public short Priority;
            private short _padding;
            private uint _reserved1;
            private uint _reserved2;
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
        public static extern bool WinDivertRecv(SafeHandle handle, byte[] packet, uint packetLen, out uint recvLen, out Address addr);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertRecv(SafeHandle handle, IntPtr packet, uint packetLen, out uint recvLen, out Address addr);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WinDivertSend(SafeHandle handle, byte[] packet, uint packetLen, out uint sendLen, in Address addr);

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
