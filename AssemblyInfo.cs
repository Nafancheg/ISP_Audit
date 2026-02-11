using System.Runtime.CompilerServices;

// Нужен доступ smoke-тестам к internal API (например PacketContext) без reflection.
[assembly: InternalsVisibleTo("TestNetworkApp")]

// Нужен доступ unit-тестам к internal API (PacketContext ctor, ProcessPacketForSmoke).
[assembly: InternalsVisibleTo("ISP_Audit.Tests")]
