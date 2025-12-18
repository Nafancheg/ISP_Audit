using System.Runtime.CompilerServices;

// Нужен доступ smoke-тестам к internal API (например PacketContext) без reflection.
[assembly: InternalsVisibleTo("TestNetworkApp")]
