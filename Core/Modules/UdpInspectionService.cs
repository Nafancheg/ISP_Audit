using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading;
using IspAudit.Utils;

namespace IspAudit.Core.Modules
{
    /// <summary>
    /// Сервис для анализа UDP-трафика (DTLS, QUIC).
    /// Детектирует попытки рукопожатий и отсутствие ответов (блокировки).
    /// </summary>
    public class UdpInspectionService
    {
        private readonly ConcurrentDictionary<IPAddress, int> _unansweredHandshakes = new();
        private readonly ConcurrentDictionary<string, long> _flowLastSeen = new(); // Key: "SrcIP:SrcPort-DstIP:DstPort"
        private readonly ConcurrentDictionary<IPAddress, bool> _alertedIps = new();

        public event Action<IPAddress>? OnBlockageDetected;

        public void Attach(NetworkMonitorService monitor)
        {
            monitor.OnPacketReceived += OnPacketReceived;
        }

        public int GetUnansweredHandshakeCount(IPAddress ip)
        {
            return _unansweredHandshakes.TryGetValue(ip, out var count) ? count : 0;
        }

        private void OnPacketReceived(PacketData packet)
        {
            // Простейший парсинг IPv4 + UDP
            // IP Header: min 20 bytes
            if (packet.Buffer.Length < 28) return;

            byte versionIhl = packet.Buffer[0];
            byte version = (byte)(versionIhl >> 4);
            if (version != 4) return; // Пока только IPv4

            byte ihl = (byte)(versionIhl & 0x0F);
            int ipHeaderLen = ihl * 4;

            if (packet.Buffer.Length < ipHeaderLen + 8) return;

            byte protocol = packet.Buffer[9];
            if (protocol != 17) return; // 17 = UDP

            // Extract IPs
            uint srcIpInt = BitConverter.ToUInt32(packet.Buffer, 12);
            uint dstIpInt = BitConverter.ToUInt32(packet.Buffer, 16);
            
            // UDP Header
            int udpSrcPort = (packet.Buffer[ipHeaderLen] << 8) | packet.Buffer[ipHeaderLen + 1];
            int udpDstPort = (packet.Buffer[ipHeaderLen + 2] << 8) | packet.Buffer[ipHeaderLen + 3];
            int udpLen = (packet.Buffer[ipHeaderLen + 4] << 8) | packet.Buffer[ipHeaderLen + 5];

            int payloadOffset = ipHeaderLen + 8;
            int payloadLen = packet.Buffer.Length - payloadOffset;

            if (payloadLen <= 0) return;

            // Анализ Payload
            bool isDtlsClientHello = IsDtlsClientHello(packet.Buffer, payloadOffset, payloadLen);
            bool isQuicInitial = IsQuicInitial(packet.Buffer, payloadOffset, payloadLen);

            if (packet.IsOutbound)
            {
                // Исходящий пакет
                if (isDtlsClientHello || isQuicInitial)
                {
                    // Регистрируем попытку рукопожатия
                    var dstIp = new IPAddress(srcIpInt); // В WinDivert outbound src = local, dst = remote? 
                    // Нет, в WinDivert outbound: Src = Local, Dst = Remote.
                    // Нам нужен Remote IP.
                    var remoteIpBytes = BitConverter.GetBytes(dstIpInt); // Little Endian usually
                    var remoteIp = new IPAddress(remoteIpBytes);

                    int count = _unansweredHandshakes.AddOrUpdate(remoteIp, 1, (_, c) => c + 1);
                    
                    // Если количество безответных рукопожатий превышает порог (например, 5), считаем это блокировкой
                    if (count >= 5 && !_alertedIps.ContainsKey(remoteIp))
                    {
                        _alertedIps.TryAdd(remoteIp, true);
                        OnBlockageDetected?.Invoke(remoteIp);
                    }
                }
            }
            else
            {
                // Входящий пакет (ответ)
                // Если пришел ЛЮБОЙ UDP пакет от хоста, считаем что он жив (частично)
                // Для точности надо бы проверять, что это ServerHello, но пока хватит факта активности.
                
                var srcIpBytes = BitConverter.GetBytes(srcIpInt);
                var remoteIp = new IPAddress(srcIpBytes);

                // Сбрасываем счетчик "безответных", так как ответ получен
                if (_unansweredHandshakes.ContainsKey(remoteIp))
                {
                    _unansweredHandshakes[remoteIp] = 0; // Reset
                    _alertedIps.TryRemove(remoteIp, out _); // Сбрасываем флаг оповещения
                }
            }
        }

        private bool IsDtlsClientHello(byte[] buffer, int offset, int len)
        {
            // DTLS 1.0/1.2 Record Header (13 bytes)
            // Content Type (1) = 22 (Handshake)
            // Version (2) = 0xFEFF or 0xFEFD
            // Epoch (2)
            // Sequence (6)
            // Length (2)
            
            if (len < 13 + 10) return false; // Header + minimal handshake

            if (buffer[offset] != 22) return false; // ContentType: Handshake

            // Check version (DTLS 1.0=0xFEFF, 1.2=0xFEFD, 1.3=?)
            // Star Citizen uses DTLS 1.2 usually
            // byte vMajor = buffer[offset + 1];
            // byte vMinor = buffer[offset + 2];
            
            // Handshake Header inside Record
            // Type (1) = 1 (ClientHello)
            // Length (3)
            // Message Seq (2)
            // Fragment Offset (3)
            // Fragment Length (3)
            
            // Offset + 13 points to Handshake Header
            if (buffer[offset + 13] == 1) // ClientHello
            {
                return true;
            }

            return false;
        }

        private bool IsQuicInitial(byte[] buffer, int offset, int len)
        {
            // QUIC Long Header:
            // First Byte: 1 (Header Form) | 1 (Fixed) | Type (2 bits) | ...
            // Initial Type = 0x00
            // So byte & 0xF0 should be 0xC0 (1100xxxx)
            
            if (len < 1200) return false; // QUIC Initial must be padded to 1200 bytes usually

            byte first = buffer[offset];
            if ((first & 0xC0) == 0xC0) // Long Header + Fixed Bit
            {
                int type = (first & 0x30) >> 4;
                if (type == 0x00) // Initial
                {
                    return true;
                }
            }
            return false;
        }
    }
}
