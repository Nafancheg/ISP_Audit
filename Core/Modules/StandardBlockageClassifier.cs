using System;
using System.Linq;
using System.Net;
using IspAudit.Core.Diagnostics;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Utils;

namespace IspAudit.Core.Modules
{
    public class StandardBlockageClassifier : IBlockageClassifier
    {
        private readonly IBlockageStateStore? _stateStore;

        public StandardBlockageClassifier()
        {
        }

        public StandardBlockageClassifier(IBlockageStateStore stateStore)
        {
            _stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        }

        public HostBlocked ClassifyBlockage(HostTested tested)
        {
            string action;
            const string strategy = PipelineContract.BypassNone;
            
            // Проверка на Fake IP (198.18.0.0/15): часто используется роутерами/шлюзами для локального редиректа
            // (в т.ч. списки обхода/VPN на уровне роутера). Это важно подсвечивать пользователю.
            if (IsFakeIp(tested.Host.RemoteIp))
            {
                action = $"Обнаружен служебный адрес ({tested.Host.RemoteIp})";
                tested = tested with { BlockageType = BlockageCode.FakeIp };
            }
            // Явный локальный шлюз/роутер — оставляем рекомендацию
            else if (tested.Hostname != null && tested.Hostname.Equals("openwrt.lan", StringComparison.OrdinalIgnoreCase))
            {
                action = "Обнаружен локальный шлюз (openwrt.lan)";
                tested = tested with { BlockageType = BlockageCode.FakeIp };
            }
            else if (tested.BlockageType == BlockageCode.PortClosed)
            {
                // Порт закрыт - не блокировка, просто сервис недоступен
                action = $"Порт {tested.Host.RemotePort} закрыт на {tested.Host.RemoteIp} (не блокировка)";
            }
            else
            {
                // Если DNS проверка не OK, а конкретный BlockageType ещё не выставлен,
                // фиксируем фактуру через DnsStatus (это поле уже нормализовано в BlockageCode).
                // Это делает классификацию детерминированной и полезной для UI.
                if (!tested.DnsOk && string.IsNullOrWhiteSpace(tested.BlockageType) && tested.DnsStatus != BlockageCode.StatusOk)
                {
                    tested = tested with { BlockageType = tested.DnsStatus };
                }

                // Получаем сигналы из стора (если есть)
                BlockageSignals? signals = null;
                if (_stateStore != null)
                {
                    signals = _stateStore.GetSignals(tested, TimeSpan.FromSeconds(60));
                }

                // Проверяем UDP блокировки даже если TCP/TLS OK
                if (tested.DnsOk && tested.TcpOk && tested.TlsOk)
                {
                    if (signals != null && signals.Value.HasUdpBlockage)
                    {
                        // TCP/TLS работает — для браузера это обычно означает успешный откат с QUIC на TCP.
                        // Не считаем это «ошибкой» и не предлагаем bypass-стратегии.
                        tested = tested with { BlockageType = BlockageCode.UdpBlockage };
                        return new HostBlocked(tested, PipelineContract.BypassNone, BlockageCode.StatusOk);
                    }
                    else
                    {
                        // Все проверки прошли успешно
                        action = BlockageCode.StatusOk;
                        return new HostBlocked(tested, strategy, action);
                    }
                }

                // Если есть стор состояния, можно дополнить рекомендацию статистикой фейлов,
                // ретрансмиссий и HTTP-редиректов (портал провайдера / DPI).
                string? suffix = null;
                if (signals != null)
                {
                    var s = signals.Value;
                    var hasProviderLikeRedirect = false;

                    // Формируем суффикс с техническими деталями (скрываем его в UI, если нужно, или показываем в скобках)
                    if (s.FailCount > 0 || s.RetransmissionCount > 0 || s.HasHttpRedirectDpi || s.HasSuspiciousRst || s.HasUdpBlockage)
                    {
                        suffix = $" (фейлов: {s.FailCount}";

                        if (s.RetransmissionCount > 0) suffix += $", потерь пакетов: {s.RetransmissionCount}";
                        if (s.HasSuspiciousRst) suffix += $", {s.SuspiciousRstDetails}";
                        if (s.UdpUnansweredHandshakes > 0) suffix += $", UDP потерь: {s.UdpUnansweredHandshakes}";
                        
                        suffix += ")";
                    }

                    // Анализ редиректов
                    if (s.HasHttpRedirectDpi && !string.IsNullOrEmpty(s.RedirectToHost))
                    {
                        var sourceHost = tested.Hostname;
                        var targetHost = s.RedirectToHost;
                        if (!string.IsNullOrEmpty(sourceHost) && !string.IsNullOrEmpty(targetHost))
                        {
                            var sourceSld = NetUtils.GetMainDomain(sourceHost);
                            var targetSld = NetUtils.GetMainDomain(targetHost);
                            if (!string.IsNullOrEmpty(sourceSld) &&
                                !string.IsNullOrEmpty(targetSld) &&
                                !string.Equals(sourceSld, targetSld, StringComparison.OrdinalIgnoreCase))
                            {
                                hasProviderLikeRedirect = true;
                            }
                        }
                    }

                    // Уточнение типа блокировки на основе сигналов
                    if (s.HasSignificantRetransmissions && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = BlockageCode.TcpRetryHeavy };
                    }

                    if (hasProviderLikeRedirect)
                    {
                        tested = tested with { BlockageType = BlockageCode.HttpRedirectDpi };
                    }
                    else if (s.HasSuspiciousRst && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = BlockageCode.TcpRstInjection };
                    }
                    else if (s.HasUdpBlockage && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = BlockageCode.UdpBlockage };
                    }
                    else if (s.HasHttpRedirectDpi && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = BlockageCode.HttpRedirectDpi };
                    }
                    else if (BlockageCode.Normalize(tested.BlockageType) == BlockageCode.TcpConnectTimeout && s.FailCount >= 3)
                    {
                        // Нормализуем на новый код подтверждённого connect-timeout.
                        tested = tested with { BlockageType = BlockageCode.TcpConnectTimeoutConfirmed };
                    }
                }

                // Формируем человекочитаемое сообщение об ошибке (без предположений)
                string errorDescription = GetFriendlyErrorMessage(tested.BlockageType, tested.Host.RemoteIp.ToString());
                action = $"{errorDescription}{suffix}";
            }
            
            return new HostBlocked(tested, strategy, action);
        }

        private string GetFriendlyErrorMessage(string? blockageType, string ip)
        {
            var normalized = BlockageCode.Normalize(blockageType);
            return normalized switch
            {
                BlockageCode.TcpRstInjection => "Соединение сброшено (TCP RST)",
                BlockageCode.HttpRedirectDpi => "Наблюдается HTTP редирект/заглушка",
                BlockageCode.TcpRetryHeavy => "Наблюдается высокая доля ретрансмиссий TCP",
                BlockageCode.UdpBlockage => "Наблюдаются проблемы с UDP/QUIC",
                BlockageCode.TcpConnectTimeout => "Наблюдается таймаут TCP connect",
                BlockageCode.TcpConnectTimeoutConfirmed => "Наблюдается повторяющийся таймаут TCP connect",
                BlockageCode.TcpConnectionReset => "Наблюдается сброс соединения (TCP reset)",
                BlockageCode.TlsHandshakeTimeout => "Наблюдается таймаут TLS рукопожатия",
                BlockageCode.TlsAuthFailure => "Наблюдается TLS auth failure (ошибка рукопожатия)",
                BlockageCode.DnsFiltered => "DNS: ответ не OK (filtered)",
                BlockageCode.DnsBogus => "DNS: ответ не OK (bogus)",
                BlockageCode.DnsTimeout => "DNS: таймаут резолва",
                BlockageCode.DnsError => "DNS: ошибка резолва",
                _ => $"Неизвестная проблема с {ip}"
            };
        }

        private bool IsFakeIp(IPAddress ip)
        {
            byte[] bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                // 198.18.0.0/15 => 198.18.0.0 - 198.19.255.255
                return bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19);
            }
            return false;
        }
    }
}