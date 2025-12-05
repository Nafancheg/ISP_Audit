using System;
using System.Linq;
using System.Net;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Bypass;
using IspAudit.Utils;

namespace IspAudit.Core.Modules
{
    public class StandardBlockageClassifier : IBlockageClassifier
    {
        private readonly IBlockageStateStore? _stateStore;

        /// <summary>
        /// Set of strategies that are currently active/enabled in the bypass controller.
        /// Used to filter recommendations (don't recommend what's already on).
        /// </summary>
        public HashSet<string> ActiveStrategies { get; set; } = new();

        public StandardBlockageClassifier()
        {
        }

        public StandardBlockageClassifier(IBlockageStateStore stateStore)
        {
            _stateStore = stateStore ?? throw new ArgumentNullException(nameof(stateStore));
        }

        public HostBlocked ClassifyBlockage(HostTested tested)
        {
            string strategy;
            string action;
            
            // Проверка на Fake IP (198.18.0.0/15) или openwrt.lan
            if (IsFakeIp(tested.Host.RemoteIp) || 
                (tested.Hostname != null && tested.Hostname.Equals("openwrt.lan", StringComparison.OrdinalIgnoreCase)))
            {
                strategy = "ROUTER_REDIRECT";
                action = $"Обнаружен служебный адрес ({tested.Hostname ?? tested.Host.RemoteIp.ToString()}). Трафик маршрутизируется через VPN или локальный шлюз.";
                // Обновляем BlockageType в результате теста для UI
                tested = tested with { BlockageType = "FAKE_IP" };
            }
            else if (tested.BlockageType == "PORT_CLOSED")
            {
                // Порт закрыт - не блокировка, просто сервис недоступен
                strategy = "NONE";
                action = $"Порт {tested.Host.RemotePort} закрыт на {tested.Host.RemoteIp} (не блокировка)";
            }
            else
            {
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
                        // TCP работает, но UDP блокируется (типично для QUIC/Games)
                        tested = tested with { BlockageType = "UDP_BLOCKAGE" };
                    }
                    else
                    {
                        // Все проверки прошли успешно
                        strategy = "NONE";
                        action = "OK";
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
                        tested = tested with { BlockageType = "TCP_RETRY_HEAVY" };
                    }

                    if (hasProviderLikeRedirect)
                    {
                        tested = tested with { BlockageType = "HTTP_REDIRECT_DPI" };
                    }
                    else if (s.HasSuspiciousRst && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = "TCP_RST_INJECTION" };
                    }
                    else if (s.HasUdpBlockage && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = "UDP_BLOCKAGE" };
                    }
                    else if (s.HasHttpRedirectDpi && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = "HTTP_REDIRECT_DPI" };
                    }
                    else if (tested.BlockageType == "TCP_TIMEOUT" && s.FailCount >= 3)
                    {
                        tested = tested with { BlockageType = "TCP_TIMEOUT_CONFIRMED" };
                    }
                }

                // Use StrategyMapping to get recommendations based on the refined diagnosis
                var rec = StrategyMapping.GetStrategiesFor(tested);

                // Filter out strategies that are already active
                var availableStrategies = rec.Applicable
                    .Where(s => !ActiveStrategies.Contains(s))
                    .ToList();

                // Формируем человекочитаемое сообщение об ошибке
                string errorDescription = GetFriendlyErrorMessage(tested.BlockageType, tested.Host.RemoteIp.ToString());

                // Use the first applicable strategy if available (skipping active ones)
                if (availableStrategies.Count > 0)
                {
                    strategy = availableStrategies[0];
                    action = $"{errorDescription}{suffix}";
                }
                // If all applicable strategies are active, it means the current strategy is failing
                else if (rec.Applicable.Count > 0)
                {
                    strategy = rec.Applicable[0];
                    action = $"Стратегия {strategy} уже применена, но проблема сохраняется. {errorDescription}{suffix}";
                }
                else if (rec.Manual.Count > 0)
                {
                    strategy = rec.Manual[0];
                    action = $"Требуется ручное вмешательство: {strategy}. {errorDescription}{suffix}";
                }
                else
                {
                    strategy = "UNKNOWN";
                    action = $"{errorDescription}{suffix}";
                }
            }
            
            return new HostBlocked(tested, strategy, action);
        }

        private string GetFriendlyErrorMessage(string? blockageType, string ip)
        {
            return blockageType switch
            {
                "TCP_RST_INJECTION" => "Соединение сброшено (RST Injection). Обнаружено активное вмешательство DPI.",
                "HTTP_REDIRECT_DPI" => "Подмена ответа (HTTP Redirect). Провайдер перенаправляет на страницу-заглушку.",
                "TCP_RETRY_HEAVY" => "Критическая потеря пакетов. Вероятно, DPI отбрасывает пакеты (Blackhole).",
                "UDP_BLOCKAGE" => "Блокировка UDP/QUIC протокола. Игровой трафик или современные веб-протоколы недоступны.",
                "TCP_TIMEOUT" => "Таймаут соединения. Сервер не отвечает.",
                "TCP_TIMEOUT_CONFIRMED" => "Сервер недоступен (подтвержденный таймаут).",
                "TLS_TIMEOUT" => "Таймаут TLS рукопожатия. TCP соединение есть, но шифрование не устанавливается.",
                "TLS_DPI" => "Ошибка TLS. Вероятно, DPI блокирует ClientHello.",
                "DNS_FILTERED" => "DNS-фильтрация. Домен резолвится в неверный IP.",
                "DNS_BOGUS" => "DNS-подмена. Ответ содержит локальный или служебный IP.",
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