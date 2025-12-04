using System;
using System.Net;
using IspAudit.Core.Interfaces;
using IspAudit.Core.Models;
using IspAudit.Bypass;

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
            // Use StrategyMapping to get recommendations
            var rec = StrategyMapping.GetStrategiesFor(tested);
            
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
            else if (tested.DnsOk && tested.TcpOk && tested.TlsOk)
            {
                // Все проверки прошли успешно
                strategy = "NONE";
                action = "OK";
            }
            else
            {
                // Если есть стор состояния, можно дополнить рекомендацию статистикой фейлов,
                // ретрансмиссий и HTTP-редиректов (портал провайдера / DPI).
                string? suffix = null;
                if (_stateStore != null)
                {
                    // Официальное окно по умолчанию – 60 секунд
                    var signals = _stateStore.GetSignals(tested, TimeSpan.FromSeconds(60));
                    var hasProviderLikeRedirect = false;

                    if (signals.FailCount > 0 || signals.RetransmissionCount > 0 || signals.HasHttpRedirectDpi)
                    {
                        suffix = $" (фейлов за {signals.Window.TotalSeconds:0}s: {signals.FailCount}" +
                                 (signals.HardFailCount > 0 ? $", жёстких: {signals.HardFailCount}" : string.Empty);

                        if (signals.RetransmissionCount > 0)
                        {
                            suffix += $", ретрансмиссий: {signals.RetransmissionCount}";
                        }

                        if (signals.HasHttpRedirectDpi && !string.IsNullOrEmpty(signals.RedirectToHost))
                        {
                            suffix += $", HTTP-редирект на {signals.RedirectToHost}";

                            // Грубая эвристика: если SLD исходного хоста и цели редиректа отличаются,
                            // считаем, что это не "обычный" редирект внутри одного домена, а, скорее всего,
                            // портал провайдера / страница блокировки.
                            var sourceHost = tested.Hostname;
                            var targetHost = signals.RedirectToHost;
                            if (!string.IsNullOrEmpty(sourceHost) && !string.IsNullOrEmpty(targetHost))
                            {
                                var sourceSld = GetSecondLevelDomainSafe(sourceHost);
                                var targetSld = GetSecondLevelDomainSafe(targetHost);
                                if (!string.IsNullOrEmpty(sourceSld) &&
                                    !string.IsNullOrEmpty(targetSld) &&
                                    !string.Equals(sourceSld, targetSld, StringComparison.OrdinalIgnoreCase))
                                {
                                    hasProviderLikeRedirect = true;
                                }
                            }
                        }

                        if (hasProviderLikeRedirect)
                        {
                            suffix += ", похоже на портал провайдера/страницу блокировки";
                        }

                        suffix += ")";
                    }

                    // Примитивная эвристика: если много ретрансмиссий и фейлов, а BlockageType пока общий,
                    // усиливаем подозрение на сетевую проблему/DPI, не меняя текст конкретной стратегии.
                    if (signals.HasSignificantRetransmissions && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = "TCP_RETRY_HEAVY" };
                    }

                    // Если есть подозрительный HTTP-редирект, фиксируем это отдельным мягким типом,
                    // не перетирая уже установленный BlockageType от тестера.
                    if (signals.HasHttpRedirectDpi && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = "HTTP_REDIRECT_DPI" };
                    }
                }

                // Use the first applicable strategy if available, otherwise the first manual one
                if (rec.Applicable.Count > 0)
                {
                    strategy = rec.Applicable[0];
                    action = $"Рекомендуемая стратегия: {strategy}" + suffix;
                }
                else if (rec.Manual.Count > 0)
                {
                    strategy = rec.Manual[0];
                    action = $"Требуется ручное вмешательство: {strategy}" + suffix;
                }
                else
                {
                    strategy = "UNKNOWN";
                    action = $"Неизвестная проблема с {tested.Host.RemoteIp}:{tested.Host.RemotePort}" + suffix;
                }
            }
            
            return new HostBlocked(tested, strategy, action);
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

        private static string? GetSecondLevelDomainSafe(string host)
        {
            try
            {
                // Убираем порт, если он есть
                var pureHost = host;
                var colonIndex = pureHost.IndexOf(':');
                if (colonIndex > 0)
                {
                    pureHost = pureHost.Substring(0, colonIndex);
                }

                var parts = pureHost.Split('.');
                if (parts.Length < 2)
                {
                    return pureHost;
                }

                // Берём два последних компонента: example.com, youtube.com и т.п.
                return string.Concat(parts[^2], ".", parts[^1]);
            }
            catch
            {
                return null;
            }
        }
    }
}