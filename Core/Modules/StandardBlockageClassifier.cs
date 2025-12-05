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

                    if (signals.FailCount > 0 || signals.RetransmissionCount > 0 || signals.HasHttpRedirectDpi || signals.HasSuspiciousRst)
                    {
                        suffix = $" (фейлов за {signals.Window.TotalSeconds:0}s: {signals.FailCount}" +
                                 (signals.HardFailCount > 0 ? $", жёстких: {signals.HardFailCount}" : string.Empty);

                        if (signals.RetransmissionCount > 0)
                        {
                            suffix += $", ретрансмиссий: {signals.RetransmissionCount}";
                        }

                        if (signals.HasSuspiciousRst)
                        {
                            suffix += $", {signals.SuspiciousRstDetails}";
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

                    // Если обнаружен явный редирект на другой домен (DPI заглушка),
                    // это более точный диагноз, чем просто ошибка TLS или таймаут.
                    if (hasProviderLikeRedirect)
                    {
                        tested = tested with { BlockageType = "HTTP_REDIRECT_DPI" };
                    }
                    // Если есть подозрительный RST, это явный признак DPI
                    else if (signals.HasSuspiciousRst && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = "TCP_RST_INJECTION" };
                    }
                    // Если просто есть редирект (но домены совпадают или неизвестны),
                    // ставим мягкий тип, только если нет другого.
                    else if (signals.HasHttpRedirectDpi && string.IsNullOrEmpty(tested.BlockageType))
                    {
                        tested = tested with { BlockageType = "HTTP_REDIRECT_DPI" };
                    }
                    // Если это таймаут, но фейлов мало (меньше 3 за минуту), считаем это случайным сбоем
                    // и не пугаем пользователя страшным словом TCP_TIMEOUT.
                    // Но если фейлов много (>3), то это уже подтвержденная проблема.
                    else if (tested.BlockageType == "TCP_TIMEOUT" && signals.FailCount < 3)
                    {
                        // Оставляем TCP_TIMEOUT, но в action будет видно, что фейлов мало.
                        // Можно было бы менять на "TCP_TIMEOUT_FLAKY", но пока не будем ломать маппинг стратегий.
                    }
                    // Если фейлов много, можно усилить вердикт
                    else if (tested.BlockageType == "TCP_TIMEOUT" && signals.FailCount >= 3)
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

                // Use the first applicable strategy if available (skipping active ones)
                if (availableStrategies.Count > 0)
                {
                    strategy = availableStrategies[0];
                    action = $"Рекомендуемая стратегия: {strategy}" + suffix;
                }
                // If all applicable strategies are active, it means the current strategy is failing
                else if (rec.Applicable.Count > 0)
                {
                    strategy = rec.Applicable[0];
                    action = $"Стратегия {strategy} уже применена, но проблема сохраняется" + suffix;
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
    }
}