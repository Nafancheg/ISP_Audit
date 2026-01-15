using System;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using IspAudit;
using IspAudit.Core.Diagnostics;
using IspAudit.Models;
using IspAudit.Utils;

namespace IspAudit.ViewModels
{
    public partial class TestResultsManager
    {
        private sealed class PipelineMessageParser
        {
            private readonly TestResultsManager _m;

            public PipelineMessageParser(TestResultsManager manager)
            {
                _m = manager;
            }

            public void Parse(string msg)
            {
                try
                {
                    // SNI-событие (даёт пользователю понятный ключ сервиса)
                    // Формат: "[SNI] Detected: 64.233.164.91 -> youtube.com"
                    if (msg.Contains("[SNI] Detected:", StringComparison.OrdinalIgnoreCase))
                    {
                        var m = Regex.Match(msg, @"Detected:\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+->\s+(?<host>[^\s\|]+)", RegexOptions.IgnoreCase);
                        if (m.Success)
                        {
                            var ip = m.Groups["ip"].Value.Trim();
                            var host = _m.NormalizeHost(m.Groups["host"].Value.Trim());
                            if (!string.IsNullOrWhiteSpace(ip) && !string.IsNullOrWhiteSpace(host) && host != "-")
                            {
                                // ВАЖНО: SNI может меняться в рамках одного прогона (youtube.com → youtube-ui.l.google.com).
                                // Это НЕ должно «переименовывать» уже показанную пользователю карточку.
                                // Правило:
                                // - если у IP ещё нет маппинга → сохраняем
                                // - мигрируем карточку только пока она IP-ориентированная (Host/Name = IP)
                                // - поздние SNI-события не затирают существующий маппинг и не вызывают миграцию

                                if (!_m._ipToUiKey.TryGetValue(ip, out var existingKey) || string.IsNullOrWhiteSpace(existingKey) || IPAddress.TryParse(existingKey, out _))
                                {
                                    _m._ipToUiKey[ip] = host;
                                }

                                var ipCard = _m.TestResults.FirstOrDefault(t => t.Target.Host == ip || t.Target.FallbackIp == ip);
                                if (ipCard != null)
                                {
                                    var hostLooksLikeIp = IPAddress.TryParse(ipCard.Target.Host, out _);
                                    var nameLooksLikeIp = IPAddress.TryParse(ipCard.Target.Name, out _);

                                    if (hostLooksLikeIp || nameLooksLikeIp)
                                    {
                                        // Миграция только из IP в первый человеко‑понятный ключ
                                        _m.TryMigrateIpCardToNameKey(ip, _m._ipToUiKey[ip]);
                                    }
                                    else
                                    {
                                        // Карточка уже человеко‑понятная: просто обновим SniHost для диагностики (без смены ключа)
                                        var old = ipCard.Target;
                                        if (string.IsNullOrWhiteSpace(old.SniHost) || old.SniHost == "-")
                                        {
                                            ipCard.Target = new Target
                                            {
                                                Name = old.Name,
                                                Host = old.Host,
                                                Service = old.Service,
                                                Critical = old.Critical,
                                                FallbackIp = old.FallbackIp,
                                                SniHost = host,
                                                ReverseDnsHost = old.ReverseDnsHost
                                            };
                                        }
                                    }
                                }
                            }
                        }
                        return;
                    }

                    // Обработка сообщения о фильтрации шума - удаляем карточку
                    if (msg.StartsWith("[NOISE]") || msg.Contains("Шум обнаружен:"))
                    {
                        // Форматы:
                        // "[NOISE] Отфильтрован: hostname"
                        // "[NOISE] Отфильтрован (late): hostname"
                        // "[Collector] Шум обнаружен: IP → hostname"
                        string? host = null;
                        string? ip = null;

                        if (msg.Contains("Отфильтрован"))
                        {
                            host = msg.Split(':').LastOrDefault()?.Trim();
                        }
                        else if (msg.Contains("Шум обнаружен:"))
                        {
                            var parts = msg.Split(new[] { " → " }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length == 2)
                            {
                                ip = parts[0].Split(':').LastOrDefault()?.Trim();
                                host = parts[1].Trim();
                            }
                        }

                        if (!string.IsNullOrEmpty(host) || !string.IsNullOrEmpty(ip))
                        {
                            var toRemove = _m.TestResults.FirstOrDefault(t =>
                                (!string.IsNullOrEmpty(host) && (t.Target.Host.Equals(host, StringComparison.OrdinalIgnoreCase) || t.Target.Name.Equals(host, StringComparison.OrdinalIgnoreCase))) ||
                                (!string.IsNullOrEmpty(ip) && (t.Target.Host == ip || t.Target.FallbackIp == ip)));
                            if (toRemove != null)
                            {
                                // Важно: шум должен скрывать только «OK/успех».
                                // Карточки с ошибками/предупреждениями не удаляем, иначе теряем лицевой эффект.
                                if (toRemove.Status == TestStatus.Pass || toRemove.Status == TestStatus.Idle || toRemove.Status == TestStatus.Running)
                                {
                                    _m.TestResults.Remove(toRemove);
                                    _m.Log($"[UI] Удалена шумовая карточка: {host ?? ip}");
                                    _m.NotifyCountersChanged();
                                }
                            }
                        }
                        return;
                    }

                    if (msg.StartsWith("✓ "))
                    {
                        // Формат: "✓ hostname:port (20ms)" или "✓ 1.2.3.4:port (20ms)"
                        var parts = msg.Substring(2).Split(' ');
                        var hostPort = parts[0].Split(':');
                        if (hostPort.Length == 2)
                        {
                            var host = hostPort[0];
                            var uiKey = _m.SelectUiKey(host, msg);
                            var fallbackIp = IPAddress.TryParse(host, out _) ? host : null;

                            // КРИТИЧНО: Проверяем на шум - не создаём карточку для успешных шумовых хостов
                            if (NoiseHostFilter.Instance.IsNoiseHost(host))
                            {
                                // Удаляем карточку, если она была создана ранее (ищем по всем полям)
                                var toRemove = _m.TestResults.FirstOrDefault(t =>
                                    t.Target.Host.Equals(host, StringComparison.OrdinalIgnoreCase) ||
                                    t.Target.Name.Equals(host, StringComparison.OrdinalIgnoreCase) ||
                                    t.Target.FallbackIp == host);
                                if (toRemove != null)
                                {
                                    _m.TestResults.Remove(toRemove);
                                    _m.Log($"[UI] Удалена шумовая карточка (успех): {host}");
                                    _m.NotifyCountersChanged();
                                }
                                return;
                            }

                            // Обновляем существующую карточку или создаём новую
                            _m.UpdateTestResult(uiKey, TestStatus.Pass, StripNameTokens(msg), fallbackIp);
                            SetLastUpdatedHost(uiKey);

                            ApplyNameTokensFromMessage(uiKey, msg);
                        }
                    }
                    else if (msg.Contains("[Collector] Новое соединение"))
                    {
                        // Формат: "[Collector] Новое соединение #1: hostname:443 (proto=6, pid=3796)"
                        // или:    "[Collector] Новое соединение #1: 142.251.38.142:443 (proto=6, pid=3796)"
                        var parts = msg.Split(new[] { ": " }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length >= 2)
                        {
                            var hostPortPart = parts[1].Split(' ')[0]; // "hostname:443" или "142.251.38.142:443"
                            var hostPort = hostPortPart.Split(':');
                            if (hostPort.Length == 2)
                            {
                                var host = hostPort[0];

                                // Если по IP уже известен SNI/hostname, используем его как ключ карточки.
                                var uiKey = _m.SelectUiKey(host, msg);
                                var fallbackIp = IPAddress.TryParse(host, out _) ? host : null;

                                // Фильтр уже применён в TrafficCollector, но проверим ещё раз
                                if (NoiseHostFilter.Instance.IsNoiseHost(host))
                                {
                                    return;
                                }

                                // ВАЖНО: событие "Новое соединение" может прийти позже итогового результата теста.
                                // Не перетираем Pass/Fail/Warn обратно в Running, иначе UI выглядит "зависшим".
                                var existing = _m.TestResults.FirstOrDefault(t =>
                                    t.Target.Host.Equals(uiKey, StringComparison.OrdinalIgnoreCase) ||
                                    t.Target.Name.Equals(uiKey, StringComparison.OrdinalIgnoreCase) ||
                                    (!string.IsNullOrEmpty(fallbackIp) && t.Target.FallbackIp == fallbackIp));
                                if (existing == null || existing.Status == TestStatus.Idle || existing.Status == TestStatus.Running)
                                {
                                    _m.UpdateTestResult(uiKey, TestStatus.Running, "Обнаружено соединение...", fallbackIp);
                                    SetLastUpdatedHost(uiKey);
                                }

                                ApplyNameTokensFromMessage(uiKey, msg);
                            }
                        }
                    }
                    else if (msg.Contains("[Collector] Hostname обновлен"))
                    {
                        // Формат: "[Collector] Hostname обновлен: 142.251.38.142 → google.com"
                        var parts = msg.Split(new[] { " → " }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 2)
                        {
                            var ipPart = parts[0].Split(new[] { ": " }, StringSplitOptions.RemoveEmptyEntries).Last();
                            var newHostname = parts[1].Trim();

                            // Находим карточку по IP-якорю (Host=IP или FallbackIp=IP)
                            var existingByIp = _m.TestResults.FirstOrDefault(t => t.Target.Host == ipPart || t.Target.FallbackIp == ipPart);

                            // КРИТИЧНО: Проверяем, не является ли новый hostname шумовым
                            if (NoiseHostFilter.Instance.IsNoiseHost(newHostname))
                            {
                                // Шумовое reverse/DNS имя (например *.1e100.net) НЕ должно удалять карточку.
                                // Это вызывает «скачки»/подмену карточек и ломает UX.
                                if (existingByIp != null)
                                {
                                    var old = existingByIp.Target;
                                    existingByIp.Target = new Target
                                    {
                                        Name = old.Name,
                                        Host = old.Host,
                                        Service = old.Service,
                                        Critical = old.Critical,
                                        FallbackIp = old.FallbackIp,
                                        SniHost = old.SniHost,
                                        ReverseDnsHost = newHostname
                                    };
                                }
                                return;
                            }

                            // Если это не шумовой hostname, используем его как человеко‑понятный ключ.
                            // IP остаётся как технический якорь (FallbackIp) для корреляции.
                            if (existingByIp != null)
                            {
                                // ВАЖНО: если карточка уже привязана к человеко-понятному ключу (например SNI youtube.com),
                                // не перетираем её на DNS/hostname обновления (youtube-ui.l.google.com и т.п.).
                                // Иначе пользователь видит «подмену» карточки.
                                var hostLooksLikeIp = IPAddress.TryParse(existingByIp.Target.Host, out _);
                                var nameLooksLikeIp = IPAddress.TryParse(existingByIp.Target.Name, out _);

                                var normalizedHostname = _m.NormalizeHost(newHostname);
                                if (!string.IsNullOrWhiteSpace(normalizedHostname) && normalizedHostname != "-" && !IPAddress.TryParse(normalizedHostname, out _))
                                {
                                    // Мигрируем только пока карточка реально IP-ориентированная.
                                    // Если она уже переименована по SNI — сохраняем hostname только как rDNS.
                                    if (hostLooksLikeIp || nameLooksLikeIp)
                                    {
                                        // Не затираем уже установленное сопоставление IP→SNI.
                                        if (!_m._ipToUiKey.ContainsKey(ipPart))
                                        {
                                            _m._ipToUiKey[ipPart] = normalizedHostname;
                                        }
                                        _m.TryMigrateIpCardToNameKey(ipPart, normalizedHostname);
                                    }
                                }

                                if (string.IsNullOrWhiteSpace(existingByIp.Target.SniHost))
                                {
                                    // Если SNI ещё не пойман — заполняем колонку SNI DNS-именем
                                    var old = existingByIp.Target;
                                    existingByIp.Target = new Target
                                    {
                                        Name = old.Name,
                                        Host = old.Host,
                                        Service = old.Service,
                                        Critical = old.Critical,
                                        FallbackIp = old.FallbackIp,
                                        SniHost = newHostname,
                                        ReverseDnsHost = old.ReverseDnsHost
                                    };
                                }

                                // Всегда сохраняем последнее hostname как rDNS для диагностики.
                                if (string.IsNullOrWhiteSpace(existingByIp.Target.ReverseDnsHost))
                                {
                                    var old2 = existingByIp.Target;
                                    existingByIp.Target = new Target
                                    {
                                        Name = old2.Name,
                                        Host = old2.Host,
                                        Service = old2.Service,
                                        Critical = old2.Critical,
                                        FallbackIp = old2.FallbackIp,
                                        SniHost = old2.SniHost,
                                        ReverseDnsHost = newHostname
                                    };
                                }
                            }
                        }
                    }
                    else if (msg.StartsWith("❌ "))
                    {
                        // Формат: "❌ 1.2.3.4:443 | DNS:✓ TCP:✓ TLS:✗ | TLS_AUTH_FAILURE"
                        var parts = msg.Substring(2).Split('|');
                        if (parts.Length > 0)
                        {
                            var hostPortStr = parts[0].Trim().Split(' ')[0];
                            var hostPort = hostPortStr.Split(':');
                            if (hostPort.Length == 2)
                            {
                                var host = hostPort[0];
                                var uiKey = _m.SelectUiKey(host, msg);
                                var fallbackIp = IPAddress.TryParse(host, out _) ? host : null;

                                // КРИТИЧНО: Проверяем на шум перед созданием карточки ошибки
                                if (NoiseHostFilter.Instance.IsNoiseHost(host))
                                {
                                    // Удаляем существующую карточку (ищем по всем полям)
                                    var toRemove = _m.TestResults.FirstOrDefault(t =>
                                        t.Target.Host.Equals(host, StringComparison.OrdinalIgnoreCase) ||
                                        t.Target.Name.Equals(host, StringComparison.OrdinalIgnoreCase) ||
                                        t.Target.FallbackIp == host);
                                    if (toRemove != null)
                                    {
                                        _m.TestResults.Remove(toRemove);
                                        _m.Log($"[UI] Удалена шумовая карточка при ошибке: {host}");
                                        _m.NotifyCountersChanged();
                                    }
                                    return;
                                }

                                // Если цель - IP адрес, убираем "DNS:✓" из сообщения
                                if (IPAddress.TryParse(host, out _))
                                {
                                    msg = msg.Replace("DNS:✓ ", "").Replace("DNS:✓", "");
                                }

                                var status = TestStatus.Fail;
                                var hasTlsAuthFailure = BlockageCode.ContainsCode(msg, BlockageCode.TlsAuthFailure);
                                if (hasTlsAuthFailure)
                                {
                                    msg += "\nℹ️ TLS рукопожатие завершилось ошибкой аутентификации (auth failure). Это факт, но не доказательство DPI.";

                                    var heuristic = _m.AnalyzeHeuristicSeverity(host);
                                    if (heuristic.status == TestStatus.Warn)
                                    {
                                        status = TestStatus.Warn;
                                        msg += $"\n⚠️ {heuristic.note}";
                                    }
                                    else
                                    {
                                        bool isRelatedToPassing = _m.TestResults.Any(t =>
                                            t.Status == TestStatus.Pass &&
                                            _m.AreHostsRelated(t.Target, host));

                                        if (isRelatedToPassing)
                                        {
                                            status = TestStatus.Warn;
                                            msg += " Связанный сервис доступен, вероятно это частичная блокировка или служебный запрос.";
                                        }
                                    }
                                }

                                _m.UpdateTestResult(uiKey, status, StripNameTokens(msg), fallbackIp);
                                SetLastUpdatedHost(uiKey);

                                ApplyNameTokensFromMessage(uiKey, msg);
                            }
                        }
                    }
                    else if (msg.StartsWith("✓✓ "))
                    {
                        // Успешный bypass
                        var match = Regex.Match(msg, @"! (.*?) теперь доступен");
                        if (match.Success)
                        {
                            var hostPort = match.Groups[1].Value.Trim();
                            var host = hostPort.Split(':')[0];

                            var existing = _m.TestResults.FirstOrDefault(t =>
                                t.Target.Host == host || t.Target.Name == host);
                            var newDetails = msg;
                            if (existing != null && !string.IsNullOrEmpty(existing.Details))
                            {
                                newDetails = existing.Details + "\n" + msg;
                            }

                            _m.UpdateTestResult(host, TestStatus.Pass, newDetails);
                            SetLastUpdatedHost(host);
                        }
                    }
                    else if (msg.StartsWith("✗ ") && !string.IsNullOrEmpty(_m._lastUpdatedHost))
                    {
                        // Неудачный bypass
                        var existing = _m.TestResults.FirstOrDefault(t =>
                            t.Target.Host == _m._lastUpdatedHost || t.Target.Name == _m._lastUpdatedHost);
                        if (existing != null)
                        {
                            existing.Details += "\n" + msg;
                        }
                    }
                    else if ((msg.Contains("→ Стратегия:") || msg.Contains("💡 Рекомендация:")) && !string.IsNullOrEmpty(_m._lastUpdatedHost))
                    {
                        var targetHostKey = _m._lastUpdatedHost;
                        if (!string.IsNullOrWhiteSpace(targetHostKey) && NoiseHostFilter.Instance.IsNoiseHost(targetHostKey))
                        {
                            // Late-resolve/rdns может перекинуть "последний хост" на шумовой паттерн.
                            // В таких случаях пытаемся привязать рекомендацию к последнему НЕ шумовому ключу.
                            if (!string.IsNullOrWhiteSpace(_m._lastUserFacingHost))
                            {
                                targetHostKey = _m._lastUserFacingHost;
                            }
                        }

                        if (string.IsNullOrWhiteSpace(targetHostKey) || NoiseHostFilter.Instance.IsNoiseHost(targetHostKey))
                        {
                            return;
                        }

                        var isV2 = msg.TrimStart().StartsWith("[V2]", StringComparison.OrdinalIgnoreCase);

                        // v2 — единственный источник рекомендаций для UI.
                        // Legacy сообщения могут присутствовать в логе, но не должны менять стратегию карточки.
                        if (!isV2)
                        {
                            return;
                        }

                        var raw = TryExtractAfterMarker(msg, "Рекомендация:")
                            ?? TryExtractAfterMarker(msg, "Стратегия:");
                        if (string.IsNullOrWhiteSpace(raw))
                        {
                            return;
                        }

                        var strategy = raw.Trim();

                        // Если в строке есть скобки с деталями (conf/фейлы/окно), отрезаем их для поля стратегии
                        var parenIndex = strategy.IndexOf('(');
                        if (parenIndex > 0)
                        {
                            strategy = strategy.Substring(0, parenIndex).Trim();
                        }

                        // v2 может выдавать список стратегий в одной строке (через запятую/плюс).
                        // Для UX на карточке показываем весь список (чтобы не «терять» DROP_RST).
                        var tokens = strategy
                            .Split(new[] { ',', '+', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                            .Select(MapV2StrategyTokenForUi)
                            .Where(t => !string.IsNullOrWhiteSpace(t))
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .ToList();

                        if (tokens.Count == 0)
                        {
                            return;
                        }

                        var uiStrategy = string.Join(" + ", tokens);

                        var result = _m.TestResults.FirstOrDefault(t =>
                            t.Target.Host == targetHostKey || t.Target.Name == targetHostKey);
                        if (result != null)
                        {
                            result.BypassStrategy = uiStrategy;
                            if (isV2)
                            {
                                result.IsBypassStrategyFromV2 = true;
                            }

                            if (uiStrategy.Equals("ROUTER_REDIRECT", StringComparison.OrdinalIgnoreCase))
                            {
                                result.Status = TestStatus.Warn;
                                result.Details = result.Details?.Replace("Блокировка", "Информация: Fake IP (VPN/туннель)")
                                    ?? "Fake IP обнаружен";
                                _m.Log($"[UI] ROUTER_REDIRECT → Status=Warn для {targetHostKey}");
                            }
                            else if (uiStrategy != PipelineContract.BypassNone && uiStrategy != PipelineContract.BypassUnknown)
                            {
                                _m.Log($"[UI] Bypass strategy for {targetHostKey}: {uiStrategy}");
                            }
                        }
                    }
                    else if ((msg.StartsWith("[BYPASS]") || msg.StartsWith("ℹ") || msg.StartsWith("⚠"))
                        && !string.IsNullOrEmpty(_m._lastUpdatedHost))
                    {
                        var result = _m.TestResults.FirstOrDefault(t =>
                            t.Target.Host == _m._lastUpdatedHost || t.Target.Name == _m._lastUpdatedHost);
                        if (result != null && (result.Details == null || !result.Details.Contains(msg)))
                        {
                            result.Details = (result.Details ?? "") + $"\n{msg}";
                        }
                    }
                }
                catch
                {
                }
            }

            private static string? TryExtractAfterMarker(string msg, string marker)
            {
                try
                {
                    var idx = msg.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
                    if (idx < 0) return null;
                    idx += marker.Length;
                    return idx >= msg.Length ? null : msg.Substring(idx);
                }
                catch
                {
                    return null;
                }
            }

            private static string MapV2StrategyTokenForUi(string token)
            {
                var t = token.Trim();
                if (string.IsNullOrWhiteSpace(t)) return string.Empty;

                // Поддерживаем enum-названия v2 и "v2:"-префикс из логов.
                if (t.StartsWith("v2:", StringComparison.OrdinalIgnoreCase))
                {
                    t = t.Substring(3).Trim();
                }

                t = t switch
                {
                    "TlsFragment" => "TLS_FRAGMENT",
                    "TlsDisorder" => "TLS_DISORDER",
                    "TlsFakeTtl" => "TLS_FAKE",
                    "DropRst" => "DROP_RST",
                    "UseDoh" => "DOH",
                    "DropUdp443" => "DROP_UDP_443",
                    "AllowNoSni" => "ALLOW_NO_SNI",
                    _ => t.ToUpperInvariant()
                };

                // Должно совпадать с текстами тумблеров в MainWindow.xaml.
                return t switch
                {
                    "TLS_FRAGMENT" => "Frag",
                    "TLS_DISORDER" => "Frag+Rev",
                    "TLS_FAKE" => "TLS Fake",
                    "DROP_RST" => "Drop RST",
                    "DOH" => "DoH",
                    "DROP_UDP_443" => "QUIC→TCP",
                    "ALLOW_NO_SNI" => "No SNI",
                    _ => t
                };
            }

            private void SetLastUpdatedHost(string hostKey)
            {
                _m._lastUpdatedHost = hostKey;

                if (string.IsNullOrWhiteSpace(hostKey))
                {
                    return;
                }

                // Мы хотим стабильно цеплять рекомендации/кнопки к "пользовательскому" ключу.
                // Поэтому шумовые домены НЕ должны затмевать последнюю «нормальную» цель.
                if (IPAddress.TryParse(hostKey, out _))
                {
                    _m._lastUserFacingHost = hostKey;
                    return;
                }

                if (!NoiseHostFilter.Instance.IsNoiseHost(hostKey))
                {
                    _m._lastUserFacingHost = hostKey;
                }
            }

            private void ApplyNameTokensFromMessage(string hostKey, string msg)
            {
                try
                {
                    // Формат добавляется pipeline: "SNI=... RDNS=..." (значения без пробелов)
                    var sni = ExtractToken(msg, "SNI");
                    var dns = ExtractToken(msg, "DNS");
                    var rdns = ExtractToken(msg, "RDNS");

                    if (string.IsNullOrWhiteSpace(sni) && string.IsNullOrWhiteSpace(rdns)) return;

                    var result = _m.TestResults.FirstOrDefault(t => t.Target.Host == hostKey || t.Target.FallbackIp == hostKey);
                    if (result == null) return;

                    // Если hostKey это IP, а SNI уже есть — мигрируем карточку на человеко-понятный ключ.
                    if (IPAddress.TryParse(hostKey, out _) && !string.IsNullOrWhiteSpace(sni) && sni != "-")
                    {
                        var normalizedSni = _m.NormalizeHost(sni);
                        _m._ipToUiKey[hostKey] = normalizedSni;
                        _m.TryMigrateIpCardToNameKey(hostKey, normalizedSni);
                    }

                    // 1) Настоящий SNI имеет приоритет
                    if (!string.IsNullOrWhiteSpace(sni) && sni != "-")
                    {
                        var old = result.Target;
                        var newName = !string.Equals(old.Name, sni, StringComparison.OrdinalIgnoreCase) ? sni : old.Name;
                        result.Target = new Target
                        {
                            Name = newName,
                            Host = old.Host,
                            Service = old.Service,
                            Critical = old.Critical,
                            FallbackIp = old.FallbackIp,
                            SniHost = sni,
                            ReverseDnsHost = old.ReverseDnsHost
                        };
                    }
                    // 2) Если SNI не пойман — используем DNS как "хост" для колонки SNI
                    else if (!string.IsNullOrWhiteSpace(dns) && dns != "-" && string.IsNullOrWhiteSpace(result.Target.SniHost))
                    {
                        var old = result.Target;
                        result.Target = new Target
                        {
                            Name = old.Name,
                            Host = old.Host,
                            Service = old.Service,
                            Critical = old.Critical,
                            FallbackIp = old.FallbackIp,
                            SniHost = dns,
                            ReverseDnsHost = old.ReverseDnsHost
                        };
                    }

                    if (!string.IsNullOrWhiteSpace(rdns) && rdns != "-")
                    {
                        var old = result.Target;
                        result.Target = new Target
                        {
                            Name = old.Name,
                            Host = old.Host,
                            Service = old.Service,
                            Critical = old.Critical,
                            FallbackIp = old.FallbackIp,
                            SniHost = old.SniHost,
                            ReverseDnsHost = rdns
                        };
                    }
                }
                catch
                {
                }
            }
        }

        private PipelineMessageParser? _pipelineMessageParser;

        private PipelineMessageParser PipelineParser => _pipelineMessageParser ??= new PipelineMessageParser(this);
    }
}
