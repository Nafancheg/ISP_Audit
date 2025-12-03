using System;
using System.Collections.Generic;
using System.Linq;
using IspAudit.Bypass;

namespace IspAudit.Utils
{
    /// <summary>
    /// Планировщик стратегий обхода блокировок
    /// </summary>
    internal static class BypassStrategyPlanner
    {
        /// <summary>
        /// Генерирует BypassProfile на основе обнаруженных проблем
        /// </summary>
        public static BypassProfile PlanBypassStrategy(
            List<BlockageProblem> problems,
            DiagnosticProfile gameProfile,
            IProgress<string>? progress = null)
        {
            progress?.Report($"Планирование стратегии обхода для {problems.Count} проблем...");

            // Определяем, какие правила нужны
            bool needDropRst = false;
            bool needFragmentTls = false;
            var redirectRules = new List<BypassRedirectRule>();

            // Анализируем каждую проблему и добавляем соответствующие правила
            foreach (var problem in problems)
            {
                switch (problem.Type)
                {
                    case BlockageType.DnsFiltering:
                        // DNS блокировка — требует смены DNS через DnsFixApplicator
                        // Bypass profile не помогает, отмечаем в логе
                        progress?.Report($"  - DNS фильтрация: требуется смена DNS на DoH (Cloudflare/Google)");
                        
                        // Добавляем fallback IP редиректы если есть
                        var target = gameProfile.Targets.FirstOrDefault(t => t.Host == problem.Target);
                        if (target != null && !string.IsNullOrEmpty(target.FallbackIp))
                        {
                            redirectRules.Add(new BypassRedirectRule
                            {
                                Name = $"Fallback for {target.Host}",
                                Protocol = IspAudit.Bypass.TransportProtocol.Tcp,
                                Port = 443,
                                RedirectIp = target.FallbackIp,
                                RedirectPort = 443,
                                Enabled = true,
                                Hosts = new List<string> { target.Host }
                            });
                            progress?.Report($"    → Добавлен редирект: {target.Host} → {target.FallbackIp}");
                        }
                        break;

                    case BlockageType.DpiRstInjection:
                        // DPI RST injection — включаем DropTcpRst
                        needDropRst = true;
                        progress?.Report($"  - DPI RST injection: включен DropTcpRst");
                        break;

                    case BlockageType.TlsSniFiltering:
                        // TLS SNI фильтрация — фрагментация ClientHello
                        needFragmentTls = true;
                        progress?.Report($"  - TLS SNI фильтрация: включена фрагментация ClientHello");
                        break;

                    case BlockageType.FirewallBlock:
                        // Firewall блокировка — перенаправление на альтернативные порты (если есть)
                        progress?.Report($"  - Firewall блокировка: обход через порты невозможен (требуется VPN)");
                        break;

                    case BlockageType.UdpBlock:
                        // UDP блокировка — перенаправление UDP -> TCP (если поддерживается игрой)
                        progress?.Report($"  - UDP блокировка: обход невозможен (требуется VPN)");
                        break;

                    case BlockageType.HttpFiltering:
                        // HTTP фильтрация — редирект через прокси
                        progress?.Report($"  - HTTP фильтрация: требуется HTTP прокси");
                        break;

                    default:
                        progress?.Report($"  - Неизвестная проблема: {problem.Description}");
                        break;
                }
            }

            // Создаем профиль с собранными настройками
            var profile = new BypassProfile
            {
                DropTcpRst = needDropRst,
                FragmentTlsClientHello = needFragmentTls,
                TlsFirstFragmentSize = 64,
                TlsFragmentThreshold = 128,
                RedirectRules = redirectRules
            };

            var strategyDescription = BuildStrategyDescription(profile);
            progress?.Report($"Стратегия обхода готова: {strategyDescription}");

            return profile;
        }

        /// <summary>
        /// Создает текстовое описание стратегии для пользователя
        /// </summary>
        private static string BuildStrategyDescription(BypassProfile profile)
        {
            var parts = new List<string>();

            if (profile.DropTcpRst)
                parts.Add("Drop TCP RST");

            if (profile.FragmentTlsClientHello)
                parts.Add("Fragment TLS ClientHello");

            if (profile.RedirectRules.Any())
                parts.Add($"{profile.RedirectRules.Count} редиректов");

            return parts.Any() ? string.Join(", ", parts) : "Нет активных правил";
        }

        /// <summary>
        /// Проверяет, требуется ли смена DNS для обхода
        /// </summary>
        public static bool RequiresDnsChange(List<BlockageProblem> problems)
        {
            return problems.Any(p => p.Type == BlockageType.DnsFiltering);
        }

        /// <summary>
        /// Проверяет, достаточно ли WinDivert bypass для обхода
        /// </summary>
        public static bool CanBypassWithWinDivert(List<BlockageProblem> problems)
        {
            // WinDivert помогает только против DPI и TLS SNI
            return problems.Any(p => 
                p.Type == BlockageType.DpiRstInjection || 
                p.Type == BlockageType.TlsSniFiltering);
        }

        /// <summary>
        /// Проверяет, требуется ли VPN для обхода
        /// </summary>
        public static bool RequiresVpn(List<BlockageProblem> problems)
        {
            // VPN нужен для Firewall и UDP блокировок
            return problems.Any(p => 
                p.Type == BlockageType.FirewallBlock || 
                p.Type == BlockageType.UdpBlock);
        }
    }
}
