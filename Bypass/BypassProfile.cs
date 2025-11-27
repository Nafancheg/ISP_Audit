using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace IspAudit.Bypass
{
    public enum TlsBypassStrategy
    {
        None,
        Fragment,
        Fake,
        FakeFragment,
        /// <summary>
        /// Disorder: отправляет фрагменты в обратном порядке (сначала второй, потом первый).
        /// Эффективно против DPI, который ожидает пакеты строго по порядку.
        /// </summary>
        Disorder,
        /// <summary>
        /// FakeDisorder: FAKE пакет + Disorder фрагментация.
        /// Комбинация для особо сложных DPI (Google).
        /// </summary>
        FakeDisorder
    }

    /// <summary>
    /// Настройки обхода блокировок для WinDivert.
    /// Профиль создаётся программно на основе результатов диагностики (DiagnosisCache).
    /// Статический файл bypass_profile.json удалён — у каждого провайдера свои методы блокировки.
    /// </summary>
    public sealed class BypassProfile
    {
        private static readonly Lazy<BypassProfile> _default = new(() => BuildDefault());

        public bool DropTcpRst { get; init; } = true;

        public bool FragmentTlsClientHello { get; init; } = true;
        
        /// <summary>
        /// Целевой IP для фильтрации (null = глобальный режим).
        /// </summary>
        public IPAddress? TargetIp { get; init; }

        /// <summary>
        /// Стратегия обхода для TLS (HTTPS).
        /// Выбирается динамически на основе диагностики.
        /// </summary>
        public TlsBypassStrategy TlsStrategy { get; init; } = TlsBypassStrategy.Fragment;

        /// <summary>
        /// Размер первой части ClientHello после фрагментации.
        /// Используется только если TlsStrategy = Fragment и SNI не найден.
        /// </summary>
        public int TlsFirstFragmentSize { get; init; } = 64;

        /// <summary>
        /// Минимальный размер ClientHello, при котором выполняется фрагментация.
        /// </summary>
        public int TlsFragmentThreshold { get; init; } = 16;

        public IReadOnlyList<BypassRedirectRule> RedirectRules { get; init; } = Array.Empty<BypassRedirectRule>();

        /// <summary>
        /// Получить профиль по умолчанию (Fragment + DROP_RST).
        /// Для конкретных хостов используйте CreateForStrategy().
        /// </summary>
        public static BypassProfile CreateDefault() => _default.Value;

        /// <summary>
        /// Создать профиль с конкретной TLS стратегией (для применения после диагностики).
        /// </summary>
        public static BypassProfile CreateForStrategy(TlsBypassStrategy strategy, bool dropRst = true, IPAddress? targetIp = null)
        {
            return new BypassProfile
            {
                DropTcpRst = dropRst,
                FragmentTlsClientHello = strategy != TlsBypassStrategy.None,
                TlsStrategy = strategy,
                TlsFirstFragmentSize = 64,
                TlsFragmentThreshold = 16,
                TargetIp = targetIp,
                RedirectRules = Array.Empty<BypassRedirectRule>()
            };
        }

        /// <summary>
        /// Создать профиль из строкового имени стратегии (для интеграции с кэшем).
        /// </summary>
        public static BypassProfile CreateFromStrategyName(string strategyName, bool dropRst = true, IPAddress? targetIp = null)
        {
            var strategy = strategyName switch
            {
                "TLS_FRAGMENT" => TlsBypassStrategy.Fragment,
                "TLS_FAKE" => TlsBypassStrategy.Fake,
                "TLS_FAKE_FRAGMENT" => TlsBypassStrategy.FakeFragment,
                "TLS_DISORDER" => TlsBypassStrategy.Disorder,
                "TLS_FAKE_DISORDER" => TlsBypassStrategy.FakeDisorder,
                "DROP_RST" => TlsBypassStrategy.None, // Только RST blocking
                _ => TlsBypassStrategy.Fragment
            };

            return CreateForStrategy(strategy, dropRst, targetIp);
        }

        private static BypassProfile BuildDefault()
        {
            // Профиль по умолчанию: Fragment + DROP_RST
            // Конкретная стратегия выбирается при диагностике
            return new BypassProfile
            {
                DropTcpRst = true,
                FragmentTlsClientHello = true,
                TlsStrategy = TlsBypassStrategy.Fragment,
                TlsFirstFragmentSize = 64,
                TlsFragmentThreshold = 16,
                RedirectRules = Array.Empty<BypassRedirectRule>()
            };
        }
    }
}
