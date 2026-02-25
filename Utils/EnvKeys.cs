namespace IspAudit.Utils
{
    /// <summary>
    /// Единый реестр строковых ключей переменных окружения ISP_AUDIT_*.
    /// Цель: убрать дубли строковых литералов и снизить риск опечаток.
    /// </summary>
    public static class EnvKeys
    {
        // TEST hooks (только DEBUG)
        public const string TestApplyDelayMs = "ISP_AUDIT_TEST_APPLY_DELAY_MS";
        public const string TestSkipTlsApply = "ISP_AUDIT_TEST_SKIP_TLS_APPLY";

        // Path override (перенаправление персиста/артефактов)
        public const string ApplyTransactionsPath = "ISP_AUDIT_APPLY_TRANSACTIONS_PATH";
        public const string OperatorConsentPath = "ISP_AUDIT_OPERATOR_CONSENT_PATH";
        public const string OperatorEventsPath = "ISP_AUDIT_OPERATOR_EVENTS_PATH";
        public const string OperatorSessionsPath = "ISP_AUDIT_OPERATOR_SESSIONS_PATH";
        public const string PostApplyChecksPath = "ISP_AUDIT_POST_APPLY_CHECKS_PATH";
        public const string WinsStorePath = "ISP_AUDIT_WINS_STORE_PATH";
        public const string UserFlowPoliciesPath = "ISP_AUDIT_USER_FLOW_POLICIES_PATH";
        public const string BlockpageHostsPath = "ISP_AUDIT_BLOCKPAGE_HOSTS_PATH";
        public const string BypassSessionPath = "ISP_AUDIT_BYPASS_SESSION_PATH";
        public const string TrafficEngineCrashDir = "ISP_AUDIT_TRAFFICENGINE_CRASH_DIR";

        // Feature gates / runtime switches
        public const string PolicyDrivenUdp443 = "ISP_AUDIT_POLICY_DRIVEN_UDP443";
        public const string PolicyDrivenTtlBlock = "ISP_AUDIT_POLICY_DRIVEN_TTLBLOCK";
        public const string PolicyDrivenTcp80 = "ISP_AUDIT_POLICY_DRIVEN_TCP80";
        public const string PolicyDrivenTcp443 = "ISP_AUDIT_POLICY_DRIVEN_TCP443";

        public const string EnableIntelDoh = "ISP_AUDIT_ENABLE_INTEL_DOH";
        public const string EnableV2Doh = "ISP_AUDIT_ENABLE_V2_DOH";
        public const string EnableAutoRetest = "ISP_AUDIT_ENABLE_AUTO_RETEST";
        public const string ClassicMode = "ISP_AUDIT_CLASSIC_MODE";

        // Auto-retest debounce (минимальный интервал между автоперетестами после изменения bypass)
        public const string RetestDebounceMs = "ISP_AUDIT_RETEST_DEBOUNCE_MS";

        // Auto-apply policy tuning
        public const string AutoApplyMinConfidence = "ISP_AUDIT_AUTO_APPLY_MIN_CONFIDENCE";
        public const string AutoApplySafeMinConfidence = "ISP_AUDIT_AUTO_APPLY_SAFE_MIN_CONFIDENCE";
        public const string AutoApplyConfidenceBoostWindowMinutes = "ISP_AUDIT_AUTO_APPLY_CONFIDENCE_BOOST_WINDOW_MINUTES";
        public const string AutoApplyConfidenceBoostRequiredHits = "ISP_AUDIT_AUTO_APPLY_CONFIDENCE_BOOST_REQUIRED_HITS";
        public const string AutoApplyConfidenceBoostPerHit = "ISP_AUDIT_AUTO_APPLY_CONFIDENCE_BOOST_PER_HIT";
        public const string AutoApplyConfidenceBoostMax = "ISP_AUDIT_AUTO_APPLY_CONFIDENCE_BOOST_MAX";

        // Тайминги/пороговые значения (runtime)
        public const string WatchdogTickMs = "ISP_AUDIT_WATCHDOG_TICK_MS";
        public const string WatchdogStaleMs = "ISP_AUDIT_WATCHDOG_STALE_MS";

        public const string ActivationEngineGraceMs = "ISP_AUDIT_ACTIVATION_ENGINE_GRACE_MS";
        public const string ActivationWarmupMs = "ISP_AUDIT_ACTIVATION_WARMUP_MS";
        public const string ActivationNoTrafficMs = "ISP_AUDIT_ACTIVATION_NO_TRAFFIC_MS";
        public const string ActivationStaleMs = "ISP_AUDIT_ACTIVATION_STALE_MS";

        public const string OutcomeDelayMs = "ISP_AUDIT_OUTCOME_DELAY_MS";
        public const string OutcomeTimeoutMs = "ISP_AUDIT_OUTCOME_TIMEOUT_MS";

        // Redirect burst cache / N-T-retention tuning
        public const string RedirectBurstDistinctEtldThreshold = "ISP_AUDIT_REDIRECT_BURST_N";
        public const string RedirectBurstWindowMinutes = "ISP_AUDIT_REDIRECT_BURST_WINDOW_MINUTES";
        public const string RedirectWindowRetentionMinutes = "ISP_AUDIT_REDIRECT_WINDOW_RETENTION_MINUTES";
    }
}
