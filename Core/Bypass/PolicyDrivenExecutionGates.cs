using System;

namespace IspAudit.Core.Bypass
{
    public static class PolicyDrivenExecutionGates
    {
        /// <summary>
        /// Feature-gate: включить policy-driven runtime-путь для UDP/443 (QUIC fallback).
        /// По умолчанию выключено.
        /// </summary>
        public static bool PolicyDrivenUdp443Enabled()
        {
            try
            {
                return IspAudit.Utils.EnvVar.ReadBool(IspAudit.Utils.EnvKeys.PolicyDrivenUdp443, defaultValue: false);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Фича-гейт: включить policy-driven runtime-путь для TTL endpoint block (reconnect-nudge).
        /// Управляется env var `ISP_AUDIT_POLICY_DRIVEN_TTLBLOCK`.
        /// По умолчанию выключен.
        /// </summary>
        public static bool PolicyDrivenTtlEndpointBlockEnabled()
        {
            try
            {
                return IspAudit.Utils.EnvVar.ReadBool(IspAudit.Utils.EnvKeys.PolicyDrivenTtlBlock, defaultValue: false);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Фича-гейт: включить policy-driven runtime-путь для TCP/80 HTTP Host tricks.
        /// Управляется env var `ISP_AUDIT_POLICY_DRIVEN_TCP80`.
        /// По умолчанию выключен.
        /// </summary>
        public static bool PolicyDrivenTcp80HostTricksEnabled()
        {
            try
            {
                return IspAudit.Utils.EnvVar.ReadBool(IspAudit.Utils.EnvKeys.PolicyDrivenTcp80, defaultValue: false);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Фича-гейт: включить policy-driven runtime-путь для TCP/443 TLS (выбор стратегии на ClientHello).
        /// Управляется env var `ISP_AUDIT_POLICY_DRIVEN_TCP443`.
        /// По умолчанию выключен.
        /// </summary>
        public static bool PolicyDrivenTcp443TlsStrategyEnabled()
        {
            try
            {
                return IspAudit.Utils.EnvVar.ReadBool(IspAudit.Utils.EnvKeys.PolicyDrivenTcp443, defaultValue: false);
            }
            catch
            {
                return false;
            }
        }
    }
}
