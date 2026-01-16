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
                var raw = Environment.GetEnvironmentVariable("ISP_AUDIT_POLICY_DRIVEN_UDP443");
                if (string.IsNullOrWhiteSpace(raw)) return false;

                return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(raw, "on", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }
}
