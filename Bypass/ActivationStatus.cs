namespace IspAudit.Bypass
{
    public enum ActivationStatus
    {
        Unknown = 0,
        NoTraffic = 1,
        NotActivated = 2,
        Activated = 3,
        EngineDead = 4
    }

    public sealed record ActivationStatusSnapshot(ActivationStatus Status, string Text, string Details);
}
