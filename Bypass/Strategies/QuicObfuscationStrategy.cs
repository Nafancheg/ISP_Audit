using System;

namespace IspAudit.Bypass.Strategies
{
    /// <summary>
    /// QuicObfuscation (заготовка).
    ///
    /// Текущая MVP-реализация техники в приложении делается через флаг DropUdp443:
    /// мы глушим UDP/443, чтобы клиент откатился с QUIC/HTTP3 на TCP/HTTPS.
    ///
    /// TODO(P1.13):
    /// - оформить это как отдельную стратегию/класс с явным контрактом,
    /// - описать параметры (селективность/глобальность, критерии включения),
    /// - добавить расширенную наблюдаемость и тесты.
    ///
    /// Примечание: файл намеренно не используется рантаймом — это документирующий stub.
    /// </summary>
    public sealed class QuicObfuscationStrategy
    {
        public const string StrategyId = "QuicObfuscation";

        public override string ToString() => StrategyId;
    }
}
