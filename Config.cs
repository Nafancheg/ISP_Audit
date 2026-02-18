using System;
using System.Collections.Generic;
using IspAudit.Utils;

namespace IspAudit
{
    /// <summary>
    /// Конфигурация приложения для GUI режима.
    /// CLI режим удалён — приложение работает только через GUI.
    /// </summary>
    public class Config
    {
        // Legacy: ранее поддерживались профили целей диагностики (Profiles/*.json).
        // Сейчас приложение работает в режиме динамических целей (по фактическому трафику);
        // сохраняются только «снятые снимки» после диагностики (см. DiagnosticOrchestrator.SaveProfileAsync).

        // Профиль окружения: normal|vpn (влияет на классификацию/пороги)
        public string Profile { get; set; } = "normal";

        // Таймауты в секундах
        public int HttpTimeoutSeconds { get; set; } = 3;
        public int TcpTimeoutSeconds { get; set; } = 2;
        public int UdpTimeoutSeconds { get; set; } = 2;

        // Переключатели тестов (используются в GUI)
        public bool EnableDns { get; set; } = true;
        public bool EnableTcp { get; set; } = true;
        public bool EnableHttp { get; set; } = true;
        public bool EnableTrace { get; set; } = false; // Отключено по умолчанию — медленный и редко полезный для пользователей
        public bool EnableUdp { get; set; } = true;
        public bool EnableRst { get; set; } = false; // Отключено по умолчанию — сложная эвристика, мало информативна
        public bool EnableAutoBypass { get; set; } = false; // Автоматическое применение обхода блокировок

        /// <summary>
        /// Runtime-флаги (feature gates) для управления поведением без изменения UI.
        /// По умолчанию — максимально консервативно (выключено), чтобы не было «магии».
        /// </summary>
        public static class RuntimeFlags
        {
            /// <summary>
            /// Разрешить применять "верхнеуровневые" системные изменения из INTEL-плана (DNS/DoH).
            /// По умолчанию false: INTEL может рекомендовать DoH, но применять его должен только пользователь вручную.
            /// </summary>
            public static bool EnableIntelDoHFromPlan
                => EnvVar.ReadBool(EnvKeys.EnableIntelDoh, defaultValue: EnvVar.ReadBool(LegacyEnableDohEnv, defaultValue: false));

            private static string LegacyEnableDohEnv => EnvKeys.EnableV2Doh;

            /// <summary>
            /// Разрешить авто-ретест после изменения тумблеров bypass в UI.
            /// По умолчанию false: ретест должен запускаться явно пользователем.
            /// </summary>
            public static bool EnableAutoRetestOnBypassChange
            {
                get
                {
                    if (ClassicMode)
                    {
                        return false;
                    }

                    return ReadBoolEnv(EnvKeys.EnableAutoRetest, defaultValue: false);
                }
            }

            /// <summary>
            /// ClassicMode: в рамках текущего run реактивные мутации переводятся в observe-only.
            /// </summary>
            public static bool ClassicMode => ReadBoolEnv(EnvKeys.ClassicMode, defaultValue: false);
        }

        private static bool ReadBoolEnv(string name, bool defaultValue)
            => EnvVar.ReadBool(name, defaultValue);

        public static Config Default() => new Config();
    }
}
