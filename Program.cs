using System;
using System.Collections.Generic;
using System.Text;
using IspAudit.Utils;

namespace IspAudit
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            // В .NET (Core/5+) кодировки вроде OEM866 требуют регистрации провайдера.
            // Без этого: Encoding.GetEncoding(866) бросает исключение.
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

            // P0.1 Step 1: продуктовый режим — DecisionGraph выбирает TLS стратегию по признакам пакета.
            // Гейт можно переопределить снаружи (env var уже задана) — тогда не трогаем.
            if (string.IsNullOrWhiteSpace(EnvVar.GetRaw(EnvKeys.PolicyDrivenTcp443)))
            {
                Environment.SetEnvironmentVariable(EnvKeys.PolicyDrivenTcp443, "1");
            }

            // Запуск GUI приложения (OutputType=WinExe — консоль не появляется)
            var app = new App();
            app.Run();

            return 0;
        }
    }
}
