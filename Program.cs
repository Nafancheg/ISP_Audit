using System;
using System.Collections.Generic;
using ISPAudit;

namespace IspAudit
{
    internal static class Program
    {
        // Для совместимости с GUI: имя -> определение цели
        public static Dictionary<string, TargetDefinition> Targets { get; set; } = TargetCatalog.CreateDefaultTargetMap();

        [STAThread]
        private static int Main(string[] args)
        {
            // Загружаем профиль по умолчанию
            Config.SetActiveProfile("Default");

            // Запуск GUI приложения (OutputType=WinExe — консоль не появляется)
            var app = new App();
            app.Run();
            
            return 0;
        }
    }
}
