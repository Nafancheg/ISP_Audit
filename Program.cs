using System;
using System.Collections.Generic;

namespace IspAudit
{
    internal static class Program
    {
        // Для совместимости с GUI: имя -> определение цели (заполняется из активного профиля)
        public static Dictionary<string, TargetDefinition> Targets { get; set; } = new(StringComparer.OrdinalIgnoreCase);

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
