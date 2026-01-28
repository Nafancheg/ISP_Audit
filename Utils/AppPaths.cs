using System;
using System.IO;

namespace IspAudit.Utils
{
    public static class AppPaths
    {
        public static string AppDirectory
        {
            get
            {
                // AppContext.BaseDirectory корректно работает и при single-file.
                // Нормализуем путь, чтобы избежать сюрпризов с относительными сегментами.
                return Path.GetFullPath(AppContext.BaseDirectory);
            }
        }

        public static string StateDirectory => Path.Combine(AppDirectory, "state");

        public static string GetStateFilePath(string fileName)
        {
            fileName = (fileName ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(fileName))
            {
                throw new ArgumentException("Имя файла пустое.", nameof(fileName));
            }

            return Path.Combine(StateDirectory, fileName);
        }

        public static string EnsureStateDirectoryExists()
        {
            Directory.CreateDirectory(StateDirectory);
            return StateDirectory;
        }
    }
}
