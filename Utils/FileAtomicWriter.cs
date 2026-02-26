using System;
using System.IO;
using System.Text;

namespace IspAudit.Utils
{
    /// <summary>
    /// Атомарная запись файла через временный файл в той же директории и последующий rename.
    /// </summary>
    public static class FileAtomicWriter
    {
        public static void WriteAllText(string path, string content, Encoding? encoding = null)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Path is required", nameof(path));
            }

            encoding ??= Encoding.UTF8;

            var targetPath = Path.GetFullPath(path);
            var dir = Path.GetDirectoryName(targetPath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var fileName = Path.GetFileName(targetPath);
            var tempName = $"{fileName}.{Guid.NewGuid():N}.tmp";
            var tempPath = string.IsNullOrWhiteSpace(dir)
                ? tempName
                : Path.Combine(dir, tempName);

            try
            {
                File.WriteAllText(tempPath, content ?? string.Empty, encoding);
                File.Move(tempPath, targetPath, overwrite: true);
            }
            finally
            {
                try
                {
                    if (File.Exists(tempPath))
                    {
                        File.Delete(tempPath);
                    }
                }
                catch
                {
                    // ignore
                }
            }
        }
    }
}
