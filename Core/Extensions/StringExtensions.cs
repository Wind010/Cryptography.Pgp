using System.IO;

namespace Cryptography.Pgp.Core.Extensions
{
    public static class StringExtensions
    {
        public static void Exists(this string filePath, string name)
        {
            if (! File.Exists(filePath))
            {
                throw new FileNotFoundException($"{name} file='{filePath}' does not exist.");
            }
        }
    }
}
