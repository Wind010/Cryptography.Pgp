using System;
using System.IO;

namespace Cryptography.Pgp.Core.Extensions
{
    public static class StringExtensions
    {
        public static void Exists(this string filePath, string name)
        {
            filePath.IsNullOrWhitespace(name);
            if (! File.Exists(filePath))
            {
                throw new FileNotFoundException($"Parameter name='{name}' with file path='{filePath}' does not exist.");
            }
        }

        public static void IsNullOrWhitespace(this string str, string name)
        {
            if (string.IsNullOrWhiteSpace(str))
            {
                throw new ArgumentNullException(name);
            }
        }
    }
}
