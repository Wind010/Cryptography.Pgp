using System;
using System.IO;
using System.Text;

namespace Cryptography.Pgp.Core.Tests.Extensions
{
    public static class StringExtensions
    {
        public static MemoryStream ToStream(this string plainText, Encoding encoding)
        {
            byte[] byteArr = encoding.GetBytes(plainText);
            return new MemoryStream(byteArr);
        }

        public static string EncodeBase64(this string plainText, Encoding encoding)
        {
            byte[] byteArr = encoding.GetBytes(plainText);
            return Convert.ToBase64String(byteArr);
        }

        public static string DecodeBase64(this string base64encoded, Encoding encoding)
        {
            byte[] byteArr = Convert.FromBase64String(base64encoded);
            return encoding.GetString(byteArr);
        }


    }
}
