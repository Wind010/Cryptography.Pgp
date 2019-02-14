using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;

using System;
using System.IO;

namespace Cryptography.Pgp.Core.Extensions
{
    public static class StreamExtensions
    {
        private static int StartOfStream = 0;
        private static int Bits = 4096;

        public static void WriteToLiteralData(this Stream output, Stream input, char fileType)
        {
            var literalDataGenerator = new PgpLiteralDataGenerator();
            Stream pOut = literalDataGenerator.Open(output, fileType, GetFileName(input), input.Length, DateTime.Now);
            PipeStreamContents(input, pOut, Bits);
        }

        public static void WriteWithAsciiArmor(this Stream outputStream, 
            PgpEncryptedDataGenerator pgpEncryptedDataGenerator, byte[] bytes)
        {
            using (var armoredStream = new ArmoredOutputStream(outputStream))
            using (Stream armoredOutStream = pgpEncryptedDataGenerator.Open(armoredStream, bytes.Length))
            { 
                armoredOutStream.Write(bytes, StartOfStream, bytes.Length);
            }
        }

        public static void WritePlainText(this Stream outputStream, 
            PgpEncryptedDataGenerator pgpEncryptedDataGenerator, byte[] bytes)
        {
            using (Stream plainStream = pgpEncryptedDataGenerator.Open(outputStream, bytes.Length))
            {
                plainStream.Write(bytes, StartOfStream, bytes.Length);
            }
        }

        private static void PipeStreamContents(Stream input, Stream pOut, int bufferSize)
        {
            byte[] buffer = new byte[bufferSize];

            int len;
            while ((len = input.Read(buffer, StartOfStream, buffer.Length)) > StartOfStream)
            {
                pOut.Write(buffer, StartOfStream, len);
            }
        }

        private static string GetFileName(this Stream stream)
        {
            if (stream == null || !(stream is FileStream))
            {
                return "name";
            }

            return ((FileStream)stream).Name;
        }


    }
}
