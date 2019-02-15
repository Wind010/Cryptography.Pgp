using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

using System;
using System.IO;
using System.Linq;

namespace Cryptography.Pgp.Core.Extensions
{
    using Models;

    public static class StreamExtensions
    {
        private const int StartOfStream = 0;
        private const int Bits = 4096;
        private const int BufferSize = 0x10000;

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

        public static void WriteEncrypted(this Stream outputStream, string inputFilepath, PgpInfo info,
            Keys keys, bool withIntegrityCheck)
        {
            using (Stream encryptedData = outputStream.ChainEncryptedOut(info, keys, withIntegrityCheck))
            using (Stream encryptedAndCompressedData = encryptedData.CompressAndChainEncryptedData(info.CompressionAlgorithm))
            {
                PgpSignatureGenerator signatureGenerator = encryptedAndCompressedData.GetPgpSignatureGenerator(keys);
                using (Stream literalOut = encryptedAndCompressedData.ChainLiteralData(info, inputFilepath))
                {
                    using (FileStream inputFileStream = File.Open(inputFilepath, FileMode.Open))
                    {
                        encryptedAndCompressedData.WriteOutputAndSign(literalOut, inputFileStream, signatureGenerator);
                    }
                }
            }
        }

        public static void WriteEncrypted(this Stream outputStream, Stream inputStream, PgpInfo info,
        Keys keys, bool withIntegrityCheck)
        {
            using (Stream encryptedData = outputStream.ChainEncryptedOut(info, keys, withIntegrityCheck))
            using (Stream encryptedAndCompressedData = encryptedData.CompressAndChainEncryptedData(info.CompressionAlgorithm))
            {
                PgpSignatureGenerator signatureGenerator = encryptedAndCompressedData.GetPgpSignatureGenerator(keys);
                using (Stream literalOut = encryptedAndCompressedData
                    .ChainLiteralStreamOut(inputStream, info, inputStream.GetFileName()))
                {
                    encryptedAndCompressedData.WriteOutputAndSign(literalOut, inputStream, signatureGenerator);
                }
            }
        }




        public static void WriteEncryptedWithAsciiArmor(this Stream outputStream, string inputFilepath, PgpInfo info,
            Keys keys, bool withIntegrityCheck)
        {
            using (var armoredStream = new ArmoredOutputStream(outputStream))
            {
                armoredStream.WriteEncrypted(inputFilepath, info, keys, withIntegrityCheck);
            }
        }

        public static void WriteEncryptedWithAsciiArmor(this Stream outputStream, Stream inputStream, PgpInfo info,
            Keys keys, bool withIntegrityCheck)
        {
            using (var armoredStream = new ArmoredOutputStream(outputStream))
            {
                armoredStream.WriteEncrypted(inputStream, info, keys, withIntegrityCheck);
            }
        }



        public static void IsNull(this Stream stream, string name)
        {
            if (stream == null) { throw new ArgumentNullException(name); }
        }


        #region Private Methods

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

        public static Stream CompressAndChainEncryptedData(this Stream encryptedOutputStream, 
            CompressionAlgorithm compressionAlgorithm)
        {
            if (compressionAlgorithm == CompressionAlgorithm.Uncompressed) { return encryptedOutputStream; }

            var compressedDataGenerator = new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)compressionAlgorithm);
            return compressedDataGenerator.Open(encryptedOutputStream);
        }

        public static Stream ChainLiteralData(this Stream compressedOut, PgpInfo info, string inputFilePath)
        {
            var unencryptedFileInfo = new FileInfo(inputFilePath);

            var pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, info.GetPgpLiteralDataFormat(),
                unencryptedFileInfo.Name, unencryptedFileInfo.Length, DateTime.Now);
        }

        public static Stream ChainLiteralStreamOut(this Stream compressedOut, Stream inputStream, PgpInfo info, string name)
        {
            var pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, info.GetPgpLiteralDataFormat(),
                name, inputStream.Length, DateTime.Now);
        }

        private static Stream ChainEncryptedOut(this Stream outputStream, PgpInfo info, Keys keys, 
            bool withIntegrityCheck)
        {
            var encryptedDataGenerator 
                = new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)info.SymmetricKeyAlgorithm, 
                withIntegrityCheck, new SecureRandom());

            encryptedDataGenerator.AddMethod(keys.Public.Value);

            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        private static PgpSignatureGenerator GetPgpSignatureGenerator(this Stream compressedOut, Keys keys)
        {
            PublicKeyAlgorithmTag tag = keys.Public.Algorithm;
            var pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, keys.Private);

            string userId = keys.Public.GetUserIds().Cast<string>().FirstOrDefault();

            var subPacketGenerator = new PgpSignatureSubpacketGenerator();
            subPacketGenerator.SetSignerUserId(false, userId);
            pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
           
            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);

            return pgpSignatureGenerator;
        }

        private static void WriteOutputAndSign(this Stream compressedOut, Stream literalOut,
            Stream inputStream, PgpSignatureGenerator signatureGenerator)
        {
            int length = 0;
            byte[] buf = new byte[BufferSize];
            while ((length = inputStream.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }

            signatureGenerator.Generate().Encode(compressedOut);
        }


        #endregion Private Methods

    }
}
