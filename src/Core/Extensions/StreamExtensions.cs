using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Cryptography.Pgp.Core.Extensions
{
    using Models;

    public static class StreamExtensions
    {
        private const int StartOfStream = 0;
        private const int Bits = 4096;
        private const int BufferSize = 0x10000;
        private const char NullChar = '\0';


        /// <summary>
        /// Take the input stream and return a string of the specified encoding.
        /// Trims any null characters ('/0') from the end.
        /// Will reset the position of the stream to the beginning (0).
        /// </summary>
        /// <param name="input"><see cref="Stream"/></param>
        /// <param name="encoding"><see cref="Encoding"/></param>
        /// <returns><see cref="string"/></returns>
        public static string ToString(this Stream input, Encoding encoding)
        {
            using (var memStream = new MemoryStream())
            {
                input.Position = 0;
                input.CopyTo(memStream);
                memStream.Position = 0;
                input.Position = 0;
                string str = encoding.GetString(memStream.GetBuffer(), StartOfStream, memStream.GetBuffer().Length).TrimEnd(NullChar);
                input.Position = 0;
                return str;
            }
        }

        public static void WriteToLiteralData(this Stream output, Stream input, char fileType)
        {
            var literalDataGenerator = new PgpLiteralDataGenerator();
            using (Stream pOut = literalDataGenerator.Open(output, fileType, GetFileName(input), input.Length, DateTime.Now))
            {
                PipeStreamContents(input, pOut, Bits);
                output = pOut;
            }
        }

        /// <summary>
        /// Creates armored stream with use of the PgpEncryptedDataGenerator.  
        /// </summary>
        /// <remarks>
        /// Similar idea to Base64 encoding where the data is encoded to a specific character set.
        /// Does not provide any security benefit.
        /// </remarks>
        /// <param name="outputStream"><see cref="Stream"/></param>
        /// <param name="pgpEncryptedDataGenerator"><see cref="PgpEncryptedDataGenerator"/></param>
        /// <param name="bytes"><see cref="byte[]"/></param>
        public static void WriteWithAsciiArmor(this Stream outputStream, 
            PgpEncryptedDataGenerator pgpEncryptedDataGenerator, byte[] bytes)
        {
            using (var armoredStream = new ArmoredOutputStream(outputStream))
            using (Stream armoredOutStream = pgpEncryptedDataGenerator.Open(armoredStream, bytes.Length))
            {
                armoredOutStream.Write(bytes, StartOfStream, bytes.Length);
                outputStream = armoredOutStream;
            }
        }

        public static void WriteEncrypted(this Stream outputStream, string inputFilepath, PgpInfo info,
            Keys keys, bool withIntegrityCheck)
        {
            using (FileStream inputFileStream = File.Open(inputFilepath, FileMode.Open))
            {
                WriteEncrypted(outputStream, inputFileStream, info, keys, withIntegrityCheck);
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
            using (FileStream inputFileStream = File.Open(inputFilepath, FileMode.Open))
            {
                WriteEncryptedWithAsciiArmor(outputStream, inputFileStream, info, keys, withIntegrityCheck);
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



        /// <summary>
        /// Check if strem is null.
        /// </summary>
        /// <param name="stream"><see cref="Stream"/></param>
        /// <param name="name"><see cref="string"/>Name of variable passed in.</param>
        /// <exception cref="ArgumentNullException">Thrown if stream is null.</exception>
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
                outputStream = plainStream;
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
            PublicKeyAlgorithmTag tag = keys.Public.Value.Algorithm;
            var pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, keys.Private.Value);

            string userId = keys.Public.Value.GetUserIds().Cast<string>().FirstOrDefault();

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
