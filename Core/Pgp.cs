using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Pgp.Core
{
    using Extensions;
    using Models;
   
    public class Pgp : IDisposable
    {
        private const int BufferSize = 0x10000;

        private PgpInfo _pgpInfo;

        public Pgp(PgpInfo pgpInfo)
        {
            _pgpInfo = pgpInfo ?? throw new ArgumentNullException(nameof(pgpInfo));
        }


        /// <summary>
        /// Stream-based encryption, which relies on a local file for input source
        /// </summary>
        /// <param name="inputFilePath">File path to source to encrypt.</param>
        /// <param name="outputFilePath">Output file path of the encrypted data.</param>
        /// <param name="publicKeyFilePath">File path to the public key.</param>
        /// <param name="armor"><see cref="bool"/>Encase the encrypted message in ASCII armor.</param>
        /// <param name="withIntegrityCheck"><see cref="bool"/>Check integrity of encrypted message.</param>
        public void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyFilePath,
            bool armor = true, bool withIntegrityCheck = true)
        {
            ValidateEncryptFileParams(inputFilePath, outputFilePath, publicKeyFilePath);

            using (Stream pkStream = File.OpenRead(publicKeyFilePath))
            {
                using (Stream outputStream = File.Create(outputFilePath))
                using (Stream inputStream = File.OpenRead(inputFilePath))
                Encrypt(inputStream, outputStream, pkStream, armor, withIntegrityCheck);
            }
        }


        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputStream"><see cref="Stream"/>Unencrypted stream.</param>
        /// <param name="outputStream"><see cref="Stream"/>Encrypted stream.</param>
        /// <param name="publicKeyStream"><see cref="Stream"/>Public key stream.</param>
        /// <param name="armor"><see cref="bool"/>Encase the encrypted message in ASCII armor.</param>
        /// <param name="withIntegrityCheck"><see cref="bool"/>Check integrity of encrypted message.</param>
        public void Encrypt(Stream inputStream, Stream outputStream, Stream publicKeyStream,
            bool armor = true, bool withIntegrityCheck = true)
        {
            ValidateEncryptFileParams(inputStream, outputStream, publicKeyStream);

            using (var outputMemoryStream = new MemoryStream())
            {
                if (_pgpInfo.CompressionAlgorithm != CompressionAlgorithm.Uncompressed)
                {
                    var comData = new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)_pgpInfo.CompressionAlgorithm);
                    outputStream.WriteToLiteralData(inputStream, _pgpInfo.GetPgpLiteralDataFormat());
                    comData.Close();
                }
                else
                    outputStream.WriteToLiteralData(inputStream, _pgpInfo.GetPgpLiteralDataFormat());

                var pgpEncryptedDataGenerator = 
                    new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)_pgpInfo.SymmetricKeyAlgorithm,
                    withIntegrityCheck, new SecureRandom());

                var publicKey = new PublicKey(publicKeyStream);
                pgpEncryptedDataGenerator.AddMethod(publicKey.Value);

                byte[] bytes = outputMemoryStream.ToArray();

                if (armor)
                {
                    outputStream.WriteWithAsciiArmor(pgpEncryptedDataGenerator, bytes);
                    return;
                }

                outputStream.WritePlainText(pgpEncryptedDataGenerator, bytes);
            }
        }




        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
