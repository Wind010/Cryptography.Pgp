using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;

namespace Cryptography.Pgp.Core.Tests
{
    using Core.Extensions;
    using Models;
    using Parameters;
    using Tests.Extensions;

    using FluentAssertions;

    [ExcludeFromCodeCoverage]
    [TestClass]
    public class PgpEncryptionTests : TestBase
    {
        [ClassInitialize()]
        public static void ClassInit(TestContext context)
        {
            LoadConfiguration(context);
        }

        [ClassCleanup]
        public static void ClassCleanUp()
        {

        }

        [TestInitialize]
        public void Initialize()
        {
        }


        [TestMethod]
        [TestCategory("Integration")]
        public void Encrypt_NoCompressionAlgorithm_AesSymmmetricKeyAlgorithm_BinaryDocumentSignature_RsaPublicKeyAlgorithm_TextFileType_EncryptedString()
        {
            var pgpInfo = new PgpInfo()
            {
                CompressionAlgorithm = CompressionAlgorithm.Uncompressed,
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.TripleDes,
                SignatureType = 16,
                PublicKeyAlgorithm = PublicKeyAlgorithm.RsaGeneral,
                FileType = FileType.Binary
            };

            string plainText = "Hello";
            PgpEncryptStreamParameters encryptStreamParams = GetPgpEncryptStreamParameters(plainText);

            using (var encryptedStream = new MemoryStream())
            {
                var pgpEncryption = new PgpEncryption(pgpInfo);
                pgpEncryption.Encrypt(encryptStreamParams, encryptedStream);

                var pgpDecrytpion = new PgpDecryption();
                var decryptStreamParameters = GetPgpDecryptStreamParameters(encryptStreamParams, encryptedStream);

                using (var decryptedStream = new MemoryStream())
                {
                    pgpDecrytpion.Decrypt(decryptStreamParameters, decryptedStream);

                    // Assert
                    decryptedStream.ToString(Encoding.UTF8).Should().Be(plainText);
                }
            }
        }


        [TestMethod]
        [TestCategory("Integration")]
        public void Encrypt_GeneratedKeys_NoCompressionAlgorithm_AesSymmmetricKeyAlgorithm_BinaryDocumentSignature_RsaPublicKeyAlgorithm_TextFileType_EncryptedString()
        {
            var pgpInfo = new PgpInfo()
            {
                CompressionAlgorithm = CompressionAlgorithm.Uncompressed,
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.Aes256,
                SignatureType = 16,
                PublicKeyAlgorithm = PublicKeyAlgorithm.RsaGeneral,
                FileType = FileType.Text
            };


            string plainText = "Hello";
            PgpEncryptStreamParameters encryptStreamParams = GetPgpEncryptStreamParameters(plainText);

            var keyInfo = new KeyGenerationInfo(GeneratedPrivateKeyFilename, GeneratedPublicKeyFilename, EmailAddress, Password);
            var keyGenerator = new KeyGenerator(16, PublicKeyAlgorithm.RsaGeneral, SymmetricKeyAlgorithm.Aes256);
            Keys keys = keyGenerator.GenerateEncryptionKeys(keyInfo);

            using (var pub = new MemoryStream())
            {
                keys.Public.Value.Encode(pub);

                pub.Position = 0;
                encryptStreamParams.PublicKeyStream = pub;

                using (var encryptedStream = new MemoryStream())
                {
                    var pgpEncryption = new PgpEncryption(pgpInfo);
                    pgpEncryption.Encrypt(encryptStreamParams, encryptedStream);

                    var pgpDecrytpion = new PgpDecryption();
                    var decryptStreamParameters = GetPgpDecryptStreamParameters(encryptStreamParams, encryptedStream);

                    using (var decryptedStream = new MemoryStream())
                    {
                        using (FileStream priv = File.OpenRead(GeneratedPrivateKeyFilename))
                        {
                            decryptStreamParameters.PrivateKeyStream = priv;


                            pgpDecrytpion.Decrypt(decryptStreamParameters, decryptedStream);

                            // Assert
                            decryptedStream.ToString(Encoding.UTF8).Should().Be(plainText);
                        }
                    }
                }
            }
        }


        private PgpEncryptStreamParameters GetPgpEncryptStreamParameters(string plainText, 
            bool armor = true, bool withIntegrityCheck = true)
        {
            return new PgpEncryptStreamParameters
            {
                InputStream = plainText.ToStream(Encoding.UTF8),
                PublicKeyStream = PublicKey.ToStream(Encoding.UTF8),
                Password = Password,
                Armor = armor,
                IntegrityCheck = withIntegrityCheck,
            };
        }

        private PgpDecryptStreamParameters GetPgpDecryptStreamParameters(PgpEncryptStreamParameters encryptParams, 
            Stream inputStream)
        {
            return new PgpDecryptStreamParameters()
            {
                PrivateKeyStream = PrivateKey.ToStream(Encoding.UTF8),
                PublicKeyStream = PublicKey.ToStream(Encoding.UTF8),
                InputStream = inputStream,
                Password = encryptParams.Password,
                Armor = encryptParams.Armor,
                IntegrityCheck = encryptParams.IntegrityCheck
            };
        }

    }
}
