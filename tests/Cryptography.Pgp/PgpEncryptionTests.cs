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
        public void Encrypt_NoCompressionAlgorithm_AesSymmmetricKeyAlgorithm_BinaryDocumentSignature_RsaPublicKeyAlgorithm_TextFileType_EncryptedString()
        {
            var pgpInfo = new PgpInfo()
            {
                CompressionAlgorithm = CompressionAlgorithm.Uncompressed,
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.Aes256,
                SignatureType = 0,
                PublicKeyAlgorithm = PublicKeyAlgorithm.RsaEncrypt,
                FileType = FileType.Text
            };

            string plainText = "Hello";
            PgpEncryptStreamParameters encryptStreamParams = GetPgpEncryptStreamParameters(plainText);

            using (var encryptedStream = new MemoryStream())
            {
                var pgpEncryption = new PgpEncryption(pgpInfo);
                pgpEncryption.Encrypt(encryptStreamParams, encryptedStream);

                var pgpDecrytpion = new PgpDecryption();
                var decryptStreamParameters = GetPgpDecryptStreamParameters(encryptStreamParams, encryptedStream);

                using (var decrytedStream = new MemoryStream())
                {
                    pgpDecrytpion.Decrypt(decryptStreamParameters, decrytedStream);

                    // Assert
                    decrytedStream.ToString(Encoding.UTF8).Should().Be(plainText);
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
