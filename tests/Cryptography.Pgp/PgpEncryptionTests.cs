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
        private const string PlainTextTestString = "Hello";

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
        public void Encrypt_String_NoCompressionAlgorithm_Aes256SymmmetricKeyAlgorithm_GeneralSignatureType_RsaGeneralPublicKeyAlgorithm_UTF8FileType_Armored_EncryptedString()
        {
            TestEncryptDecrypt(new PgpInfo());
        }


        [TestMethod]
        [TestCategory("Integration")]
        public void Encrypt_String_ZipCompressionAlgorithm_Aes256SymmmetricKeyAlgorithm_GeneralSignatureType_RsaGeneralPublicKeyAlgorithm_UTF8FileType_Armored_EncryptedString()
        {
            var pgpInfo = new PgpInfo() { CompressionAlgorithm = CompressionAlgorithm.Zip };

            TestEncryptDecrypt(new PgpInfo());
        }

        [TestMethod]
        [TestCategory("Integration")]
        public void Encrypt_String_ZLibCompressionAlgorithm_Aes256SymmmetricKeyAlgorithm_GeneralSignatureType_RsaGeneralPublicKeyAlgorithm_UTF8FileType_Armored_EncryptedString()
        {
            var pgpInfo = new PgpInfo() { CompressionAlgorithm = CompressionAlgorithm.ZLib };

            TestEncryptDecrypt(new PgpInfo());
        }

        [TestMethod]
        [TestCategory("Integration")]
        public void Encrypt_String_BZip2CompressionAlgorithm_Aes256SymmmetricKeyAlgorithm_GeneralSignatureType_RsaGeneralPublicKeyAlgorithm_UTF8FileType_Armored_EncryptedString()
        {
            var pgpInfo = new PgpInfo() { CompressionAlgorithm = CompressionAlgorithm.BZip2 };

            TestEncryptDecrypt(new PgpInfo());
        }


        [TestMethod]
        [TestCategory("Integration")]
        public void Encrypt_File_ZipCompressionAlgorithm_Aes256SymmmetricKeyAlgorithm_GeneralSignatureType_RsaGeneralPublicKeyAlgorithm_UTF8FileType_Armored_EncryptedString()
        {
            var pgpInfo = new PgpInfo()
            {
                CompressionAlgorithm = CompressionAlgorithm.Uncompressed,
                SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.Aes256,
                SignatureType = 16,
                PublicKeyAlgorithm = PublicKeyAlgorithm.RsaGeneral,
                FileType = FileType.UTF8
            };

            const string testFile = "Test.txt";
            PgpEncryptStreamParameters encryptStreamParams = GetPgpEncryptStreamParameters(PlainTextTestString, testFile);

            TestEncryptDecrypt(new PgpInfo());
        }


        [TestMethod]
        [TestCategory("Integration")]
        public void Encrypt_GeneratedKeys_NoCompressionAlgorithm_AesSymmmetricKeyAlgorithm_BinaryDocumentSignature_RsaPublicKeyAlgorithm_TextFileType_EncryptedString()
        {
            PgpEncryptStreamParameters encryptStreamParams = GetPgpEncryptStreamParameters(PlainTextTestString);

            var keyInfo = new KeyGenerationInfo(GeneratedPrivateKeyFilename, GeneratedPublicKeyFilename, EmailAddress, Password);
            var keyGenerator = new KeyGenerator(16, PublicKeyAlgorithm.RsaGeneral, SymmetricKeyAlgorithm.Aes256);
            Keys keys = keyGenerator.GenerateEncryptionKeys(keyInfo);

            var decryptStreamParams = GetPgpDecryptStreamParameters(encryptStreamParams, new MemoryStream());

            using (FileStream priv = File.OpenRead(GeneratedPrivateKeyFilename))
            {
                decryptStreamParams.PrivateKeyStream = priv;

                using (var pub = new MemoryStream())
                {
                    keys.Public.Value.Encode(pub);

                    pub.Position = 0;
                    encryptStreamParams.PublicKeyStream = pub;

                    TestEncryptDecrypt(new PgpInfo(), encryptStreamParams, decryptStreamParams);
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

        private PgpEncryptStreamParameters GetPgpEncryptStreamParameters(string plainText, string fileName,
            bool armor = true, bool withIntegrityCheck = true)
        {
            var parameters = GetPgpEncryptStreamParameters(plainText);
            File.WriteAllText(fileName, plainText);

            return parameters;
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


        private void TestEncryptDecrypt(PgpInfo pgpInfo, PgpEncryptStreamParameters encryptStreamParams = null,
            PgpDecryptStreamParameters decryptStreamParams = null)
        {
            encryptStreamParams = encryptStreamParams ?? GetPgpEncryptStreamParameters(PlainTextTestString);

            using (var encryptedStream = new MemoryStream())
            {
                var pgpEncryption = new PgpEncryption(pgpInfo);
                // Act 
                pgpEncryption.Encrypt(encryptStreamParams, encryptedStream);

                // Assert encryption
                string encryptedString = encryptedStream.ToString(Encoding.UTF8);
                encryptedString.Should().NotBeNullOrWhiteSpace();

                var pgpDecrytpion = new PgpDecryption();
                decryptStreamParams = decryptStreamParams ?? GetPgpDecryptStreamParameters(encryptStreamParams, encryptedStream);
                decryptStreamParams.InputStream = encryptedStream;

                using (var decryptedStream = new MemoryStream())
                {
                    // Act
                    pgpDecrytpion.Decrypt(decryptStreamParams, decryptedStream);

                    // Assert decryption
                    decryptedStream.ToString(Encoding.UTF8).Should().Be(encryptStreamParams.InputStream.ToString(Encoding.UTF8));
                }
            }
        }

    }
}
