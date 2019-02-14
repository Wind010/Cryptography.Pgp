using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;


namespace Cryptography.Pgp.Core
{
    using Models;

    public class KeyGenerator : IKeyGenerator
    {
        private int _signatureType { get; set; }

        private PublicKeyAlgorithm _publicKeyAlgorithm { get; set; }

        private SymmetricKeyAlgorithm _symmetricKeyAlgorithm { get; set; }

        public KeyGenerator(int signatureType, PublicKeyAlgorithm publicKeyAlgorithm, SymmetricKeyAlgorithm symmetricKeyAlgorithm)
        {
            _signatureType = signatureType;
            _publicKeyAlgorithm = publicKeyAlgorithm;
            _symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        }

        public async Task GenerateKeysAsync(PgpInfo pgpInfo, CancellationToken ct)
        {
            await Task.Run(() => GenerateKeys(pgpInfo), ct);
        }


        public void GenerateKeys(PgpInfo pgpInfo)
        {
            using (Stream privateKeyStream = File.Open(pgpInfo.PrivateKeyFilePath, FileMode.OpenOrCreate))
            using (Stream publicKeyStream = File.Open(pgpInfo.PublicKeyFilePath, FileMode.OpenOrCreate))
            {
                IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
                kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), pgpInfo.Strength, pgpInfo.Certainty));

                AsymmetricCipherKeyPair asymmetricCipherKeyPair = kpg.GenerateKeyPair();

                WriteKeyPairToFiles(privateKeyStream, publicKeyStream, asymmetricCipherKeyPair.Public, asymmetricCipherKeyPair.Private, pgpInfo);
            }
        }

        private void WriteKeyPairToFiles(Stream privateOut, Stream publicOut, AsymmetricKeyParameter publicKey, 
            AsymmetricKeyParameter privateKey, PgpInfo pgpInfo)
        {
            if (pgpInfo.Armor)
            {
                privateOut = new ArmoredOutputStream(privateOut);
            }

            var secretKey = new PgpSecretKey(
                _signatureType,
                (PublicKeyAlgorithmTag)(int)_publicKeyAlgorithm,
                publicKey,
                privateKey,
                DateTime.UtcNow,
                pgpInfo.Username,
                (SymmetricKeyAlgorithmTag)(int)_symmetricKeyAlgorithm,
                pgpInfo.Password.ToCharArray(),
                null,
                null,
                new SecureRandom()
           );

            secretKey.Encode(privateOut);

            privateOut.Close();

            if (pgpInfo.Armor)
            {
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            publicOut.Close();
        }


    }
}
