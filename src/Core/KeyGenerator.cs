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

        public KeyGenerator(int signatureType, PublicKeyAlgorithm publicKeyAlgorithm, 
            SymmetricKeyAlgorithm symmetricKeyAlgorithm)
        {
            _signatureType = signatureType;
            _publicKeyAlgorithm = publicKeyAlgorithm;
            _symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        }

        public async Task<Keys> GenerateEncryptionKeysAsync(KeyGenerationInfo keyInfo, CancellationToken ct)
        {
            return await Task.Run(() => GenerateEncryptionKeys(keyInfo), ct);
        }

        public Keys GenerateEncryptionKeys(KeyGenerationInfo keyInfo)
        {
            using (Stream privateKeyStream = File.Open(keyInfo.PrivateKeyFilepath, FileMode.OpenOrCreate))
            using (Stream publicKeyStream = File.Open(keyInfo.PublicKeyFilepath, FileMode.OpenOrCreate))
            {
                IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
                kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 
                    keyInfo.Strength, keyInfo.Certainty));

                AsymmetricCipherKeyPair asymmetricCipherKeyPair = kpg.GenerateKeyPair();

                return WriteKeyPairToFiles(privateKeyStream, publicKeyStream, asymmetricCipherKeyPair.Public, 
                    asymmetricCipherKeyPair.Private, keyInfo);
            }

        }

        private Keys WriteKeyPairToFiles(Stream privateOut, Stream publicOut, 
            AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey, KeyGenerationInfo keyInfo)
        {
            if (keyInfo.Armor)
            {
                privateOut = new ArmoredOutputStream(privateOut);
            }

            var secretKey = new PgpSecretKey(
                _signatureType,
                (PublicKeyAlgorithmTag)(int)_publicKeyAlgorithm,
                publicKey,
                privateKey,
                DateTime.UtcNow,
                keyInfo.Username,
                (SymmetricKeyAlgorithmTag)(int)_symmetricKeyAlgorithm,
                keyInfo.Password.ToCharArray(),
                null,
                null,
                new SecureRandom()
           );

            secretKey.Encode(privateOut);

            privateOut.Close();

            if (keyInfo.Armor)
            {
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey publicKeyFromSecret = secretKey.PublicKey;

            publicKeyFromSecret.Encode(publicOut);

            publicOut.Close();

            return new Keys(secretKey.ExtractPrivateKey(keyInfo.Password.ToCharArray()), secretKey, publicKeyFromSecret);
        }


    }
}
