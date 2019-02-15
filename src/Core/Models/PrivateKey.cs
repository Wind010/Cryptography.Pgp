using Org.BouncyCastle.Bcpg.OpenPgp;

using System;
using System.IO;
using System.Linq;

namespace Cryptography.Pgp.Core.Models
{
    using Extensions;

    public class PrivateKey : IPrivateKey
    {
        public const string ThePrivateKeyFileDoesNotExist = "Private Key file='{0}' does not exist.";
        public const string CanNotFindSigningKeyInKeyRing = "Can not find signing key in key ring.";

        public PgpSecretKey SecretKey { get; private set; }

        /// <summary>
        /// <see cref="PgpPrivateKey"/>
        /// </summary>
        public PgpPrivateKey Value { get; private set; }

        public PrivateKey(PgpPrivateKey privateKey, PgpSecretKey secretKey)
        {
            Value = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            SecretKey = secretKey ?? throw new ArgumentNullException(nameof(secretKey));
        }

        /// <summary>
        /// <param name="privateKeyFileStream"><see cref="string"/></param>
        /// </summary>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"><see cref="string"/></param>
        public PrivateKey(string privateKeyFilePath, string passPhrase)
        {
            privateKeyFilePath.IsNullOrWhitespace(nameof(privateKeyFilePath));
            passPhrase.IsNullOrWhitespace(nameof(passPhrase));
            privateKeyFilePath.Exists(nameof(privateKeyFilePath));

            SecretKey = GetSecretKeyFromPrivateKey(privateKeyFilePath);
            Value = GetPrivateKeyWithSecret(privateKeyFilePath);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKeyFileStream"><see cref="Stream"/></param>
        /// <param name="passPhrase"><see cref="string"/></param>
        public PrivateKey(Stream privateKeyFileStream, string passPhrase)
        {
            privateKeyFileStream.IsNull(nameof(privateKeyFileStream));
            passPhrase.IsNullOrWhitespace(nameof(passPhrase));

            SecretKey = GetSecretKeyFromPrivateKey(privateKeyFileStream);
            Value = GetPrivateKeyWithSecret(passPhrase);
        }

        
        private PgpPrivateKey GetPrivateKeyWithSecret(string passPhrase)
        {
            PgpPrivateKey privateKey = SecretKey.ExtractPrivateKey(passPhrase.ToCharArray());
            if (privateKey != null)
                return privateKey;

            throw new ArgumentException("No private key found in secret key.");
        }


        private PgpSecretKey GetSecretKeyFromPrivateKey(Stream privateKeyStream)
        {
            using (Stream inputStream = PgpUtilities.GetDecoderStream(privateKeyStream))
            {
                var secretKeyRingBundle = new PgpSecretKeyRingBundle(inputStream);
                PgpSecretKey foundKey = GetFirstSecretKey(secretKeyRingBundle);

                if (foundKey != null) { return foundKey; }
            }

            throw new ArgumentException(CanNotFindSigningKeyInKeyRing);
        }


        private PgpSecretKey GetSecretKeyFromPrivateKey(string privateKeyFilePath)
        {
            using (Stream sr = File.OpenRead(privateKeyFilePath))
            {
                return GetSecretKeyFromPrivateKey(sr);
            }

            throw new ArgumentException(CanNotFindSigningKeyInKeyRing);
        }

        /// <summary>
        /// Return the first key we can use to encrypt.
        /// Note: A file can contain multiple keys (stored in "key rings").
        /// </summary>
        private PgpSecretKey GetFirstSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            foreach (PgpSecretKeyRing kRing in secretKeyRingBundle.GetKeyRings())
            {
                PgpSecretKey key = kRing.GetSecretKeys()
                    .Cast<PgpSecretKey>()
                    .FirstOrDefault(k => k.IsSigningKey);

                if (key != null) { return key; }
            }

            return null;
        }

    }
}
