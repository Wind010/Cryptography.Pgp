using Org.BouncyCastle.Bcpg.OpenPgp;

using System;
using System.IO;
using System.Linq;

namespace Cryptography.Pgp.Core.Models
{
    using Extensions;

    public class PublicKey : IPublicKey
    {
        public const string PublicKeyFileDoesNotExist = "Public Key file='{0}' does not exist.";
        public const string NoEncryptionKeyFoundInPublicKeyRing = "No encryption key found in public key ring.";

        /// <summary>
        /// <see cref="PgpPublicKey"/>
        /// </summary>
        public PgpPublicKey Value { get; private set; }

        public PublicKey(PgpPublicKey publicKey)
        {
            Value = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        /// <param name="publicKeyFilePath"><see cref="string"/></param>
        public PublicKey(string publicKeyFilePath)
        {
            publicKeyFilePath.IsNullOrWhitespace(nameof(publicKeyFilePath));
            publicKeyFilePath.Exists(nameof(publicKeyFilePath));

            Value = ReadPublicKey(publicKeyFilePath);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="publicKeyFileStream"><see cref="Stream"/></param>
        public PublicKey(Stream publicKeyFileStream)
        {
            publicKeyFileStream.IsNull(nameof(publicKeyFileStream));

            Value = ReadPublicKey(publicKeyFileStream);
        }

        
        private PgpPublicKey ReadPublicKey(Stream publicKeyStream)
        {
            using (Stream inputStream = PgpUtilities.GetDecoderStream(publicKeyStream))
            {
                var publicKeyRingBundle = new PgpPublicKeyRingBundle(inputStream);
                PgpPublicKey foundKey = GetFirstPublicKey(publicKeyRingBundle);

                if (foundKey != null) { return foundKey; }
            }

            throw new ArgumentException(NoEncryptionKeyFoundInPublicKeyRing);
        }

        private PgpPublicKey ReadPublicKey(string publicKeyPath)
        {
            using (Stream keyIn = File.OpenRead(publicKeyPath))
            {
                return ReadPublicKey(keyIn);
            }

            throw new ArgumentException(NoEncryptionKeyFoundInPublicKeyRing);
        }

        private PgpPublicKey GetFirstPublicKey(PgpPublicKeyRingBundle publicKeyRingBundle)
        {
            foreach (PgpPublicKeyRing kRing in publicKeyRingBundle.GetKeyRings())
            {
                PgpPublicKey key = kRing.GetPublicKeys()
                    .Cast<PgpPublicKey>()
                    .FirstOrDefault(k => k.IsEncryptionKey);

                if (key != null) { return key; }
            }
            return null;
        }

    }
}
