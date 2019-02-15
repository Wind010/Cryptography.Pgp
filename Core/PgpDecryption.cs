using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

using System;
using System.IO;
using System.Linq;

namespace Cryptography.Pgp.Core
{
    using Parameters;
    using Models;

    public class PgpDecryption 
    {
        public const string UnableToFindSecretKey = "Unable to find secret key.";
        public const string EncryptedMessageContainsSignedMessage = "Encrypted message contains a signed message - not literal data.";
        public const string MessageIsNotASimpleEncryptedFile = "Message is not a simple encrypted file.";
        public const string FailedToVerifyInputStream = "Failed to verify input stream.";


        public PgpDecryption()
        {
        }


        /// <summary>
        /// Decrypt a file.
        /// </summary>
        /// <param name="decryptFilepathParams"><see cref="PgpDecryptFilepathParameters"/></param>
        public void DecryptFile(PgpDecryptFilepathParameters decryptFilepathParams)
        {
            decryptFilepathParams.Validate();

            using (Stream inputStream = File.OpenRead(decryptFilepathParams.InputFilepath))
            using (Stream privateKeyStream = File.OpenRead(decryptFilepathParams.PrivateKeyFilepath))

            // Write to file.
            using (Stream outputStream = File.Create(decryptFilepathParams.OutputFilepath))
            {
                var decryptStreamParams = new PgpDecryptStreamParameters()
                {
                    InputStream = inputStream,
                    OutputStream = outputStream,
                    PrivateKeyStream = privateKeyStream
                };

                Decrypt(decryptStreamParams);
            }
        }


        /// <summary>
        /// Decrypt input stream with PgpSecretKeyBundle.
        /// </summary>
        /// <param name="decryptStreamParams"><see cref="PgpDecryptStreamParameters"/></param>
        public void Decrypt(PgpDecryptStreamParameters decryptStreamParams)
        {
            decryptStreamParams.Validate();

            var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(decryptStreamParams.InputStream));
            
            // Find secret key
            var keyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(decryptStreamParams.PrivateKeyStream));

            PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(objFactory);

            PgpPrivateKey privateKey = null;

            PgpPublicKeyEncryptedData publicKeyEncryptedData = encryptedDataList.GetEncryptedDataObjects()
                .Cast<PgpPublicKeyEncryptedData>()
                .FirstOrDefault(encryptedData => {
                    privateKey = FindSecretKey(keyRingBundle, encryptedData.KeyId, decryptStreamParams.Password);
                    return privateKey != null;
                });

            if (privateKey == null)
            {
                throw new InvalidOperationException(UnableToFindSecretKey);
            }

            FindAndPipeMessageToStream(publicKeyEncryptedData, privateKey, decryptStreamParams.OutputStream);
        }


        /// <summary>
        /// Decrypt input stream with specified private key and password.
        /// </summary>
        /// <param name="decryptStreamParams"><see cref="PgpDecryptStreamParameters"/></param>
        public void DecryptAndVerify(PgpDecryptStreamParameters decryptStreamParams)
        {
            decryptStreamParams.Validate();

            Keys keys = new Keys(decryptStreamParams.PrivateKeyStream,
                decryptStreamParams.PublicKeyStream, decryptStreamParams.Password);

            var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(decryptStreamParams.InputStream));

            PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(objFactory);

            PgpPublicKeyEncryptedData publicKeyEncryptedData = encryptedDataList.GetEncryptedDataObjects()
                .Cast<PgpPublicKeyEncryptedData>()
                .FirstOrDefault(encryptedData =>  encryptedData != null );


            if (publicKeyEncryptedData.KeyId != keys.Public.Value.KeyId)
            {
                throw new PgpException(FailedToVerifyInputStream);
            }

            FindAndPipeMessageToStream(publicKeyEncryptedData, keys.Private.Value, decryptStreamParams.OutputStream);
        }


        #region Private Methods

        private PgpEncryptedDataList GetEncryptedDataList(PgpObjectFactory objFactory)
        {
            PgpObject pgpObject = objFactory?.NextPgpObject();

            // The first object might be a PGP marker packet.
            if (pgpObject is PgpEncryptedDataList)
            {
                return (PgpEncryptedDataList)pgpObject;
            }

            return (PgpEncryptedDataList)objFactory.NextPgpObject();
        }

        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle, long keyId, string password)
        {
            PgpSecretKey pgpSecKey = secretKeyRingBundle.GetSecretKey(keyId);

            if (pgpSecKey == null)
            {
                return null;
            }

            return pgpSecKey.ExtractPrivateKey(password.ToCharArray());
        }

        private void FindAndPipeMessageToStream(PgpPublicKeyEncryptedData publicKeyEncryptedData, 
            PgpPrivateKey privateKey, Stream outputStream)
        {
            using (Stream plainStream = publicKeyEncryptedData.GetDataStream(privateKey))
            {
                var plainObjectFactory = new PgpObjectFactory(plainStream);

                PgpObject message = plainObjectFactory.NextPgpObject();

                if (message is PgpOnePassSignatureList)
                {
                    message = plainObjectFactory.NextPgpObject();
                }

                if (message is PgpCompressedData)
                {
                    PipeToStream(DecompressData(message), outputStream);
                    return;
                }

                if (message is PgpLiteralData)
                {
                    PipeToStream(message, outputStream);
                    return;
                }

                if (message is PgpOnePassSignatureList)
                {
                    throw new PgpException(EncryptedMessageContainsSignedMessage);
                }

                throw new PgpException(MessageIsNotASimpleEncryptedFile);
            }
        }

        private PgpObject DecompressData(PgpObject message)
        {
            var compressedData = (PgpCompressedData)message;
            PgpObjectFactory objectFactory = null;

            using (Stream compressedDataStream = compressedData.GetDataStream())
            {
                objectFactory = new PgpObjectFactory(compressedDataStream);
            }

            message = objectFactory.NextPgpObject();

            // What else in objectFactory?
            if (message is PgpOnePassSignatureList)
            {
                message = objectFactory.NextPgpObject();
            }

            return message;
        }
        
        private void PipeToStream(PgpObject message, Stream outputStream)
        {
            var literalData = (PgpLiteralData)message;
            // TODO: Logging
            //string outFileName = literalData.FileName;

            Stream uncompressedStream = literalData.GetInputStream();
            Streams.PipeAll(uncompressedStream, outputStream);
        }


        #endregion Private Methods

    }
}
