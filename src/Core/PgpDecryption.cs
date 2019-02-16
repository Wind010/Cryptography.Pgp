
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;

using System.IO;
using System.Linq;

namespace Cryptography.Pgp.Core
{
    using Parameters;
    using Models;

    public class PgpDecryption 
    {
        public const string UnableToExtractPrivateKeyFromPgpSecretKeyRingBundle = "Unable to extract private key from PGP secret key ring bundle.";
        public const string EncryptedMessageContainsSignedMessage = "Encrypted message contains a signed message - not literal data.";
        public const string MessageIsNotASimpleEncryptedFile = "Message is not a simple encrypted file.";  // Uknown message type encountered.
        public const string FailedToVerifyInputStream = "Failed to verify input stream.";
        public const string FailedToRetrievePgpPublicKeyEncryptedData = "Failed to retrieve PGP public key encrypted data.";
        public const string CouldNotFindEncryptedDataListInMessage = "Could not find the public key encrypted data list in the PGP message.";
        public const string SessionKeyNotFound = "Session key to decrypt message was not found.";

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
                    PrivateKeyStream = privateKeyStream
                };

                Decrypt(decryptStreamParams, outputStream);
            }
        }


        /// <summary>
        /// Decrypt input stream with PgpSecretKeyBundle.
        /// </summary>
        /// <param name="decryptStreamParams"><see cref="PgpDecryptStreamParameters"/></param>
        public void Decrypt(PgpDecryptStreamParameters decryptStreamParams, Stream outputStream)
        {
            decryptStreamParams.Validate();

            var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(decryptStreamParams.InputStream));
            
            // Find secret key
            var keyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(decryptStreamParams.PrivateKeyStream));

            PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(objFactory);

            PgpPrivateKey privateKey = null;

            // Now, we have to locate the random session key that is associated with the ciphertext we
            // need to decrypt. Each encrypted data object in the payload stores the ID of the public/private
            // key pair that was used to encrypt the data and therefore can decrypt it. We have to search
            // through the list of encrypted data for the key ID of our key pair in order to figure out
            // which encrypted items in the list we can decrypt. BouncyCastle will then decrypt the session
            // key with our private key so that we can decrypt the actual data.
            PgpPublicKeyEncryptedData publicKeyEncryptedData = encryptedDataList.GetEncryptedDataObjects()
                .Cast<PgpPublicKeyEncryptedData>()
                .FirstOrDefault(encryptedData => {
                    privateKey = ExtractPrivateKeyFromSecretKeyRingBundle(keyRingBundle, encryptedData.KeyId, decryptStreamParams.Password);
                    return privateKey != null;
                });

            if (privateKey == null)
            {
                throw new PgpException(UnableToExtractPrivateKeyFromPgpSecretKeyRingBundle);
            }

            if (publicKeyEncryptedData == null)
            {
                throw new PgpException(FailedToRetrievePgpPublicKeyEncryptedData);
            }

            FindAndPipeMessageToStream(publicKeyEncryptedData, privateKey, outputStream);
        }


        /// <summary>
        /// Decrypt input stream with specified private key and password.
        /// </summary>
        /// <param name="decryptStreamParams"><see cref="PgpDecryptStreamParameters"/></param>
        public void DecryptAndVerify(PgpDecryptStreamParameters decryptStreamParams, Stream outputStream)
        {
            decryptStreamParams.Validate();

            Keys keys = new Keys(decryptStreamParams.PrivateKeyStream,
                decryptStreamParams.PublicKeyStream, decryptStreamParams.Password);

            var objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(decryptStreamParams.InputStream));

            PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(objFactory);

            PgpPublicKeyEncryptedData publicKeyEncryptedData = encryptedDataList.GetEncryptedDataObjects()
                .Cast<PgpPublicKeyEncryptedData>()
                .FirstOrDefault(encryptedData =>  encryptedData != null );

            // In addition to the actual data that is stored, PGP *MAY* store information about signatures
            // in the data stream. The data *MAY* also be compressed before it was encrypted. So a file
            // may contain nested objects and look like this:
            //
            // +---------------------------------------+
            // | Encrypted payload                     |
            // | +-----------------------------------+ |
            // | | Compressed payload                | |
            // | | +-------------------------------+ | |
            // | | | One-pass signature list (opt) | | |
            // | | +-------------------------------+ | |
            // | | +-------------------------------+ | |
            // | | | Literal Data (actual data)    | | |
            // | | +-------------------------------+ | |
            // | +-----------------------------------+ |
            // +---------------------------------------+
            //
            // If the objects aren't compressed, the view would be much simpler:
            //
            // +-----------------------------------+
            // | Encrypted payload                 |
            // | +-------------------------------+ |
            // | | One-pass signature list (opt) | |
            // | +-------------------------------+ |
            // | +-------------------------------+ |
            // | | Literal Data (actual data)    | |
            // | +-------------------------------+ |
            // +-----------------------------------+


            if (publicKeyEncryptedData == null)
            {
                throw new PgpException(FailedToRetrievePgpPublicKeyEncryptedData);
            }

            if (publicKeyEncryptedData.KeyId != keys.Public.Value.KeyId)
            {
                throw new PgpException(FailedToVerifyInputStream);
            }

            // Now that we have the private key, build a stream to read and decrypt data, thus removing the
            // encryption wrapping all of the other payloads.
            FindAndPipeMessageToStream(publicKeyEncryptedData, keys.Private.Value, outputStream);
        }


        #region Private Methods

        private PgpEncryptedDataList GetEncryptedDataList(PgpObjectFactory objFactory)
        {
            PgpObject pgpObject = objFactory?.NextPgpObject();

            // From the OpenPGP standard, RFC 4880 (https://tools.ietf.org/html/rfc4880):
            // OpenPGP combines symmetric-key encryption and public-key encryption
            // to provide confidentiality.When made confidential, first the object
            // is encrypted using a symmetric encryption algorithm. Each symmetric
            // key is used only once, for a single object. A new "session key" is
            // generated as a random number for each object (sometimes referred to
            // as a session). Since it is used only once, the session key is bound
            // to the message and transmitted with it. To protect the key, it is
            // encrypted with the receiver's public key.
            //
            // To decrypt the data, we have to pull the encrypted random key out of the encrypted payload,
            // decrypt it with our private key, and then use the random key to decrypt the actual
            // ciphertext to retrieve the original plaintext. BouncyCastle takes care of a few of these
            // steps for us like decrypting the session key with our private key.
            //

            //
            // Get the list of encrypted data (i.e., the ciphertext and encrypted session key). The first
            // object in the stream could be either the list of encrypted data or it might be a PGP marker
            // packet (https://tools.ietf.org/html/rfc4880#section-5.8). If it's just the marker packet,
            // the encrypted data list should be the next item in the stream.

            if (pgpObject is PgpEncryptedDataList)
            {
                return (PgpEncryptedDataList)pgpObject;
            }

            // Skip over the marker, and grab the next item. If it isn't the encrypted data, either the
            // data is corrupt or we don't know how to process it.

            var encryptedDataList = (PgpEncryptedDataList)objFactory?.NextPgpObject();
            if (null == encryptedDataList)
            {

                // The documentation on BouncyCastle is non-existent. It only exists through sample code
                // and StackExchange posts, so if this ever happens, it is entirely possible that we're
                // encountering a valid stream that we just don't know how to parse. In other words, this
                // exception does not mean that the stream is bad. It could indicate a bug in our use of
                // the library.
                throw new PgpException(CouldNotFindEncryptedDataListInMessage);
            }
        }

        private PgpPrivateKey ExtractPrivateKeyFromSecretKeyRingBundle(PgpSecretKeyRingBundle secretKeyRingBundle, 
            long keyId, string password)
        {
            PgpSecretKey secretKey = secretKeyRingBundle.GetSecretKey(keyId);

            if (secretKey == null)
            {
                throw new PgpException(SessionKeyNotFound);
            }

            return secretKey.ExtractPrivateKey(password.ToCharArray());
        }

        private void FindAndPipeMessageToStream(PgpPublicKeyEncryptedData publicKeyEncryptedData, 
            PgpPrivateKey privateKey, Stream outputStream)
        {
            using (Stream plainStream = publicKeyEncryptedData.GetDataStream(privateKey))
            {
                var plainObjectFactory = new PgpObjectFactory(plainStream);
                PgpObject plainMessage = plainObjectFactory.NextPgpObject();

                while (plainMessage != null)
                {
                    // TODO:  Implement multi-pass signature evaluate case for PgpSignatureList.
                    if (plainMessage is PgpOnePassSignatureList)
                    {
                        plainMessage = plainObjectFactory.NextPgpObject();
                    }

                    if (plainMessage is PgpCompressedData)
                    {
                        // Change the factory over to one that is dealing with compressed data from
                        // here on out.
                        PipeToStream(DecompressData(plainMessage), outputStream);
                        return;
                    }

                    // If we found literal data, we have found the decrypted data. Stream the literal data to the
                    // output stream, and get out of here because we're done.
                    if (plainMessage is PgpLiteralData)
                    {
                        PipeToStream(plainMessage, outputStream);
                        return;
                    }

                    if (plainMessage is PgpOnePassSignatureList)
                    {
                        throw new PgpException(EncryptedMessageContainsSignedMessage);
                    }

                    plainMessage = plainObjectFactory.NextPgpObject();
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

            // Reset the output stream so the caller starts reading from the beginning.
            outputStream.Position = 0;
        }


        #endregion Private Methods

    }
}
