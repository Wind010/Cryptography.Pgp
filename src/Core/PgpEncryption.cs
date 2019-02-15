﻿using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

using System;
using System.IO;

namespace Cryptography.Pgp.Core
{
    using Extensions;
    using Parameters;
    using Models;
   
    public class PgpEncryption : PgpBase
    {
        public PgpEncryption(PgpInfo pgpInfo)
        {
            Info = pgpInfo ?? throw new ArgumentNullException(nameof(pgpInfo));
        }


        /// <summary>
        /// Encrypt a file.
        /// </summary>
        /// <param name="encryptFilepathParams"><see cref="PgpEncryptFilepathParameter"/></param>
        public void EncryptFile(PgpEncryptFilepathParameter encryptFilepathParams)
        {
            encryptFilepathParams.Validate();

            using (Stream pkStream = File.OpenRead(encryptFilepathParams.PublicKeyFilepath))
            using (Stream outputStream = File.Create(encryptFilepathParams.OutputFilepath))
            using (Stream inputStream = File.OpenRead(encryptFilepathParams.InputFilepath))
            {
                var encryptStreamParams = new PgpEncryptStreamParameters
                {
                    PublicKeyStream = pkStream,
                    OutputStream = outputStream,
                    InputStream = inputStream
                };
                Encrypt(encryptStreamParams);
            }
        }


        /// <summary>
        /// PGP Encrypt the input stream.
        /// </summary>
        /// <param name="encryptParams"><see cref="PgpEncryptStreamParameters"/></param>
        public void Encrypt(PgpEncryptStreamParameters encryptParams)
        {
            encryptParams.Validate();
            encryptParams.CheckDefaults();

            using (var outputMemoryStream = new MemoryStream())
            {
                if (Info.CompressionAlgorithm != CompressionAlgorithm.Uncompressed)
                {
                    var comData = 
                        new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)Info.CompressionAlgorithm);
                    encryptParams.OutputStream
                        .WriteToLiteralData(encryptParams.InputStream, Info.GetPgpLiteralDataFormat());

                    comData.Close();
                }
                else
                    encryptParams.OutputStream
                        .WriteToLiteralData(encryptParams.InputStream, Info.GetPgpLiteralDataFormat());

                var pgpEncryptedDataGenerator = 
                    new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)Info.SymmetricKeyAlgorithm,
                    encryptParams.IntegrityCheck.Value, new SecureRandom());

                var publicKey = new PublicKey(encryptParams.PublicKeyStream);
                pgpEncryptedDataGenerator.AddMethod(publicKey.Value);

                byte[] bytes = outputMemoryStream.ToArray();

                if (encryptParams.Armor.Value)
                {
                    encryptParams.OutputStream.WriteWithAsciiArmor(pgpEncryptedDataGenerator, bytes);
                    return;
                }

                encryptParams.OutputStream.WritePlainText(pgpEncryptedDataGenerator, bytes);
            }
        }


        public void EncryptFileAndSign(PgpEncryptAndSignFileParameters encryptAndSignParameters)
        {
            encryptAndSignParameters.Validate();

            var keyInfo = new KeyGenerationInfo(encryptAndSignParameters.PublicKeyFilepath,
                encryptAndSignParameters.PrivateKeyFilepath, string.Empty, encryptAndSignParameters.Options.Password);

            var keyGenerator = new KeyGenerator(Info.SignatureType, Info.PublicKeyAlgorithm, 
                Info.SymmetricKeyAlgorithm);

            Keys keys = keyGenerator.GenerateEncryptionKeys(keyInfo);

            string inputFilePath = encryptAndSignParameters.InputFilepath;
            PgpEncryptOptions options = encryptAndSignParameters.Options;
            using (Stream outputStream = File.Create(encryptAndSignParameters.OutputFilepath))
            {
                if (encryptAndSignParameters.Options.Armor.HasValue)
                {
                    outputStream.WriteEncryptedWithAsciiArmor(inputFilePath, Info, keys,
                        options.IntegrityCheck.Value);

                    return;
                }

                outputStream.WriteEncrypted(inputFilePath, Info, keys,
                    options.IntegrityCheck.Value);
            }
        }

        public void EncryptFileAndSign(PgpEncryptAndSignStreamParameters encryptAndSignParameters)
        {
            encryptAndSignParameters.Validate();

            Keys keys = new Keys(encryptAndSignParameters.PrivateKeyStream, 
                encryptAndSignParameters.PublicKeyStream, encryptAndSignParameters.Password);

            PgpEncryptOptions options = encryptAndSignParameters.Options;

            if (encryptAndSignParameters.Options.Armor.HasValue)
            {
                encryptAndSignParameters.OutputStream.WriteEncryptedWithAsciiArmor(encryptAndSignParameters.InputStream,
                    Info, keys, options.IntegrityCheck.Value);
            }
        }


    }
}