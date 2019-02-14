using System;
using System.IO;

namespace Cryptography.Pgp.Core
{
    using Extensions;

    public class PgpParameters
    {
        /// <summary>
        /// String to be encrypted or decrypted.
        /// </summary>
        public string Input { get; set; }

        /// <summary>
        /// Encrypted/Decrypted string.
        /// </summary>
        public string Output { get; set; }

        public string InputFile { get; set; }
        public string OutputFile { get; set; }

        public Stream InputStream { get; set; }
        public Stream OutputStream { get; set; }

        public string PublicKey { get; set; }
        public string PrivateKey { get; set; }

        public string PublicKeyFilePath { get; set; }
        public string PrivateKeyFilePath { get; set; }

        public Stream PublicKeyStream { get; set; }
        public Stream PrivateKeyStream { get; set; }

        public string Password { get; set; }

        /// <summary>
        /// Encase the encrypted message in ASCII armor.
        /// </summary>
        public bool Armor { get; set; }

        public bool IntegretyCheck { get; set; }

        private void ValidateEncryptFileParams(string inputFilePath, string outputFilePath, string publicKeyFilePath)
        {
            inputFilePath.Exists(nameof(inputFilePath));
            outputFilePath.Exists(nameof(outputFilePath));
            publicKeyFilePath.Exists(nameof(publicKeyFilePath));
        }


        private void ValidateEncryptStreamParameters(Stream inputStream, Stream outputStream, Stream publicKeyStream)
        {
            inputStream.IsNull(nameof(inputStream));

            outputStream.IsNull(nameof(inputStream));

            publicKeyStream.IsNull(nameof(inputStream));
        }

    }
}
