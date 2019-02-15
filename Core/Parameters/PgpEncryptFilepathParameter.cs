namespace Cryptography.Pgp.Core.Parameters
{
    using Extensions;

    public class PgpEncryptFilepathParameter : IPgpEncryptFilepathParameter
    {
        /// <summary>
        /// File path to source to encrypt or decrypt.
        /// </summary>
        public string InputFilepath { get; set; }

        /// <summary>
        /// Output file path of the encrypted data.
        /// </summary>
        public string OutputFilepath { get; set; }

        /// <summary>
        /// File path to the public key.
        /// </summary>
        public string PublicKeyFilepath { get; set; }

        
        public virtual void Validate()
        {
            InputFilepath.Exists(nameof(InputFilepath));
            OutputFilepath.Exists(nameof(OutputFilepath));
            PublicKeyFilepath.Exists(nameof(PublicKeyFilepath));
        }


    }
}
