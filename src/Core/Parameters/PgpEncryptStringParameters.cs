
namespace Cryptography.Pgp.Core.Parameters
{
    using Extensions;

    public class PgpEncryptStringParameters : IPgpEncryptStringParameters
    {
        /// <summary>
        /// String to be encrypted or decrypted.
        /// </summary>
        public string Input { get; set; }

        /// <summary>
        /// The encrypted or decrypted string.
        /// </summary>
        public string Output { get; set; }

        /// <summary>
        /// Public key string.
        /// </summary>
        public string PublicKey { get; set; }


        public virtual void Validate()
        {
            Input.IsNullOrWhitespace(nameof(Input));
            Output.IsNullOrWhitespace(nameof(Output));
            PublicKey.IsNullOrWhitespace(nameof(PublicKey));
        }

    }
}
