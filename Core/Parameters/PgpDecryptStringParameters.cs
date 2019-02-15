namespace Cryptography.Pgp.Core.Parameters
{
    using Extensions;

    public class PgpDecryptStringParameters : PgpEncryptStringParameters
    {
        /// <summary>
        /// Private key string.
        /// </summary>
        public string PrivateKey { get; set; }


        public override void Validate()
        {
            base.Validate();
            PrivateKey.IsNullOrWhitespace(nameof(PrivateKey));
        }
    }

}
