namespace Cryptography.Pgp.Core.Parameters
{
    using Extensions;

    public class PgpDecryptFilepathParameters : PgpEncryptFilepathParameter, IPgpDecrytpFilepathParameters
    {
        /// <summary>
        /// File path to the private key.
        /// </summary>
        public string PrivateKeyFilepath { get; set; }

        public override void Validate()
        {
            base.Validate();
            PrivateKeyFilepath.Exists(nameof(PrivateKeyFilepath));
        }

    }
}
