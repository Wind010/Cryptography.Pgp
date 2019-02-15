using System.IO;

namespace Cryptography.Pgp.Core.Parameters
{
    using Extensions;

    public class PgpDecryptStreamParameters : PgpEncryptStreamParameters
    {
        /// <summary>
        /// Stream of the private key.
        /// </summary>
        public Stream PrivateKeyStream { get; set; }

        public override void Validate()
        {
            base.Validate();
            PrivateKeyStream.IsNull(nameof(PrivateKeyStream));
        }
    }
}
