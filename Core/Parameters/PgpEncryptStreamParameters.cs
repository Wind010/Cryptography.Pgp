using System.IO;

namespace Cryptography.Pgp.Core.Parameters
{
    using Extensions;

    public class PgpEncryptStreamParameters : PgpEncryptOptions, IPgpEncryptStreamParameters
    {
        /// <summary>
        /// Stream to be encrypted or decrypted.
        /// </summary>
        public Stream InputStream { get; set; }

        /// <summary>
        /// The encrypted or decrypted stream.
        /// </summary>
        public Stream OutputStream { get; set; }

        /// <summary>
        /// Stream of the public key.
        /// </summary>
        public Stream PublicKeyStream { get; set; }


        public virtual void Validate()
        {
            InputStream.IsNull(nameof(InputStream));
            OutputStream.IsNull(nameof(OutputStream));
            PublicKeyStream.IsNull(nameof(PublicKeyStream));
        }

    }
}
