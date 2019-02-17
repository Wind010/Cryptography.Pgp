using System.IO;

namespace Cryptography.Pgp.Core.Parameters
{
    using Extensions;

    public class PgpDecryptStreamParameters : PgpEncryptStreamParameters
    {
        bool _disposed = false;

        /// <summary>
        /// Stream of the private key.
        /// </summary>
        public Stream PrivateKeyStream { get; set; }

        public override void Validate()
        {
            base.Validate();
            PrivateKeyStream.IsNull(nameof(PrivateKeyStream));
            PrivateKeyStream.Position = 0;
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed) { return; }

            if (disposing)
            {
                // For unmanaged objects use SafeFileHandle. 

                // Free any other managed objects here.
                PrivateKeyStream.Dispose();
            }

            _disposed = true;
            base.Dispose(disposing);
        }



    }
}
