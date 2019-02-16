using System.IO;
using System;

namespace Cryptography.Pgp.Core.Parameters
{
    using Extensions;

    public class PgpEncryptStreamParameters : PgpEncryptOptions, IPgpEncryptStreamParameters, IDisposable
    {
        bool _disposed = false;

        /// <summary>
        /// Stream to be encrypted or decrypted.
        /// </summary>
        public Stream InputStream { get; set; }

        /// <summary>
        /// Stream of the public key.
        /// </summary>
        public Stream PublicKeyStream { get; set; }

        public virtual void Validate()
        {
            InputStream.IsNull(nameof(InputStream));
            PublicKeyStream.IsNull(nameof(PublicKeyStream));
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) { return; }

            if (disposing)
            {
                // Free any other managed objects here.
                InputStream.Dispose();
                PublicKeyStream.Dispose();
            }

            // Free any unmanaged objects here.
            //
            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        ~PgpEncryptStreamParameters()
        {
            Dispose(false);
        }
    }
}
