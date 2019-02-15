using System;

namespace Cryptography.Pgp.Core
{\
    using Models;

    public abstract class PgpBase : IDisposable
    {
        protected bool IsDisposed;
        protected PgpInfo Info;

        protected virtual void Dispose(bool disposing)
        {
            if (!IsDisposed)
            {
                Info = null;
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
