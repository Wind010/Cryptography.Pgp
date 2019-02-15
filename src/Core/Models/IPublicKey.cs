using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Cryptography.Pgp.Core.Models
{
    public interface IPublicKey
    {
        PgpPublicKey Value { get; }
    }
}