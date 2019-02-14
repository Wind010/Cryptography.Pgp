using Org.BouncyCastle.Bcpg.OpenPgp;

namespace Cryptography.Pgp.Core.Models
{
    public interface IPrivateKey
    {
        PgpSecretKey SecretKey { get; }
        PgpPrivateKey Value { get; }
    }
}