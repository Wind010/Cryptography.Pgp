using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;

namespace Cryptography.Pgp.Core.Models
{
    public class Keys
    {
        public PrivateKey Private { get; private set; }
        public PublicKey Public { get; private set; }

        public Keys(PgpPrivateKey privateKey, PgpSecretKey secretKey, PgpPublicKey publicKey)
        {
            Private = new PrivateKey(privateKey, secretKey);
            Public = new PublicKey(publicKey);
        }

        public Keys(Stream privateKey, Stream publicKey, string password)
        {
            Private = new PrivateKey(privateKey, password);
            
            Public = new PublicKey(publicKey);
        }

    }
}
