
namespace Cryptography.Common.Models
{
    public class PrivatePublicKeyPair
    {
        public PrivatePublicKeyPair()
        {
        }

        public PrivatePublicKeyPair(string privateKey, string publicKey)
        {
            PrivateKey = privateKey;
            PublicKey = publicKey;
        }

        public string PrivateKey { get; }
        public string PublicKey { get; }
    }
}
