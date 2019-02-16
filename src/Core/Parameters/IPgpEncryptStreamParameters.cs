using System.IO;

namespace Cryptography.Pgp.Core.Parameters
{
    public interface IPgpEncryptStreamParameters
    {
        Stream InputStream { get; set; }
        Stream PublicKeyStream { get; set; }

        void Validate();
    }
}