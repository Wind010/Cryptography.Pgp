namespace Cryptography.Pgp.Core.Parameters
{
    public interface IPgpDecrytpFilepathParameters
    {
        string PrivateKeyFilepath { get; set; }

        void Validate();
    }
}