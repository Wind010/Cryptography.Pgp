namespace Cryptography.Pgp.Core.Parameters
{
    public interface IPgpEncryptStringParameters
    {
        string Input { get; set; }
        string Output { get; set; }
        string PublicKey { get; set; }

        void Validate();
    }
}