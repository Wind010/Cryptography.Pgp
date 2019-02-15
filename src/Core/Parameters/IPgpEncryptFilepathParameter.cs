namespace Cryptography.Pgp.Core.Parameters
{
    public interface IPgpEncryptFilepathParameter
    {
        string InputFilepath { get; set; }
        string OutputFilepath { get; set; }
        string PublicKeyFilepath { get; set; }

        void Validate();
    }
}