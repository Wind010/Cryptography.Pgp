namespace Cryptography.Pgp.Core.Parameters
{
    public interface IPgpEncryptOptions
    {
        bool? Armor { get; set; }
        bool? IntegrityCheck { get; set; }
        string Password { get; set; }

        void CheckDefaults();
    }
}