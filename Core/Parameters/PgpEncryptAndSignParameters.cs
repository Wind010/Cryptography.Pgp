
namespace Cryptography.Pgp.Core.Parameters
{
    public class PgpEncryptAndSignFileParameters: PgpDecryptFilepathParameters
    {

        public PgpEncryptOptions Options { get; set; }


        public override void Validate()
        {
            base.Validate();
            Options.CheckDefaults();
        }
    }
}
