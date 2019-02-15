
namespace Cryptography.Pgp.Core.Parameters
{
    public class PgpEncryptAndSignFileParameters: PgpDecrytpFilepathParameters
    {

        public PgpEncryptOptions Options { get; set; }


        public override void Validate()
        {
            base.Validate();
            Options.CheckDefaults();
        }
    }
}
