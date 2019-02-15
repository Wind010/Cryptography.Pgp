namespace Cryptography.Pgp.Core.Parameters
{
    public class PgpEncryptAndSignStreamParameters : PgpDecryptStreamParameters
    {

        public PgpEncryptOptions Options { get; set; }


        public override void Validate()
        {
            base.Validate();
            Options.CheckDefaults();
        }
    }
}

