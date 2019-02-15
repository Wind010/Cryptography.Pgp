

namespace Cryptography.Pgp.Core.Parameters
{
    public class PgpEncryptOptions : IPgpEncryptOptions
    {
        /// <summary>
        /// 
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Encase the encrypted message in ASCII armor.
        /// </summary>
        public bool? Armor { get; set; }

        /// <summary>
        /// Check integrity of encrypted message.
        /// </summary>
        public bool? IntegrityCheck { get; set; }


        public void CheckDefaults()
        {
            if (! Armor.HasValue) { Armor = true; }
            if (! IntegrityCheck.HasValue) { IntegrityCheck = true; }
            if (Password == null) { Password = string.Empty; }
        }
    }

}
