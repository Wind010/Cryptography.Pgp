using System;

namespace Cryptography.Pgp.Core.Models
{

    public class KeyGenerationInfo : KeyPair
    {
        public KeyGenerationInfo(string privateKeyFilePath, string publicKeyFilePath, string username, string password)
        {
            PrivateKeyFilepath = string.IsNullOrWhiteSpace(privateKeyFilePath) ? 
                throw new ArgumentNullException(nameof(privateKeyFilePath)) : privateKeyFilePath;
            PublicKeyFilepath = string.IsNullOrWhiteSpace(publicKeyFilePath) ?
                throw new ArgumentNullException(nameof(publicKeyFilePath)) : publicKeyFilePath;

            Username = string.IsNullOrWhiteSpace(username) ? string.Empty : username;
            Password = string.IsNullOrWhiteSpace(password) ? string.Empty : password;

            Strength = 1024;
            Certainty = 8;
            Armor = true;
        }

        /// <summary>
        /// Username or Identity.
        /// </summary>
        public string Username { get; set; }

        public string Password { get; set; }

        public int Strength { get; set; }

        public int Certainty { get; set; }

        public bool Armor { get; set; }


    }
}
