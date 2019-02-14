using System;
using System.Collections.Generic;
using System.Text;

namespace Cryptography.Pgp.Core.Models
{
    using Cryptography.Common.Models;

    public class PgpInfo : PrivatePublicKeyPair
    {
        public PgpInfo(string privateKeyFilePath, string publicKeyFilePath, string username, string password)
        {

            PrivateKeyFilePath = string.IsNullOrWhiteSpace(privateKeyFilePath) ? 
                throw new ArgumentNullException(nameof(privateKeyFilePath)) : privateKeyFilePath;
            PublicKeyFilePath = string.IsNullOrWhiteSpace(publicKeyFilePath) ?
                throw new ArgumentNullException(nameof(publicKeyFilePath)) : publicKeyFilePath;

            Username = string.IsNullOrWhiteSpace(username) ? string.Empty : username;
            Password = string.IsNullOrWhiteSpace(password) ? string.Empty : password;

            Strength = 1024;
            Certainty = 8;
            Armor = true;
        }

        public string PrivateKeyFilePath { get; private set; }

        public string PublicKeyFilePath { get; private set; }

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
