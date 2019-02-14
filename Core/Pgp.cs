using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Cryptography.Pgp.Core
{
    using Models;

    public class Pgp : IDisposable
    {
        private const int BufferSize = 0x10000;

        public CompressionAlgorithm CompressionAlgorithm { get; set; }

        public SymmetricKeyAlgorithm SymmetricKeyAlgorithm { get; set; }

        public int SignatureType { get; set; }

        public PublicKeyAlgorithm PublicKeyAlgorithm { get; set; }

        public FileType FileType { get; set; }

        public Pgp()
        {

        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
