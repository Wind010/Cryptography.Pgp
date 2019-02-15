using Org.BouncyCastle.Bcpg.OpenPgp;


namespace Cryptography.Pgp.Core.Models
{
    public class PgpInfo : KeyPair
    {
        public CompressionAlgorithm CompressionAlgorithm { get; set; }

        public SymmetricKeyAlgorithm SymmetricKeyAlgorithm { get; set; }

        public int SignatureType { get; set; }

        public PublicKeyAlgorithm PublicKeyAlgorithm { get; set; }

        public FileType FileType { get; set; }

        /// <summary>
        /// Mapping of internal FileType enumeration to PgpLiteralData character indicator of format.
        /// </summary>
        /// <param name="fileType"><see cref="FileType"/></param>
        /// <returns><see cref="char"/></returns>
        public char GetPgpLiteralDataFormat()
        {
            switch(FileType)
            {
                case FileType.UTF8:
                    return PgpLiteralData.Utf8;
                case FileType.Text:
                    return PgpLiteralData.Text;
                default:
                    return PgpLiteralData.Binary;
            }
        }


    }
}
