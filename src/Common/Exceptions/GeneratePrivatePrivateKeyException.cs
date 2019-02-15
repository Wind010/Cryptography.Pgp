using System;
using System.Diagnostics.CodeAnalysis;

namespace Cryptography.Common.Exceptions
{
    [Serializable]
    [ExcludeFromCodeCoverage]
    public class GeneratePrivatePublicKeysException : BaseException
    {
        public GeneratePrivatePublicKeysException()
        {
        }

        public GeneratePrivatePublicKeysException(string message)
                : base(message)
        {
        }

        public GeneratePrivatePublicKeysException(string message, Exception inner)
                : base(message, inner)
        {
        }
    }
}
