using System;
using System.Diagnostics.CodeAnalysis;

namespace Cryptography.Common.Exceptions
{
    [Serializable]
    [ExcludeFromCodeCoverage]
    public class EncryptException : BaseException
    {
        public EncryptException()
        {
        }

        public EncryptException(string message)
            : base(message)
        {
        }

        public EncryptException(string message, Exception inner)
            : base(message, inner)
        {
        }

    }
}
