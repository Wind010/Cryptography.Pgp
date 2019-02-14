using System;
using System.Diagnostics.CodeAnalysis;

namespace Cryptography.Common.Exceptions
{
    [Serializable]
    [ExcludeFromCodeCoverage]
    public class DecryptException : BaseException
    {
        public DecryptException()
        {
        }

        public DecryptException(string message)
            : base(message)
        {
        }

        public DecryptException(string message, Exception inner)
            : base(message, inner)
        {
        }

    }
}
