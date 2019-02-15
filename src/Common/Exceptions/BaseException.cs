using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.Serialization;
using System.Security.Permissions;

namespace Cryptography.Common.Exceptions
{
    [Serializable]
    [ExcludeFromCodeCoverage]
    public class BaseException : Exception
    {
        public string ResourceReferenceProperty { get; set; }

        public BaseException()
        {
        }

        public BaseException(string message)
            : base(message)
        {
        }

        public BaseException(string message, Exception inner)
            : base(message, inner)
        {
        }


        [SecurityPermission(SecurityAction.Demand, SerializationFormatter = true)]
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            if (info == null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            info.AddValue(nameof(ResourceReferenceProperty), ResourceReferenceProperty);
            base.GetObjectData(info, context);
        }
    }
}
