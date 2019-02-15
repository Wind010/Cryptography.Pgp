using System.Threading;
using System.Threading.Tasks;

namespace Cryptography.Pgp.Core
{
    using Models;

    public interface IKeyGenerator
    {
        Keys GenerateEncryptionKeys(KeyGenerationInfo keyInfo);
        Task<Keys> GenerateEncryptionKeysAsync(KeyGenerationInfo keyInfo, CancellationToken ct);
    }
}