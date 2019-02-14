using System.Threading;
using System.Threading.Tasks;
using Cryptography.Pgp.Core.Models;

namespace Cryptography.Pgp.Core
{
    public interface IKeyGenerator
    {
        void GenerateKeys(KeyGenerationInfo pgpInfo);
        Task GenerateKeysAsync(KeyGenerationInfo pgpInfo, CancellationToken ct);
    }
}