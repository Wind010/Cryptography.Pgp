using System.Threading;
using System.Threading.Tasks;
using Cryptography.Pgp.Core.Models;

namespace Cryptography.Pgp.Core
{
    public interface IKeyGenerator
    {
        void GenerateKeys(PgpInfo pgpInfo);
        Task GenerateKeysAsync(PgpInfo pgpInfo, CancellationToken ct);
    }
}