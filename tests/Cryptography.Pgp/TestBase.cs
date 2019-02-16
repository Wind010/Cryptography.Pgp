using Microsoft.Extensions.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;


namespace Cryptography.Pgp.Core.Tests
{
    using Tests.Extensions;

    [ExcludeFromCodeCoverage]
    public class TestBase
    {
        protected TestBase() { }


        protected static string PublicKey { get; private set; }
        protected static string PrivateKey { get; private set; }
        protected static string Password { get; private set; }
        protected static string EmailAddress { get; private set; }

        protected static IConfigurationRoot Configuration { private set; get; }

        protected static void LoadConfiguration(TestContext context)
        {
            Configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            PublicKey = Configuration.GetSection(nameof(PublicKey)).Value.DecodeBase64(Encoding.UTF8);
            PrivateKey = Configuration.GetSection(nameof(PrivateKey)).Value.DecodeBase64(Encoding.UTF8);
            Password = Configuration.GetSection(nameof(Password)).Value;
            EmailAddress = Configuration.GetSection(nameof(EmailAddress)).Value;
        }

    }
}
