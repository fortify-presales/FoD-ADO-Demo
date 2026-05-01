using Microsoft.Extensions.Configuration;
using VulnerableApi.Services;
using Xunit;

namespace VulnerableApi.Tests;

public class SecurityBehaviorTests
{
    [Fact]
    public void WeakToken_IncludesSensitiveData()
    {
        var service = new InsecureTokenService();

        var token = service.CreateWeakToken("alice", "Password123!", "user");
        var decoded = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(token));

        Assert.Contains("Password123!", decoded);
    }

    [Fact]
    public void WeakToken_AdminBypassContainsCheck()
    {
        var service = new InsecureTokenService();

        Assert.True(service.IsAdminByContainsCheck("this-is-not-real-admin-token"));
    }

    [Fact]
    public void WeakCrypto_UsesMd5()
    {
        var service = new WeakCryptoService();

        var hash = service.HashWithMd5("abc");

        Assert.Equal("900150983cd24fb0d6963f7d28e17f72", hash);
    }

    [Fact]
    public void SqlInjectionPayload_LeadsToUnsafeLogin()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:DefaultConnection"] = $"Data Source={Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".db")}" 
            })
            .Build();

        var service = new VulnerableDbService(config);
        service.Initialize();

        var user = service.LoginUnsafe("' OR 1=1 --", "irrelevant");

        Assert.NotNull(user);
    }

    [Fact]
    public void QueryBuilder_EmbedsUserInputDirectly()
    {
        var config = new ConfigurationBuilder().Build();
        var service = new VulnerableDbService(config);

        var sql = service.BuildUnsafeUserSearchQuery("x' OR '1'='1");

        Assert.Contains("OR", sql);
        Assert.Contains("x' OR '1'='1", sql);
    }
}
