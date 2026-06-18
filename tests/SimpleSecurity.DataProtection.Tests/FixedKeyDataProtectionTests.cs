using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using SimpleSecurity.DataProtection;
using Xunit;

namespace SimpleSecurity.DataProtection.Tests;

public class FixedKeyDataProtectionTests
{
    private static IDataProtectionProvider Provider(string secret = "abc")
        => new FixedKeyDataProtectionProvider(Encoding.UTF8.GetBytes(secret));

    [Fact]
    public void Roundtrips_plaintext()
    {
        var protector = Provider().CreateProtector("cookies");
        var data = Encoding.UTF8.GetBytes("hello world");

        var protectedData = protector.Protect(data);
        var unprotected = protector.Unprotect(protectedData);

        Assert.Equal(data, unprotected);
    }

    [Fact]
    public void Same_secret_decrypts_across_provider_instances()
    {
        var a = Provider().CreateProtector("auth");
        var b = Provider().CreateProtector("auth");

        var token = a.Protect(Encoding.UTF8.GetBytes("session"));

        Assert.Equal("session", Encoding.UTF8.GetString(b.Unprotect(token)));
    }

    [Fact]
    public void Different_secret_cannot_decrypt()
    {
        var token = Provider("secret-one").CreateProtector("auth").Protect([1, 2, 3]);

        Assert.Throws<CryptographicException>(
            () => Provider("secret-two").CreateProtector("auth").Unprotect(token));
    }

    [Fact]
    public void Different_purpose_cannot_decrypt()
    {
        var token = Provider().CreateProtector("purpose-a").Protect([1, 2, 3]);

        Assert.Throws<CryptographicException>(
            () => Provider().CreateProtector("purpose-b").Unprotect(token));
    }

    [Fact]
    public void Nested_purposes_are_isolated()
    {
        var root = Provider();
        var nested = root.CreateProtector("outer").CreateProtector("inner");
        var token = nested.Protect([9]);

        var sameNested = root.CreateProtector("outer").CreateProtector("inner");
        Assert.Equal(new byte[] { 9 }, sameNested.Unprotect(token));

        Assert.Throws<CryptographicException>(
            () => root.CreateProtector("outer").Unprotect(token));
    }

    [Fact]
    public void Tampering_is_detected()
    {
        var protector = Provider().CreateProtector("x");
        var token = protector.Protect(Encoding.UTF8.GetBytes("important"));
        token[^1] ^= 0xFF; // flip a ciphertext bit

        Assert.Throws<CryptographicException>(() => protector.Unprotect(token));
    }

    [Fact]
    public void Truncated_payload_is_rejected()
    {
        var protector = Provider().CreateProtector("x");
        Assert.Throws<CryptographicException>(() => protector.Unprotect([1, 2, 3]));
    }

    [Fact]
    public void Ciphertext_differs_each_call_due_to_random_nonce()
    {
        var protector = Provider().CreateProtector("x");
        var data = Encoding.UTF8.GetBytes("same input");

        Assert.NotEqual(protector.Protect(data), protector.Protect(data));
    }

    [Fact]
    public void DI_registration_replaces_default_provider()
    {
        var services = new ServiceCollection();
        // Stand in for any pre-existing provider (e.g. the framework's AddDataProtection()).
        services.AddSingleton<IDataProtectionProvider>(new StubProvider());
        services.UseSimpleDataProtection("env-style-key");

        using var sp = services.BuildServiceProvider();
        var provider = sp.GetRequiredService<IDataProtectionProvider>();

        Assert.IsType<FixedKeyDataProtectionProvider>(provider);
        var protector = provider.CreateProtector("test");
        Assert.Equal("ok", Encoding.UTF8.GetString(
            protector.Unprotect(protector.Protect(Encoding.UTF8.GetBytes("ok")))));
    }

    [Fact]
    public void Missing_secret_throws_at_resolution()
    {
        var services = new ServiceCollection();
        services.UseSimpleDataProtection(); // no secret configured

        using var sp = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(
            () => { _ = sp.GetRequiredService<IDataProtectionProvider>(); });
    }

    private sealed class StubProvider : IDataProtectionProvider
    {
        public IDataProtector CreateProtector(string purpose) => throw new NotSupportedException();
    }
}
