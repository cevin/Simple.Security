using Microsoft.Extensions.DependencyInjection;

namespace SimpleSecurity.DataProtection;

/// <summary>
/// Fluent configuration surface returned by
/// <see cref="SimpleDataProtectionServiceCollectionExtensions.UseSimpleDataProtection(IServiceCollection)"/>.
/// Every method returns the same builder so calls can be chained.
/// </summary>
public interface ISimpleDataProtectionBuilder
{
    /// <summary>The service collection the provider is registered against.</summary>
    IServiceCollection Services { get; }

    /// <summary>Use a UTF-8 string as the master secret (Laravel <c>APP_KEY</c> style).</summary>
    ISimpleDataProtectionBuilder UseSecret(string secret);

    /// <summary>Use raw bytes as the master secret.</summary>
    ISimpleDataProtectionBuilder UseSecret(byte[] secret);

    /// <summary>
    /// Read the master secret from an environment variable. Throws at startup if the
    /// variable is missing or empty, so misconfiguration fails fast.
    /// </summary>
    ISimpleDataProtectionBuilder UseSecretFromEnvironment(string variableName);

    /// <summary>Set an optional HKDF salt from a UTF-8 string for extra domain separation.</summary>
    ISimpleDataProtectionBuilder UseSalt(string salt);

    /// <summary>Set an optional HKDF salt from raw bytes.</summary>
    ISimpleDataProtectionBuilder UseSalt(byte[] salt);

    /// <summary>Apply an arbitrary configuration delegate against the options.</summary>
    ISimpleDataProtectionBuilder Configure(Action<SimpleDataProtectionOptions> configure);
}
