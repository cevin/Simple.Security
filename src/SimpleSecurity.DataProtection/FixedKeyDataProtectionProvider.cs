using Microsoft.AspNetCore.DataProtection;

namespace SimpleSecurity.DataProtection;

/// <summary>
/// An <see cref="IDataProtectionProvider"/> that hands out <see cref="FixedKeyDataProtector"/>
/// instances, all derived from a single fixed master secret. This replaces the framework's
/// default key-ring-based provider, so there are no <c>*.xml</c> key files to manage.
/// </summary>
public sealed class FixedKeyDataProtectionProvider : IDataProtectionProvider
{
    private readonly byte[] _secret;
    private readonly byte[]? _salt;

    /// <summary>Creates a provider from the given master secret and optional HKDF salt.</summary>
    /// <param name="secret">Master keying material. Must be non-empty.</param>
    /// <param name="salt">Optional HKDF salt; may be <see langword="null"/>.</param>
    public FixedKeyDataProtectionProvider(byte[] secret, byte[]? salt = null)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
            throw new ArgumentException("The data protection secret must not be empty.", nameof(secret));

        _secret = secret;
        _salt = salt;
    }

    /// <inheritdoc />
    public IDataProtector CreateProtector(string purpose)
    {
        ArgumentException.ThrowIfNullOrEmpty(purpose);
        return new FixedKeyDataProtector(_secret, _salt, purpose);
    }
}
