using System.Text;

namespace SimpleSecurity.DataProtection;

/// <summary>
/// Configuration for the fixed-key data protection provider. All protectors and the
/// keys they produce are derived from <see cref="Secret"/> (optionally salted by
/// <see cref="Salt"/>), so there are no key-ring files to persist or synchronize.
/// </summary>
public sealed class SimpleDataProtectionOptions
{
    /// <summary>
    /// The master secret (input keying material). Every key is derived from this value
    /// via HKDF. Treat it like Laravel's <c>APP_KEY</c>: keep it out of source control,
    /// and keep it identical across every instance that must read each other's payloads.
    /// </summary>
    public byte[]? Secret { get; set; }

    /// <summary>
    /// Optional HKDF salt for extra domain separation. May be <see langword="null"/>.
    /// Changing it invalidates every previously protected payload.
    /// </summary>
    public byte[]? Salt { get; set; }

    /// <summary>Sets <see cref="Secret"/> from a UTF-8 string.</summary>
    public void UseSecret(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        Secret = Encoding.UTF8.GetBytes(secret);
    }

    /// <summary>Sets <see cref="Salt"/> from a UTF-8 string.</summary>
    public void UseSalt(string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(salt);
        Salt = Encoding.UTF8.GetBytes(salt);
    }
}
