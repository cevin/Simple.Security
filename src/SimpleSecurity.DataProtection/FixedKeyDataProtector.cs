using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace SimpleSecurity.DataProtection;

/// <summary>
/// An <see cref="IDataProtector"/> whose AES-GCM key is derived, via HKDF-SHA256, from a
/// fixed master secret and the protector's purpose chain. Purpose isolation is therefore
/// cryptographic: a protector created for one purpose cannot decrypt another's payloads.
/// </summary>
/// <remarks>
/// Payload layout: <c>[version:1][nonce:12][tag:16][ciphertext:n]</c>. The version byte is
/// bound as AES-GCM associated data so it cannot be tampered with. AES-GCM's authentication
/// tag makes a separate HMAC unnecessary.
/// </remarks>
internal sealed class FixedKeyDataProtector : IDataProtector
{
    private const byte FormatVersion = 1;
    private const int NonceSize = 12;   // 96-bit nonce, the AES-GCM standard
    private const int TagSize = 16;     // 128-bit authentication tag
    private const int KeySize = 32;     // AES-256

    // HKDF context label keeps keys from this library distinct from any other HKDF use of
    // the same secret. Bump the suffix only alongside a FormatVersion change.
    private const string InfoPrefix = "SimpleSecurity.DataProtection|v1|";

    private readonly byte[] _secret;
    private readonly byte[]? _salt;
    private readonly string _purpose;
    private readonly byte[] _key;

    public FixedKeyDataProtector(byte[] secret, byte[]? salt, string purpose)
    {
        _secret = secret;
        _salt = salt;
        _purpose = purpose;
        _key = DeriveKey(secret, salt, purpose);
    }

    public IDataProtector CreateProtector(string purpose)
    {
        ArgumentException.ThrowIfNullOrEmpty(purpose);
        return new FixedKeyDataProtector(_secret, _salt, CombinePurpose(_purpose, purpose));
    }

    public byte[] Protect(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);

        Span<byte> nonce = stackalloc byte[NonceSize];
        RandomNumberGenerator.Fill(nonce);

        var result = new byte[1 + NonceSize + TagSize + plaintext.Length];
        result[0] = FormatVersion;
        nonce.CopyTo(result.AsSpan(1, NonceSize));

        var tag = result.AsSpan(1 + NonceSize, TagSize);
        var ciphertext = result.AsSpan(1 + NonceSize + TagSize, plaintext.Length);

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, AssociatedData);
        return result;
    }

    public byte[] Unprotect(byte[] protectedData)
    {
        ArgumentNullException.ThrowIfNull(protectedData);
        if (protectedData.Length < 1 + NonceSize + TagSize)
            throw new CryptographicException("The protected payload is invalid or truncated.");
        if (protectedData[0] != FormatVersion)
            throw new CryptographicException($"Unsupported protected payload version: {protectedData[0]}.");

        var nonce = protectedData.AsSpan(1, NonceSize);
        var tag = protectedData.AsSpan(1 + NonceSize, TagSize);
        var cipherStart = 1 + NonceSize + TagSize;
        var ciphertext = protectedData.AsSpan(cipherStart);
        var plaintext = new byte[ciphertext.Length];

        try
        {
            using var aes = new AesGcm(_key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, AssociatedData);
        }
        catch (CryptographicException)
        {
            // Wrong key, wrong purpose, or tampered data all surface as a generic failure.
            throw new CryptographicException(
                "The protected payload could not be decrypted. The secret may be wrong, the purpose may not match, or the data was tampered with.");
        }

        return plaintext;
    }

    private static ReadOnlySpan<byte> AssociatedData => [FormatVersion];

    private static string CombinePurpose(string parent, string child)
        => parent.Length == 0 ? child : $"{parent}{child}"; // U+001F unit separator

    private static byte[] DeriveKey(byte[] secret, byte[]? salt, string purpose)
    {
        var info = Encoding.UTF8.GetBytes(InfoPrefix + purpose);
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, secret, KeySize, salt, info);
    }
}
