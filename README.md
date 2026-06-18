# SimpleSecurity.DataProtection

> English | [中文](README_zh.md)

A replacement for ASP.NET Core's `IDataProtectionProvider`. All keys are derived from a single
secret string, like Laravel (PHP)'s `APP_KEY`. There is no key-ring XML under
`~/.aspnet/dataprotection-keys/`, no key rotation, and no shared storage to configure.
Instances configured with the same secret can decrypt each other's payloads.

## Behavior

- Default ASP.NET Core data protection generates a random key, writes it to a key-ring (disk,
  Redis, or blob storage), and rotates it every 90 days. If the key-ring is lost, existing
  cookies, tokens, and antiforgery values cannot be decrypted.
- This library uses one fixed secret instead. The secret is supplied by the application and is
  not persisted by the library. There is no automatic rotation.

## How it works

- HKDF-SHA256 derives a separate AES-256 key per *purpose*. `CreateProtector("cookies")` and
  `CreateProtector("antiforgery")` use different keys, so a protector cannot decrypt another
  purpose's payloads.
- AES-GCM provides authenticated encryption. Its 128-bit tag detects tampering, so no separate
  HMAC is used.
- Payload layout: `[version:1][nonce:12][tag:16][ciphertext:n]`. The version byte is bound as
  AES-GCM associated data. The format can change without breaking older payloads.

## Install

```bash
dotnet add package SimpleSecurity.DataProtection
```

Target frameworks: `net8.0`, `net9.0`, `net10.0`.

## Usage

### Inline secret

```csharp
builder.Services.UseSimpleDataProtection("a-long-random-secret");
```

### From an environment variable

```csharp
builder.Services.UseSimpleDataProtection()
    .UseSecretFromEnvironment("APP_KEY");
```

Throws at startup if the variable is missing or empty.

### From configuration (`appsettings.json`, user secrets, Key Vault)

```csharp
builder.Services.UseSimpleDataProtection()
    .UseSecret(builder.Configuration["Security:DataProtectionKey"]!);
```

### Options delegate and optional salt

```csharp
builder.Services.UseSimpleDataProtection(options =>
{
    options.UseSecret(builder.Configuration["Security:Key"]!);
    options.UseSalt("my-app-domain-separator"); // optional HKDF salt
});
```

Every `UseSimpleDataProtection(...)` overload returns `ISimpleDataProtectionBuilder` for chaining:

```csharp
builder.Services
    .UseSimpleDataProtection("secret")
    .UseSalt("tenant-42");
```

### On the host builder

`IHostApplicationBuilder` overloads register the provider and return the builder. They work with
`WebApplicationBuilder` and `HostApplicationBuilder`:

```csharp
builder.UseSimpleDataProtection("a-long-random-secret");
// or
builder.UseSimpleDataProtection(o => o.UseSecret(builder.Configuration["APP_KEY"]!));
```

### Consuming the provider

Same API as the built-in provider. Inject `IDataProtectionProvider` and create a protector:

```csharp
public class TokenService(IDataProtectionProvider provider)
{
    private readonly IDataProtector _protector = provider.CreateProtector("MyApp.Tokens.v1");

    public string Protect(string value) =>
        Convert.ToBase64String(_protector.Protect(Encoding.UTF8.GetBytes(value)));
}
```

## Notes

- Keep the secret confidential and stable. Anyone with the secret can read and forge payloads.
  Changing the secret invalidates existing cookies, tokens, and antiforgery values.
- Use a high-entropy secret. HKDF stretches the input but does not add entropy. Use 32+ random
  bytes (for example `openssl rand -base64 32`), not a short passphrase.
- The same secret and salt produce interchangeable instances. The secret must be distributed to
  every instance that needs to interoperate.
- No automatic rotation. To rotate, change the secret (existing payloads stop decrypting) or
  bump the purpose string (for example `...Tokens.v2`).

## License

MIT
