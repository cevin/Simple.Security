using System.Text;
using Microsoft.Extensions.DependencyInjection;

namespace SimpleSecurity.DataProtection;

internal sealed class SimpleDataProtectionBuilder : ISimpleDataProtectionBuilder
{
    public IServiceCollection Services { get; }

    public SimpleDataProtectionBuilder(IServiceCollection services)
    {
        Services = services;
    }

    public ISimpleDataProtectionBuilder UseSecret(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        return UseSecret(Encoding.UTF8.GetBytes(secret));
    }

    public ISimpleDataProtectionBuilder UseSecret(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
            throw new ArgumentException("The data protection secret must not be empty.", nameof(secret));
        return Configure(o => o.Secret = secret);
    }

    public ISimpleDataProtectionBuilder UseSecretFromEnvironment(string variableName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(variableName);
        var value = Environment.GetEnvironmentVariable(variableName);
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException(
                $"Environment variable '{variableName}' is not set or empty; cannot configure the data protection secret.");
        return UseSecret(value);
    }

    public ISimpleDataProtectionBuilder UseSalt(string salt)
    {
        ArgumentException.ThrowIfNullOrEmpty(salt);
        return UseSalt(Encoding.UTF8.GetBytes(salt));
    }

    public ISimpleDataProtectionBuilder UseSalt(byte[] salt)
    {
        ArgumentNullException.ThrowIfNull(salt);
        return Configure(o => o.Salt = salt);
    }

    public ISimpleDataProtectionBuilder Configure(Action<SimpleDataProtectionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.Configure(configure);
        return this;
    }
}
