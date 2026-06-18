using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace SimpleSecurity.DataProtection;

/// <summary>
/// Registration helpers that swap ASP.NET Core's default key-ring data protection for a
/// fixed-secret implementation. All overloads remove any previously registered
/// <see cref="IDataProtectionProvider"/> and register <see cref="FixedKeyDataProtectionProvider"/>.
/// </summary>
public static class SimpleDataProtectionServiceCollectionExtensions
{
    /// <summary>
    /// Registers fixed-key data protection and returns a builder for configuring the secret.
    /// Use this when you want to set the key fluently, e.g.
    /// <c>services.UseSimpleDataProtection().UseSecretFromEnvironment("APP_KEY")</c>.
    /// </summary>
    public static ISimpleDataProtectionBuilder UseSimpleDataProtection(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // Replace the framework's key-ring provider entirely.
        services.RemoveAll<IDataProtectionProvider>();

        services.AddSingleton<IDataProtectionProvider>(sp =>
        {
            var options = sp.GetRequiredService<IOptions<SimpleDataProtectionOptions>>().Value;
            if (options.Secret is null || options.Secret.Length == 0)
            {
                throw new InvalidOperationException(
                    "No data protection secret configured. Call UseSecret(...), UseSecretFromEnvironment(...), " +
                    "or pass the secret to UseSimpleDataProtection(secret).");
            }

            return new FixedKeyDataProtectionProvider(options.Secret, options.Salt);
        });

        return new SimpleDataProtectionBuilder(services);
    }

    /// <summary>
    /// Registers fixed-key data protection with the secret supplied inline. Returns the builder
    /// so additional settings (e.g. a salt) can still be chained.
    /// </summary>
    public static ISimpleDataProtectionBuilder UseSimpleDataProtection(this IServiceCollection services, string secret)
        => services.UseSimpleDataProtection().UseSecret(secret);

    /// <summary>
    /// Registers fixed-key data protection and configures it through a delegate.
    /// </summary>
    public static ISimpleDataProtectionBuilder UseSimpleDataProtection(
        this IServiceCollection services, Action<SimpleDataProtectionOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        return services.UseSimpleDataProtection().Configure(configure);
    }
}
