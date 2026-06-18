using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SimpleSecurity.DataProtection;

/// <summary>
/// Convenience extensions that register fixed-key data protection directly on a host
/// application builder and return that same builder for chaining. Works with any
/// <see cref="IHostApplicationBuilder"/> — including <c>WebApplicationBuilder</c> and
/// <c>HostApplicationBuilder</c> — without taking a dependency on the ASP.NET Core
/// shared framework.
/// </summary>
public static class SimpleDataProtectionHostBuilderExtensions
{
    /// <summary>
    /// Registers fixed-key data protection with the secret supplied inline, then returns
    /// <paramref name="builder"/> so further <c>builder.AddXxx(...)</c> calls can be chained.
    /// </summary>
    /// <example><c>builder.UseSimpleDataProtection("a-long-random-secret");</c></example>
    public static TBuilder UseSimpleDataProtection<TBuilder>(this TBuilder builder, string secret)
        where TBuilder : IHostApplicationBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.UseSimpleDataProtection(secret);
        return builder;
    }

    /// <summary>
    /// Registers fixed-key data protection configured through a delegate, then returns
    /// <paramref name="builder"/> for chaining. Use this for env-var / configuration / salt setups.
    /// </summary>
    /// <example>
    /// <c>builder.UseSimpleDataProtection(o => o.UseSecret(builder.Configuration["APP_KEY"]!));</c>
    /// </example>
    public static TBuilder UseSimpleDataProtection<TBuilder>(
        this TBuilder builder, Action<SimpleDataProtectionOptions> configure)
        where TBuilder : IHostApplicationBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.UseSimpleDataProtection(configure);
        return builder;
    }
}
