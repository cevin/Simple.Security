using System.Text;
using Microsoft.AspNetCore.DataProtection;
using SimpleSecurity.DataProtection;

var builder = WebApplication.CreateBuilder(args);

// One fixed secret drives all data protection — no XML key-ring on disk.
// The extension hangs straight off `builder` and returns it, so it chains like any AddXxx.
// Try: set APP_KEY in the environment, otherwise fall back to an inline demo key.
builder.UseSimpleDataProtection(options =>
{
    var key = builder.Configuration["APP_KEY"] ?? "demo-only-replace-with-a-32-byte-random-secret";
    options.UseSecret(key);
});

var app = builder.Build();

app.MapGet("/protect", (string value, IDataProtectionProvider provider) =>
{
    var protector = provider.CreateProtector("MinimalApiSample.Demo.v1");
    var token = Convert.ToBase64String(protector.Protect(Encoding.UTF8.GetBytes(value)));
    return Results.Ok(new { token });
});

app.MapGet("/unprotect", (string token, IDataProtectionProvider provider) =>
{
    var protector = provider.CreateProtector("MinimalApiSample.Demo.v1");
    try
    {
        var value = Encoding.UTF8.GetString(protector.Unprotect(Convert.FromBase64String(token)));
        return Results.Ok(new { value });
    }
    catch (Exception)
    {
        return Results.BadRequest(new { error = "Invalid or tampered token." });
    }
});

app.Run();
