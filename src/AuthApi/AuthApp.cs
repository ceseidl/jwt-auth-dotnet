using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi;

public sealed class AuthAppOptions
{
    // Changes the JWT validation (the lab uses it to show traps).
    public Action<JwtBearerOptions>? TweakJwt { get; init; }
    // The bug from the article: role taken from the request body.
    public bool TrustRoleFromClient { get; init; }
    // The other bug: unknown email answers faster.
    public bool SkipDummyHash { get; init; }
}

public static class AuthApp
{
    public static WebApplication Create(
        string[] args, AuthAppOptions? options = null)
    {
        options ??= new();
        var builder = WebApplication.CreateBuilder(args);
        var jwt = builder.Configuration.GetSection("Jwt")
            .Get<JwtSettings>() ?? new JwtSettings();

        builder.Services.AddSingleton(jwt);
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<UserStore>();
        builder.Services.AddSingleton<RefreshTokenStore>();
        builder.Services.AddSingleton<TokenService>();
        builder.Services.AddProblemDetails();

        #region jwt-bearer
        builder.Services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(o =>
            {
                // keep "role" and "sub" as they are in the token
                o.MapInboundClaims = false;
                o.TokenValidationParameters = new()
                {
                    ValidIssuer = jwt.Issuer,
                    ValidAudience = jwt.Audience,
                    IssuerSigningKey = jwt.Key(),
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                    NameClaimType = "email",
                    RoleClaimType = "role",
                    // the default is 5 minutes
                    ClockSkew = TimeSpan.FromSeconds(30),
                };
                options.TweakJwt?.Invoke(o);
            });
        builder.Services.AddAuthorization();
        #endregion

        var app = builder.Build();
        Seed(app, builder.Configuration);

        #region pipeline
        app.UseAuthentication();
        app.UseAuthorization();
        #endregion

        app.MapAuthEndpoints();
        return app;
    }

    // Development only: an admin user from configuration.
    static void Seed(WebApplication app, IConfiguration config)
    {
        var email = config["Seed:AdminEmail"];
        var password = config["Seed:AdminPassword"];
        if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            return;
        app.Services.GetRequiredService<UserStore>()
            .Register(email, password, "admin");
    }
}
