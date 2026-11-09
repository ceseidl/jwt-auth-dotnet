using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi;

#region settings
public sealed class JwtSettings
{
    public string Issuer { get; init; } = "shop-auth";
    public string Audience { get; init; } = "shop-api";
    public string SigningKey { get; init; } = "";
    public TimeSpan AccessTokenLifetime { get; init; } =
        TimeSpan.FromMinutes(5);
    public TimeSpan RefreshTokenLifetime { get; init; } =
        TimeSpan.FromDays(7);

    public SymmetricSecurityKey Key()
    {
        var bytes = Encoding.UTF8.GetBytes(SigningKey);
        // HMAC-SHA256 needs at least 256 bits (32 bytes)
        if (bytes.Length < 32)
            throw new InvalidOperationException(
                "Jwt:SigningKey needs at least 32 bytes.");
        return new SymmetricSecurityKey(bytes);
    }
}
#endregion
