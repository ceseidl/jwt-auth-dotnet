using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi;

public sealed record TokenPair(
    string AccessToken, string RefreshToken, int ExpiresIn);

internal sealed class TokenService(
    JwtSettings jwt, TimeProvider clock)
{
    readonly JsonWebTokenHandler _handler = new();

    #region access-token
    public string CreateAccessToken(User user)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = jwt.Issuer,
            Audience = jwt.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = now.Add(jwt.AccessTokenLifetime),
            Subject = new ClaimsIdentity(
            [
                new Claim("sub", user.Id.ToString()),
                new Claim("email", user.Email),
                new Claim("role", user.Role),
            ]),
            SigningCredentials = new SigningCredentials(
                jwt.Key(), SecurityAlgorithms.HmacSha256),
        };
        return _handler.CreateToken(descriptor);
    }
    #endregion

    // Only for the lab and the tests: a token with any times.
    internal string CreateWithTimes(User user, DateTime notBefore,
        DateTime expires, string? audience = null)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = jwt.Issuer,
            Audience = audience ?? jwt.Audience,
            IssuedAt = notBefore,
            NotBefore = notBefore,
            Expires = expires,
            Subject = new ClaimsIdentity(
            [
                new Claim("sub", user.Id.ToString()),
                new Claim("email", user.Email),
                new Claim("role", user.Role),
            ]),
            SigningCredentials = new SigningCredentials(
                jwt.Key(), SecurityAlgorithms.HmacSha256),
        };
        return _handler.CreateToken(descriptor);
    }
}

internal sealed record RefreshEntry(
    Guid UserId, Guid FamilyId, DateTimeOffset ExpiresAt)
{
    public bool Used { get; set; }
    public bool Revoked { get; set; }
}

// Stores only the SHA-256 of each refresh token. A copy of
// this store does not let anyone log in.
internal sealed class RefreshTokenStore(
    JwtSettings jwt, TimeProvider clock)
{
    readonly ConcurrentDictionary<string, RefreshEntry> _byHash =
        new();

    public IReadOnlyDictionary<string, RefreshEntry> Entries =>
        _byHash;

    public static string Hash(string token) =>
        Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    #region issue
    public string Issue(Guid userId, Guid? familyId = null)
    {
        var token = Convert.ToBase64String(
            RandomNumberGenerator.GetBytes(32));
        _byHash[Hash(token)] = new RefreshEntry(
            userId, familyId ?? Guid.NewGuid(),
            clock.GetUtcNow().Add(jwt.RefreshTokenLifetime));
        return token;
    }
    #endregion

    #region rotate
    public (Guid UserId, string NewToken)? Rotate(string token)
    {
        if (!_byHash.TryGetValue(Hash(token), out var entry))
            return null;

        lock (entry)
        {
            if (entry.Used || entry.Revoked)
            {
                // an old token came back: someone has a copy.
                // Kill the whole family, including the newest.
                RevokeFamily(entry.FamilyId);
                return null;
            }
            if (entry.ExpiresAt <= clock.GetUtcNow())
                return null;
            entry.Used = true;
        }
        return (entry.UserId, Issue(entry.UserId, entry.FamilyId));
    }
    #endregion

    void RevokeFamily(Guid familyId)
    {
        foreach (var e in _byHash.Values)
            if (e.FamilyId == familyId) e.Revoked = true;
    }
}
