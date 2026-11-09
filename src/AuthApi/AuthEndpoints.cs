using System.Security.Claims;

namespace AuthApi;

public sealed record RegisterRequest(
    string Email, string Password, string? Role = null);
public sealed record LoginRequest(string Email, string Password);
public sealed record RefreshRequest(string RefreshToken);

internal static class AuthEndpoints
{
    public static void MapAuthEndpoints(this WebApplication app)
    {
        #region register
        app.MapPost("/auth/register", (RegisterRequest req,
            UserStore users, AuthAppOptions opts) =>
        {
            var errors = Validate(req);
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // the role is decided here, never by the client
            var role = "user";
            if (opts.TrustRoleFromClient && req.Role is not null)
                role = req.Role; // the bug, on purpose

            var user = users.Register(req.Email, req.Password, role);
            return user is null
                ? Results.Problem("Email already registered.",
                    statusCode: 409)
                : Results.Created($"/users/{user.Id}",
                    new { user.Id, user.Email, user.Role });
        });
        #endregion

        #region login
        app.MapPost("/auth/login", (LoginRequest req,
            UserStore users, TokenService tokens,
            RefreshTokenStore refresh, JwtSettings jwt) =>
        {
            var user = users.CheckPassword(req.Email, req.Password);
            // same answer for unknown email and wrong password
            if (user is null)
                return Results.Problem(
                    "Invalid email or password.", statusCode: 401);

            return Results.Ok(new TokenPair(
                tokens.CreateAccessToken(user),
                refresh.Issue(user.Id),
                (int)jwt.AccessTokenLifetime.TotalSeconds));
        });
        #endregion

        #region refresh
        app.MapPost("/auth/refresh", (RefreshRequest req,
            UserStore users, TokenService tokens,
            RefreshTokenStore refresh, JwtSettings jwt) =>
        {
            var rotated = refresh.Rotate(req.RefreshToken);
            var user = rotated is null
                ? null : users.Find(rotated.Value.UserId);
            if (user is null)
                return Results.Problem(
                    "Invalid refresh token.", statusCode: 401);

            return Results.Ok(new TokenPair(
                tokens.CreateAccessToken(user),
                rotated!.Value.NewToken,
                (int)jwt.AccessTokenLifetime.TotalSeconds));
        });
        #endregion

        #region protected
        app.MapGet("/me", (ClaimsPrincipal user) => new
        {
            Id = user.FindFirstValue("sub"),
            Email = user.Identity!.Name,
            Role = user.FindFirstValue("role"),
            IsAdmin = user.IsInRole("admin"),
        }).RequireAuthorization();

        app.MapGet("/admin/report", () => new { Orders = 42 })
            .RequireAuthorization(p => p.RequireRole("admin"));
        #endregion
    }

    static Dictionary<string, string[]> Validate(RegisterRequest r)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(r.Email) || !r.Email.Contains('@'))
            errors["email"] = ["Invalid email."];
        if (r.Password is null || r.Password.Length < 8)
            errors["password"] = ["Use at least 8 characters."];
        return errors;
    }
}
