using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AuthApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

// Starts the real API on localhost and calls it over HTTP.
// Usage: AuthLab [1..7]   (no argument = all parts)
CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;
const string Key = "local-demo-key-only-not-for-production-0123456789";
var parts = args.Length > 0 ? args
    : ["1", "2", "3", "4", "5", "6", "7"];
var port = 5301;

foreach (var p in parts)
{
    Console.WriteLine($"=== part {p} ===");
    switch (p)
    {
        case "1": await Flow(); break;
        case "2": await Unauthorized(); break;
        case "3": await Forbidden(); break;
        case "4": await Refresh(); break;
        case "5": await RoleFromClient(); break;
        case "6": Hashing(); break;
        case "7": await LoginTiming(); break;
    }
    Console.WriteLine();
}

async Task<Api> Start(AuthAppOptions? o = null)
{
    var url = $"http://localhost:{port++}";
    var app = AuthApp.Create(
    [
        "--urls", url,
        "--Jwt:SigningKey", Key,
        "--Logging:LogLevel:Default", "Warning",
    ], o);
    await app.StartAsync();
    return new Api(app, new HttpClient { BaseAddress = new(url) });
}

async Task Flow()
{
    await using var api = await Start();
    var reg = await api.Http.PostAsJsonAsync("/auth/register",
        new { email = "ana@shop.test", password = "Ana#2026pass" });
    Console.WriteLine($"register: {(int)reg.StatusCode} " +
        await reg.Content.ReadAsStringAsync());

    var pair = await api.Login("ana@shop.test", "Ana#2026pass");
    var t = pair.AccessToken.Split('.');
    Console.WriteLine($"login: access token {pair.AccessToken.Length}"
        + $" chars, expiresIn {pair.ExpiresIn} s");
    Console.WriteLine($"parts: header {t[0].Length}, payload " +
        $"{t[1].Length}, signature {t[2].Length} chars");
    Console.WriteLine("header : " + Decode(t[0]));
    Console.WriteLine("payload: " + Decode(t[1]));

    Console.WriteLine("GET /me without token: " +
        (int)(await api.Get("/me", null)).StatusCode);
    var me = await api.Get("/me", pair.AccessToken);
    Console.WriteLine($"GET /me with token: {(int)me.StatusCode} " +
        await me.Content.ReadAsStringAsync());
}

async Task Unauthorized()
{
    await using var api = await Start();
    var user = api.Users.Register("bia@shop.test", "Bia#2026pass",
        "user")!;
    var token = (await api.Login("bia@shop.test", "Bia#2026pass"))
        .AccessToken;

    await Show(api, "no Authorization header", null);
    await Show(api, "garbage token", "abc.def.ghi");

    var t = token.Split('.');
    var payload = Decode(t[1]).Replace("\"user\"", "\"admin\"");
    var forged = $"{t[0]}.{Base64UrlEncoder.Encode(payload)}.{t[2]}";
    await Show(api, "payload edited to admin", forged);

    var otherAud = api.Tokens.CreateWithTimes(user,
        DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5), "other-api");
    await Show(api, "token for another audience", otherAud);
    var aud = JsonDocument.Parse(Decode(otherAud.Split('.')[1]))
        .RootElement.GetProperty("aud").GetString();
    Console.WriteLine($"  (aud inside the token: {aud})");

    var expired = api.Tokens.CreateWithTimes(user,
        DateTime.UtcNow.AddMinutes(-6), DateTime.UtcNow.AddSeconds(-60));
    await Show(api, "expired 60 s ago (skew 30 s)", expired);

    await using var loose = await Start(new AuthAppOptions
    {
        TweakJwt = o => o.TokenValidationParameters.ClockSkew =
            TokenValidationParameters.DefaultClockSkew,
    });
    await Show(loose, "same token, default skew (5 min)", expired);
}

async Task Forbidden()
{
    await using var api = await Start();
    api.Users.Register("caio@shop.test", "Caio#2026pass", "user");
    api.Users.Register("root@shop.test", "Root#2026pass", "admin");
    var user = (await api.Login("caio@shop.test", "Caio#2026pass"))
        .AccessToken;
    var admin = (await api.Login("root@shop.test", "Root#2026pass"))
        .AccessToken;

    Console.WriteLine("GET /admin/report as user : " +
        (int)(await api.Get("/admin/report", user)).StatusCode);
    Console.WriteLine("GET /admin/report as admin: " +
        (int)(await api.Get("/admin/report", admin)).StatusCode);
    Console.WriteLine("GET /admin/report no token: " +
        (int)(await api.Get("/admin/report", null)).StatusCode);

    // MapInboundClaims = false and RoleClaimType left at its
    // default (ClaimTypes.Role): the "role" claim is never read.
    await using var noRole = await Start(new AuthAppOptions
    {
        TweakJwt = o => o.TokenValidationParameters.RoleClaimType =
            ClaimTypes.Role,
    });
    noRole.Users.Register("root@shop.test", "Root#2026pass", "admin");
    var admin2 = (await noRole.Login("root@shop.test",
        "Root#2026pass")).AccessToken;
    Console.WriteLine("RoleClaimType = ClaimTypes.Role, admin: " +
        (int)(await noRole.Get("/admin/report", admin2)).StatusCode);
    var me = await noRole.Get("/me", admin2);
    Console.WriteLine("  /me: " + await me.Content.ReadAsStringAsync());
}

async Task Refresh()
{
    await using var api = await Start();
    api.Users.Register("duda@shop.test", "Duda#2026pass", "user");
    var first = await api.Login("duda@shop.test", "Duda#2026pass");

    var r2 = await api.Http.PostAsJsonAsync("/auth/refresh",
        new { refreshToken = first.RefreshToken });
    var second = (await r2.Content.ReadFromJsonAsync<TokenPair>())!;
    Console.WriteLine($"refresh with R1: {(int)r2.StatusCode}, " +
        $"R2 != R1: {second.RefreshToken != first.RefreshToken}");

    var again = await api.Http.PostAsJsonAsync("/auth/refresh",
        new { refreshToken = first.RefreshToken });
    Console.WriteLine($"refresh with R1 again: {(int)again.StatusCode}");

    var r3 = await api.Http.PostAsJsonAsync("/auth/refresh",
        new { refreshToken = second.RefreshToken });
    Console.WriteLine($"refresh with R2 after the reuse: " +
        $"{(int)r3.StatusCode}");

    var me = await api.Get("/me", second.AccessToken);
    Console.WriteLine($"GET /me with the access token from R2: " +
        $"{(int)me.StatusCode}");

    Console.WriteLine("store (only hashes):");
    foreach (var (name, t) in new[] {
        ("R1", first.RefreshToken), ("R2", second.RefreshToken) })
    {
        var hash = RefreshTokenStore.Hash(t);
        var e = api.Refresh.Entries[hash];
        Console.WriteLine($"  {name}: {hash[..16]}...  " +
            $"used={e.Used} revoked={e.Revoked}");
    }
    Console.WriteLine($"R1 itself in the store: " +
        api.Refresh.Entries.ContainsKey(first.RefreshToken));
}

async Task RoleFromClient()
{
    foreach (var trust in new[] { true, false })
    {
        await using var api = await Start(
            new AuthAppOptions { TrustRoleFromClient = trust });
        var reg = await api.Http.PostAsJsonAsync("/auth/register",
            new
            {
                email = "eve@shop.test",
                password = "Eve#2026pass",
                role = "admin",
            });
        var token = (await api.Login("eve@shop.test", "Eve#2026pass"))
            .AccessToken;
        Console.WriteLine($"TrustRoleFromClient={trust}: register " +
            await reg.Content.ReadAsStringAsync());
        Console.WriteLine("  GET /admin/report: " +
            (int)(await api.Get("/admin/report", token)).StatusCode);
    }
}

void Hashing()
{
    var hasher = new PasswordHasher<User>();
    var u = new User(Guid.NewGuid(), "x@shop.test", "", "user");
    var h1 = hasher.HashPassword(u, "Same#2026pass");
    var h2 = hasher.HashPassword(u, "Same#2026pass");
    var b = Convert.FromBase64String(h1);
    var prf = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(1));
    var iter = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(5));
    var salt = BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(9));
    Console.WriteLine($"hash: {h1.Length} chars, format 0x{b[0]:X2}");
    Console.WriteLine($"  prf {prf} (2 = HMAC-SHA512), " +
        $"{iter:N0} iterations, salt {salt} bytes");
    Console.WriteLine($"same password twice: {h1[..20]}...");
    Console.WriteLine($"                     {h2[..20]}...");

    hasher.HashPassword(u, "warm-up");
    var sw = Stopwatch.StartNew();
    const int n = 20;
    for (var i = 0; i < n; i++) hasher.HashPassword(u, "p" + i);
    Console.WriteLine($"time per hash: " +
        $"{sw.Elapsed.TotalMilliseconds / n:0.0} ms (avg of {n})");
}

async Task LoginTiming()
{
    foreach (var skip in new[] { true, false })
    {
        await using var api = await Start(
            new AuthAppOptions { SkipDummyHash = skip });
        api.Users.Register("fabi@shop.test", "Fabi#2026pass", "user");

        async Task<double> Time(string email)
        {
            var sw = Stopwatch.StartNew();
            await api.Http.PostAsJsonAsync("/auth/login",
                new { email, password = "wrong-password" });
            return sw.Elapsed.TotalMilliseconds;
        }

        for (var i = 0; i < 5; i++) // warm-up
        {
            await Time("fabi@shop.test");
            await Time("ghost@shop.test");
        }
        var known = new List<double>();
        var unknown = new List<double>();
        for (var i = 0; i < 30; i++) // alternated
        {
            known.Add(await Time("fabi@shop.test"));
            unknown.Add(await Time("ghost@shop.test"));
        }
        Console.WriteLine(skip
            ? "without the dummy hash (the bug):"
            : "with the dummy hash:");
        Console.WriteLine($"  existing email, wrong password: " +
            $"median {Median(known):0.0} ms");
        Console.WriteLine($"  email that does not exist     : " +
            $"median {Median(unknown):0.0} ms");
    }
}

static double Median(List<double> xs)
{
    var s = xs.Order().ToArray();
    return (s[s.Length / 2] + s[(s.Length - 1) / 2]) / 2;
}

async Task Show(Api api, string label, string? token)
{
    var r = await api.Get("/me", token);
    var why = r.Headers.WwwAuthenticate.FirstOrDefault()?.ToString();
    Console.WriteLine($"{label}: {(int)r.StatusCode}");
    if (why is null) return;
    // WWW-Authenticate: Bearer error="...", error_description="..."
    foreach (var piece in Shorten(why).Split(", "))
        Console.WriteLine($"  {piece}");
}

static string Shorten(string s) =>
    // the date changes on every run
    System.Text.RegularExpressions.Regex.Replace(
        s, @"expired at '[^']*'", "expired at '<date>'");

static string Decode(string part) =>
    Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(part));

sealed record Api(WebApplication App, HttpClient Http)
    : IAsyncDisposable
{
    public UserStore Users =>
        App.Services.GetRequiredService<UserStore>();
    public TokenService Tokens =>
        App.Services.GetRequiredService<TokenService>();
    public RefreshTokenStore Refresh =>
        App.Services.GetRequiredService<RefreshTokenStore>();

    public async Task<TokenPair> Login(string email, string pass)
    {
        var r = await Http.PostAsJsonAsync("/auth/login",
            new { email, password = pass });
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<TokenPair>())!;
    }

    public Task<HttpResponseMessage> Get(string path, string? token)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null)
            req.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
        return Http.SendAsync(req);
    }

    public async ValueTask DisposeAsync()
    {
        Http.Dispose();
        await App.StopAsync();
        await App.DisposeAsync();
    }
}
