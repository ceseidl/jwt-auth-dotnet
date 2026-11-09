using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using AuthApi;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Tests;

public sealed class Api : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder b) =>
        b.UseSetting("Jwt:SigningKey",
            "test-key-only-for-xunit-0123456789-abcdef");

    internal UserStore Users =>
        Services.GetRequiredService<UserStore>();
    internal TokenService Tokens =>
        Services.GetRequiredService<TokenService>();

    public async Task<TokenPair> Login(HttpClient http,
        string email, string password)
    {
        var r = await http.PostAsJsonAsync("/auth/login",
            new { email, password });
        r.EnsureSuccessStatusCode();
        return (await r.Content.ReadFromJsonAsync<TokenPair>())!;
    }
}

public class AuthTests : IClassFixture<Api>
{
    readonly Api _api;
    readonly HttpClient _http;

    public AuthTests(Api api)
    {
        _api = api;
        _http = api.CreateClient();
    }

    async Task<HttpStatusCode> Get(string path, string? token)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null)
            req.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
        return (await _http.SendAsync(req)).StatusCode;
    }

    async Task<string> NewUser(string role = "user")
    {
        var email = $"{Guid.NewGuid():N}@shop.test";
        _api.Users.Register(email, "Pass#2026word", role);
        return (await _api.Login(_http, email, "Pass#2026word"))
            .AccessToken;
    }

    #region test-401-403
    [Fact]
    public async Task No_token_is_401_and_wrong_role_is_403()
    {
        var user = await NewUser();
        var admin = await NewUser("admin");

        Assert.Equal(HttpStatusCode.Unauthorized,
            await Get("/admin/report", null));
        Assert.Equal(HttpStatusCode.Forbidden,
            await Get("/admin/report", user));
        Assert.Equal(HttpStatusCode.OK,
            await Get("/admin/report", admin));
    }
    #endregion

    #region test-tampered
    [Fact]
    public async Task Edited_payload_is_rejected()
    {
        var p = (await NewUser()).Split('.');
        var json = Encoding.UTF8.GetString(
            Base64UrlEncoder.DecodeBytes(p[1]));
        var forged = string.Join('.', p[0], Base64UrlEncoder
            .Encode(json.Replace("\"user\"", "\"admin\"")), p[2]);

        Assert.Equal(HttpStatusCode.Unauthorized,
            await Get("/admin/report", forged));
    }
    #endregion

    [Fact]
    public async Task Token_expired_a_minute_ago_is_401()
    {
        var u = _api.Users.Register($"{Guid.NewGuid():N}@shop.test",
            "Pass#2026word", "user")!;
        var expired = _api.Tokens.CreateWithTimes(u,
            DateTime.UtcNow.AddMinutes(-6),
            DateTime.UtcNow.AddSeconds(-60));

        Assert.Equal(HttpStatusCode.Unauthorized,
            await Get("/me", expired));
    }

    #region test-refresh
    [Fact]
    public async Task Reused_refresh_token_revokes_the_family()
    {
        var email = $"{Guid.NewGuid():N}@shop.test";
        _api.Users.Register(email, "Pass#2026word", "user");
        var r1 = (await _api.Login(_http, email, "Pass#2026word"))
            .RefreshToken;

        var first = await Refresh(r1);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var r2 = (await first.Content
            .ReadFromJsonAsync<TokenPair>())!.RefreshToken;

        Assert.Equal(HttpStatusCode.Unauthorized,
            (await Refresh(r1)).StatusCode); // reuse
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await Refresh(r2)).StatusCode); // family is dead
    }
    #endregion

    Task<HttpResponseMessage> Refresh(string token) =>
        _http.PostAsJsonAsync("/auth/refresh",
            new { refreshToken = token });

    [Fact]
    public async Task Register_ignores_the_role_sent_by_the_client()
    {
        var email = $"{Guid.NewGuid():N}@shop.test";
        await _http.PostAsJsonAsync("/auth/register", new
        {
            email, password = "Pass#2026word", role = "admin",
        });
        var token = (await _api.Login(_http, email, "Pass#2026word"))
            .AccessToken;

        Assert.Equal(HttpStatusCode.Forbidden,
            await Get("/admin/report", token));
    }

    [Fact]
    public async Task Unknown_email_and_wrong_password_look_the_same()
    {
        var email = $"{Guid.NewGuid():N}@shop.test";
        _api.Users.Register(email, "Pass#2026word", "user");

        var wrong = await _http.PostAsJsonAsync("/auth/login",
            new { email, password = "nope-nope" });
        var unknown = await _http.PostAsJsonAsync("/auth/login",
            new { email = "ghost@shop.test", password = "nope-nope" });

        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(await Body(wrong), await Body(unknown));
    }

    // the ProblemDetails body without traceId, which always changes
    static async Task<string> Body(HttpResponseMessage r)
    {
        var node = System.Text.Json.Nodes.JsonNode.Parse(
            await r.Content.ReadAsStringAsync())!.AsObject();
        node.Remove("traceId");
        return node.ToJsonString();
    }

    [Fact]
    public async Task Payload_has_no_password_or_hash()
    {
        var p = (await NewUser()).Split('.');
        var json = Encoding.UTF8.GetString(
            Base64UrlEncoder.DecodeBytes(p[1]));

        Assert.DoesNotContain("Pass#2026word", json);
        Assert.DoesNotContain("AQAAAA", json); // hash prefix
        Assert.Contains("\"role\":\"user\"", json);
    }

    [Fact]
    public async Task Weak_password_is_400()
    {
        var r = await _http.PostAsJsonAsync("/auth/register",
            new { email = "a@shop.test", password = "123" });
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
    }
}
