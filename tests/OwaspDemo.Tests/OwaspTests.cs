using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using OwaspDemo.Api;

namespace OwaspDemo.Tests;

/// <summary>
/// Each test proves the same thing a learner proves by hand with curl:
/// the /vuln endpoint is exploitable, the /secure endpoint blocks the attack.
/// </summary>
public class OwaspTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public OwaspTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    private static async Task<JsonElement> Json(HttpResponseMessage response)
        => JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    // A01 — Broken Access Control
    [Fact]
    public async Task A01_VulnerableEndpointLeaksAnotherUsersNote()
    {
        // Alice asks for Bob's note (id 2). No auth at all — and it works.
        var response = await _client.GetAsync("/vuln/notes/2");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await Json(response);
        Assert.Equal("bob", body.GetProperty("owner").GetString());
    }

    [Fact]
    public async Task A01_SecureEndpointEnforcesOwnership()
    {
        var noAuth = await _client.GetAsync("/secure/notes/2");
        Assert.Equal(HttpStatusCode.Unauthorized, noAuth.StatusCode);

        var wrongOwner = new HttpRequestMessage(HttpMethod.Get, "/secure/notes/2");
        wrongOwner.Headers.Add("X-User", "alice");
        var forbidden = await _client.SendAsync(wrongOwner);
        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);

        var owner = new HttpRequestMessage(HttpMethod.Get, "/secure/notes/2");
        owner.Headers.Add("X-User", "bob");
        var ok = await _client.SendAsync(owner);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    // A02 — Cryptographic Failures
    [Fact]
    public async Task A02_VulnerableHashIsPlainMd5()
    {
        var response = await _client.GetAsync("/vuln/hash?password=password");
        var body = await Json(response);
        // MD5("password") — the most rainbow-tabled hash on earth.
        Assert.Equal("5f4dcc3b5aa765d61d8327deb882cf99", body.GetProperty("hash").GetString());
    }

    [Fact]
    public async Task A02_SecureHashIsSaltedAndNonDeterministic()
    {
        var first = await Json(await _client.GetAsync("/secure/hash?password=password"));
        var second = await Json(await _client.GetAsync("/secure/hash?password=password"));
        var h1 = first.GetProperty("hash").GetString()!;
        var h2 = second.GetProperty("hash").GetString()!;
        Assert.NotEqual(h1, h2);                       // random salt each time
        Assert.NotEqual("5f4dcc3b5aa765d61d8327deb882cf99", h1);
        Assert.True(Crypto.VerifyPassword("password", h1));
        Assert.False(Crypto.VerifyPassword("wrong", h1));
    }

    // A03 — Injection
    [Fact]
    public async Task A03_VulnerableEndpointFallsToSqlInjection()
    {
        var response = await _client.GetAsync("/vuln/users?q=%27%20OR%20%271%27%3D%271");
        var body = await Json(response);
        Assert.Equal(4, body.GetProperty("count").GetInt32()); // all customers leaked
    }

    [Fact]
    public async Task A03_SecureEndpointTreatsInjectionAsData()
    {
        var response = await _client.GetAsync("/secure/users?q=%27%20OR%20%271%27%3D%271");
        var body = await Json(response);
        Assert.Equal(0, body.GetProperty("count").GetInt32());

        var normal = await Json(await _client.GetAsync("/secure/users?q=ali"));
        Assert.Equal(1, normal.GetProperty("count").GetInt32());
    }

    // A04 — Insecure Design
    [Fact]
    public async Task A04_VulnerableResetTokenIsPredictable()
    {
        var first = await Json(await _client.PostAsJsonAsync("/vuln/reset", new { user = "alice" }));
        var second = await Json(await _client.PostAsJsonAsync("/vuln/reset", new { user = "alice" }));
        Assert.Equal(
            first.GetProperty("resetToken").GetString(),
            second.GetProperty("resetToken").GetString());
    }

    [Fact]
    public async Task A04_SecureResetTokenIsRandom()
    {
        var first = await Json(await _client.PostAsJsonAsync("/secure/reset", new { user = "alice" }));
        var second = await Json(await _client.PostAsJsonAsync("/secure/reset", new { user = "alice" }));
        Assert.NotEqual(
            first.GetProperty("resetToken").GetString(),
            second.GetProperty("resetToken").GetString());
    }

    // A05 — Security Misconfiguration
    [Fact]
    public async Task A05_VulnerableErrorLeaksInternals()
    {
        var response = await _client.GetAsync("/vuln/error");
        var text = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains("prod-db-01", text); // connection details in the response
    }

    [Fact]
    public async Task A05_SecureErrorIsGeneric()
    {
        var response = await _client.GetAsync("/secure/error");
        var text = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.DoesNotContain("prod-db-01", text);
        Assert.Contains("Something went wrong", text);
    }

    [Fact]
    public async Task A05_SecurityHeadersArePresent()
    {
        var response = await _client.GetAsync("/health");
        Assert.True(response.Headers.Contains("X-Content-Type-Options"));
        Assert.True(response.Headers.Contains("X-Frame-Options"));
    }

    // A07 — Identification & Authentication Failures
    [Fact]
    public async Task A07_VulnerableLoginNeverLocksOut()
    {
        for (var i = 0; i < 6; i++)
        {
            var response = await _client.PostAsJsonAsync("/vuln/login", new { user = "alice", password = "wrong" });
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode); // never 429
        }
        var ok = await _client.PostAsJsonAsync("/vuln/login", new { user = "alice", password = "hunter2" });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
    }

    [Fact]
    public async Task A07_SecureLoginLocksOutAfterFiveFailures()
    {
        // "carol" is a fresh user for this test so earlier tests can't pollute it.
        for (var i = 0; i < 4; i++)
        {
            var response = await _client.PostAsJsonAsync("/secure/login", new { user = "carol", password = "wrong" });
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
        var fifth = await _client.PostAsJsonAsync("/secure/login", new { user = "carol", password = "wrong" });
        Assert.Equal(HttpStatusCode.TooManyRequests, fifth.StatusCode);

        var correct = await _client.PostAsJsonAsync(
            "/secure/login", new { user = "alice", password = "correct-horse-battery-staple" });
        Assert.Equal(HttpStatusCode.OK, correct.StatusCode);
    }

    // A08 — Software & Data Integrity Failures
    [Fact]
    public async Task A08_VulnerableWebhookAcceptsUnsignedPayload()
    {
        var content = new StringContent("{\"event\":\"payment.received\"}", Encoding.UTF8, "application/json");
        var response = await _client.PostAsync("/vuln/webhook", content);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task A08_SecureWebhookRequiresValidHmac()
    {
        const string payload = "{\"event\":\"payment.received\"}";
        var unsigned = new StringContent(payload, Encoding.UTF8, "application/json");
        var noSig = await _client.PostAsync("/secure/webhook", unsigned);
        Assert.Equal(HttpStatusCode.Unauthorized, noSig.StatusCode);

        var forged = new HttpRequestMessage(HttpMethod.Post, "/secure/webhook")
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        };
        forged.Headers.Add("X-Signature", "deadbeef");
        Assert.Equal(HttpStatusCode.Unauthorized, (await _client.SendAsync(forged)).StatusCode);

        var signed = new HttpRequestMessage(HttpMethod.Post, "/secure/webhook")
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        };
        signed.Headers.Add("X-Signature", Crypto.SignHmac(payload, "demo-secret"));
        Assert.Equal(HttpStatusCode.OK, (await _client.SendAsync(signed)).StatusCode);
    }

    // A09 — Security Logging & Monitoring Failures
    [Fact]
    public async Task A09_VulnerableLoginLogsThePasswordInClearText()
    {
        await _client.PostAsJsonAsync("/vuln/login", new { user = "alice", password = "hunter2" });
        var logs = await Json(await _client.GetAsync("/vuln/logs"));
        var text = logs.GetRawText();
        Assert.Contains("hunter2", text);
    }

    [Fact]
    public async Task A09_SecureLoginNeverLogsThePassword()
    {
        await _client.PostAsJsonAsync("/secure/login", new { user = "alice", password = "correct-horse-battery-staple" });
        var logs = await Json(await _client.GetAsync("/secure/logs"));
        var text = logs.GetRawText();
        Assert.DoesNotContain("correct-horse-battery-staple", text);
        Assert.Contains("password=***", text);
    }

    // A10 — Server-Side Request Forgery
    [Fact]
    public async Task A10_SecureFetchRejectsNonAllowlistedUrls()
    {
        var metadata = await _client.GetAsync("/secure/fetch?url=http://169.254.169.254/latest/meta-data/");
        Assert.Equal(HttpStatusCode.BadRequest, metadata.StatusCode);

        var other = await _client.GetAsync("/secure/fetch?url=https://evil.example.com/steal");
        Assert.Equal(HttpStatusCode.BadRequest, other.StatusCode);
    }

    [Fact]
    public async Task A10_VulnerableFetchAttemptsAnyUrl()
    {
        // The vulnerable endpoint does not reject the metadata URL — it tries
        // to fetch it (502 here because the sandbox has no such host).
        var response = await _client.GetAsync("/vuln/fetch?url=http://169.254.169.254/latest/meta-data/");
        Assert.NotEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task HealthIsOk()
    {
        var response = await _client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }
}
