using System.Text;
using Microsoft.Data.Sqlite;
using OwaspDemo.Api;

var builder = WebApplication.CreateBuilder(args);

// A05 — the SECURE pipeline gets real security headers. The /vuln endpoints
// deliberately skip them so learners can see the difference in the response.
builder.Services.AddSingleton<HttpClient>();

var app = builder.Build();

app.Use(async (ctx, next) =>
{
    // Security headers on every response (A05 fix). Browsers enforce these;
    // curl users can see them with -i.
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    await next();
});

app.MapGet("/", () => Results.Ok(new
{
    name = "OWASP Top 10 demo API",
    docs = "/docs — see docs/owasp-top10.md in the repo",
    vulnerable = "/vuln/* — every OWASP Top 10 2021 flaw, on purpose",
    secure = "/secure/* — the same feature, fixed",
}));

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

// ---------------------------------------------------------------------------
// A01 — Broken Access Control
// ---------------------------------------------------------------------------
app.MapGet("/vuln/notes/{id:int}", (int id) =>
{
    // VULNERABLE: no ownership check. Any caller can read anyone's note.
    // Try: curl localhost:5050/vuln/notes/2   (Bob's private note, no auth)
    var note = Store.Notes.FirstOrDefault(n => n.Id == id);
    return note is null ? Results.NotFound() : Results.Ok(note);
});

app.MapGet("/secure/notes/{id:int}", (int id, HttpRequest req) =>
{
    // SECURE: the caller identifies as X-User and must own the note.
    if (!req.Headers.TryGetValue("X-User", out var user) || string.IsNullOrWhiteSpace(user))
        return Results.Unauthorized();
    var note = Store.Notes.FirstOrDefault(n => n.Id == id);
    if (note is null) return Results.NotFound();
    if (!string.Equals(note.Owner, user, StringComparison.OrdinalIgnoreCase))
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    return Results.Ok(note);
});

// ---------------------------------------------------------------------------
// A02 — Cryptographic Failures
// ---------------------------------------------------------------------------
app.MapGet("/vuln/hash", (string password) =>
{
    // VULNERABLE: MD5 — fast, unsalted, cracked in seconds with rainbow tables.
    // "password" always hashes to 5f4dcc3b5aa765d61d8327deb882cf99.
    return Results.Ok(new { algorithm = "MD5 (broken)", hash = Crypto.HashMd5(password) });
});

app.MapGet("/secure/hash", (string password) =>
{
    // SECURE: PBKDF2, random salt, 210k iterations. Same input, different hash every time.
    return Results.Ok(new { algorithm = "PBKDF2-SHA256, 210k iterations", hash = Crypto.HashPassword(password) });
});

// ---------------------------------------------------------------------------
// A03 — Injection (SQL)
// ---------------------------------------------------------------------------
app.MapGet("/vuln/users", (string q) =>
{
    // VULNERABLE: user input concatenated straight into SQL.
    // Try: q=' OR '1'='1   → returns every customer.
    var sql = $"SELECT id, name, email FROM customers WHERE name LIKE '%{q}%'";
    var rows = Store.QueryCustomers(sql);
    return Results.Ok(new { sql, count = rows.Count, rows });
});

app.MapGet("/secure/users", (string q) =>
{
    // SECURE: parameterized query — the input is data, never code.
    var rows = Store.QueryCustomers(
        "SELECT id, name, email FROM customers WHERE name LIKE '%' || $q || '%'",
        new SqliteParameter("$q", q));
    return Results.Ok(new { count = rows.Count, rows });
});

// ---------------------------------------------------------------------------
// A04 — Insecure Design (predictable password-reset tokens)
// ---------------------------------------------------------------------------
app.MapPost("/vuln/reset", (ResetRequest req) =>
{
    // VULNERABLE: the token is derived from the username — guessable, and the
    // same every time for the same user. An attacker resets anyone's password.
    var token = ResetTokens.Predictable(req.User);
    return Results.Ok(new { user = req.User, resetToken = token, warning = "Predictable! Same token every time." });
});

app.MapPost("/secure/reset", (ResetRequest req) =>
{
    // SECURE: 256-bit random token, single-use, short expiry in a real system.
    return Results.Ok(new { user = req.User, resetToken = ResetTokens.Random() });
});

// ---------------------------------------------------------------------------
// A05 — Security Misconfiguration (verbose errors)
// ---------------------------------------------------------------------------
app.MapGet("/vuln/error", () =>
{
    // VULNERABLE: the full exception — type, message, stack trace, file paths —
    // is handed to the caller. Attackers use it to map your internals.
    try
    {
        throw new InvalidOperationException("Connection string 'Server=prod-db-01;...' failed: timeout after 30s.");
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.ToString(), statusCode: 500);
    }
});

app.MapGet("/secure/error", () =>
{
    // SECURE: the caller gets a generic message; the detail goes to the logs only.
    try
    {
        throw new InvalidOperationException("Connection string 'Server=prod-db-01;...' failed: timeout after 30s.");
    }
    catch (Exception ex)
    {
        Store.Log($"[secure/error] {ex.GetType().Name}: {ex.Message}");
        return Results.Problem("Something went wrong. Reference id logged.", statusCode: 500);
    }
});

// ---------------------------------------------------------------------------
// A07 — Identification & Authentication Failures
// ---------------------------------------------------------------------------
app.MapPost("/vuln/login", (LoginRequest req) =>
{
    // VULNERABLE: plaintext passwords, no lockout — unlimited guessing.
    // A09 too: the password is written to the log in clear text.
    Store.Log($"[vuln/login] user={req.User} password={req.Password}");
    var ok = Store.PlaintextPasswords.TryGetValue(req.User, out var stored) && stored == req.Password;
    return ok
        ? Results.Ok(new { message = $"Welcome, {req.User}!" })
        : Results.Unauthorized();
});

app.MapPost("/secure/login", (LoginRequest req) =>
{
    // SECURE: PBKDF2 verification, 5-strike lockout, redacted logging.
    lock (Store.LoginLock)
    {
        Store.LoginAttempts.TryGetValue(req.User, out var state);
        if (state.LockedUntil.HasValue && state.LockedUntil > DateTimeOffset.UtcNow)
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
    }

    Store.Log($"[secure/login] user={req.User} password=***");
    var ok = Store.HashedPasswords.TryGetValue(req.User, out var stored)
        && Crypto.VerifyPassword(req.Password, stored);

    lock (Store.LoginLock)
    {
        Store.LoginAttempts.TryGetValue(req.User, out var state);
        if (ok)
        {
            Store.LoginAttempts[req.User] = (0, null);
            return Results.Ok(new { message = $"Welcome, {req.User}!" });
        }
        var count = state.Count + 1;
        DateTimeOffset? lockedUntil = count >= 5 ? DateTimeOffset.UtcNow.AddMinutes(15) : null;
        Store.LoginAttempts[req.User] = (count, lockedUntil);
        return lockedUntil.HasValue
            ? Results.StatusCode(StatusCodes.Status429TooManyRequests)
            : Results.Unauthorized();
    }
});

// ---------------------------------------------------------------------------
// A08 — Software & Data Integrity Failures (unsigned webhooks)
// ---------------------------------------------------------------------------
app.MapPost("/vuln/webhook", async (HttpRequest req) =>
{
    // VULNERABLE: any payload is accepted. An attacker forges "payment received".
    using var reader = new StreamReader(req.Body, Encoding.UTF8);
    var body = await reader.ReadToEndAsync();
    return Results.Ok(new { accepted = true, body });
});

app.MapPost("/secure/webhook", async (HttpRequest req) =>
{
    // SECURE: HMAC-SHA256 signature required (shared secret "demo-secret").
    // Sign with: scripts/sign-webhook.sh '{"event":"payment.received"}'
    if (!req.Headers.TryGetValue("X-Signature", out var signature))
        return Results.Unauthorized();
    using var reader = new StreamReader(req.Body, Encoding.UTF8);
    var body = await reader.ReadToEndAsync();
    var valid = Crypto.VerifyHmac(body, signature!, "demo-secret");
    return valid
        ? Results.Ok(new { accepted = true, body })
        : Results.Unauthorized();
});

// ---------------------------------------------------------------------------
// A09 — Security Logging & Monitoring Failures
// ---------------------------------------------------------------------------
app.MapGet("/vuln/logs", () =>
{
    // VULNERABLE (by design): this is what the app logged. Log in via /vuln/login
    // first, then look — the password is right there in clear text.
    lock (Store.LogLock) { return Results.Ok(Store.LogEntries); }
});

app.MapGet("/secure/logs", () =>
{
    // Same log view — but the secure endpoints only ever wrote redacted entries.
    lock (Store.LogLock) { return Results.Ok(Store.LogEntries); }
});

// ---------------------------------------------------------------------------
// A10 — Server-Side Request Forgery (SSRF)
// ---------------------------------------------------------------------------
app.MapGet("/vuln/fetch", async (string url, HttpClient http) =>
{
    // VULNERABLE: fetches ANY url the caller supplies — including the cloud
    // metadata endpoint http://169.254.169.254/ that hands out credentials.
    try
    {
        var response = await http.GetAsync(url);
        var body = await response.Content.ReadAsStringAsync();
        return Results.Ok(new { status = (int)response.StatusCode, preview = body[..Math.Min(200, body.Length)] });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Upstream fetch failed: {ex.Message}", statusCode: 502);
    }
});

app.MapGet("/secure/fetch", async (string url, HttpClient http) =>
{
    // SECURE: strict allowlist — only our own API host, https only.
    if (!url.StartsWith("https://api.example.com/", StringComparison.OrdinalIgnoreCase))
        return Results.BadRequest(new { error = "URL not on the allowlist." });
    try
    {
        var response = await http.GetAsync(url);
        var body = await response.Content.ReadAsStringAsync();
        return Results.Ok(new { status = (int)response.StatusCode, preview = body[..Math.Min(200, body.Length)] });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Upstream fetch failed: {ex.Message}", statusCode: 502);
    }
});

app.Run();

public record ResetRequest(string User);
public record LoginRequest(string User, string Password);

// Exposed for WebApplicationFactory in the test project.
public partial class Program { }
