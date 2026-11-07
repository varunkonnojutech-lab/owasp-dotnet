# OWASP Top 10 in .NET — break it, then fix it

[![Build](https://github.com/varunkonnojutech-lab/owasp-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/varunkonnojutech-lab/owasp-dotnet/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4)](https://dotnet.microsoft.com/)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/varunkonnojutech-lab/owasp-dotnet)

Every OWASP Top 10 (2021) vulnerability, demonstrated live in a .NET 8 API — and fixed, in the same repo, endpoint by endpoint. Each flaw has a `/vuln/*` endpoint you can exploit with curl and a `/secure/*` endpoint that blocks the same attack. The tests prove both sides: the vulnerable endpoint really leaks, and the secure one really doesn't.

> ⚠️ **This API is deliberately vulnerable.** Run it only on your own machine. Never deploy the `/vuln/*` endpoints anywhere real — they exist so you can learn what the attacks look like before they happen to you.

## Who is this for

.NET developers who ship APIs and want to recognise the OWASP Top 10 in their own code — not as a checklist to memorise, but as requests you can send and responses you can read. If you have ever wondered what SQL injection or broken access control *actually looks like* over HTTP, this is the lab.

## What you'll learn

- **A01 Broken Access Control** — reading another user's private note with no auth, then enforcing ownership
- **A02 Cryptographic Failures** — why MD5 password hashes are worthless, and PBKDF2 with a random salt
- **A03 Injection** — `' OR '1'='1` dumping a whole table, then parameterized queries
- **A04 Insecure Design** — password-reset tokens you can guess from a username, then crypto-random tokens
- **A05 Security Misconfiguration** — stack traces and connection strings in error responses, then generic errors + security headers
- **A06 Vulnerable Components** — finding known-vulnerable packages with `dotnet list package --vulnerable`
- **A07 Auth Failures** — plaintext passwords with unlimited guessing, then PBKDF2 + 5-strike lockout
- **A08 Integrity Failures** — forging an unsigned webhook, then HMAC-SHA256 verification
- **A09 Logging Failures** — passwords sitting in clear text in the logs, then redacted logging
- **A10 SSRF** — making the server fetch the cloud metadata endpoint, then a strict URL allowlist

## Quick start

You need .NET 8. No Docker, no database server, no external services — the demo data lives in memory (SQLite in-memory for the injection lab).

```bash
dotnet test   # 19 tests: every attack succeeds on /vuln, fails on /secure
dotnet run --project src/OwaspDemo.Api   # http://localhost:5050
```

Then attack it:

```bash
# A01 — read Bob's private note with no authentication at all
curl -s http://localhost:5050/vuln/notes/2

# A01 fixed — Alice gets 403, Bob gets his note
curl -s -H "X-User: alice" http://localhost:5050/secure/notes/2
curl -s -H "X-User: bob"   http://localhost:5050/secure/notes/2

# A03 — SQL injection dumps all four customers
curl -s "http://localhost:5050/vuln/users?q=%27%20OR%20%271%27%3D%271"

# A03 fixed — the same input returns zero rows
curl -s "http://localhost:5050/secure/users?q=%27%20OR%20%271%27%3D%271"

# A07 + A09 — log in with a wrong password, then read the logs
curl -s -X POST http://localhost:5050/vuln/login \
  -H "Content-Type: application/json" -d '{"user":"alice","password":"hunter2"}'
curl -s http://localhost:5050/vuln/logs   # the password is right there

# A08 — forge a webhook, then sign one properly
curl -s -X POST http://localhost:5050/vuln/webhook \
  -H "Content-Type: application/json" -d '{"event":"payment.received"}'
bash scripts/sign-webhook.sh '{"event":"payment.received"}'
```

The full guided attack walkthrough — every endpoint, what to send, what to look for — is in **[docs/owasp-top10.md](docs/owasp-top10.md)**.

## The labs

| # | OWASP | The flaw | The attack | The fix |
|---|---|---|---|---|
| A01 | Broken Access Control | No ownership check on notes | `GET /vuln/notes/2` reads Bob's note | Caller must own the resource (403 otherwise) |
| A02 | Cryptographic Failures | MD5 password hash | `password` → `5f4dcc3b…` every time | PBKDF2-SHA256, random salt, 210k iterations |
| A03 | Injection | SQL string concatenation | `' OR '1'='1` returns all rows | Parameterized queries |
| A04 | Insecure Design | Reset token derived from username | Same token every time, guessable | 256-bit crypto-random token |
| A05 | Security Misconfiguration | Verbose errors, no headers | Error leaks `prod-db-01` connection info | Generic error + `X-Frame-Options`, CSP, `nosniff` |
| A06 | Vulnerable Components | Outdated packages | `dotnet list package --vulnerable` | Patch + Dependabot (see docs) |
| A07 | Auth Failures | Plaintext passwords, no lockout | Unlimited guessing | PBKDF2 + 5-strike lockout (429) |
| A08 | Integrity Failures | Unsigned webhooks | Forge `payment.received` | HMAC-SHA256 signature verification |
| A09 | Logging Failures | Passwords in clear-text logs | `GET /vuln/logs` shows passwords | Redact secrets: `password=***` |
| A10 | SSRF | Server fetches any URL | `?url=http://169.254.169.254/…` | Strict `https://api.example.com/` allowlist |

## How the tests work

The test suite is the point: each test attacks both versions of the same feature and asserts the opposite outcome.

```csharp
// The vulnerable endpoint really is exploitable…
var response = await _client.GetAsync("/vuln/users?q=%27%20OR%20%271%27%3D%271");
Assert.Equal(4, body.GetProperty("count").GetInt32()); // all customers leaked

// …and the secure endpoint really blocks it.
var safe = await _client.GetAsync("/secure/users?q=%27%20OR%20%271%27%3D%271");
Assert.Equal(0, body.GetProperty("count").GetInt32());
```

## Project layout

```
src/OwaspDemo.Api/
  Program.cs    # all /vuln/* and /secure/* endpoints, one section per OWASP item
  Data.cs       # seeded notes/users, in-memory SQLite, crypto + token helpers
tests/OwaspDemo.Tests/
  OwaspTests.cs # 19 tests — exploit on /vuln, blocked on /secure
docs/
  owasp-top10.md  # guided walkthrough: every flaw, attack, and fix
scripts/
  sign-webhook.sh # signs a webhook payload with the demo HMAC secret
```

## Next steps

- Read the [OWASP Top 10 2021](https://owasp.org/Top10/) itself — this repo is the hands-on companion, not a replacement.
- Run `dotnet list package --vulnerable` on one of your own projects and fix what it finds.
- Try the same attacks against your own APIs in a test environment — the secure endpoints here are the patterns to copy.
- If you want the auth story in full depth (refresh-token rotation, revocation, Entra ID), see the companion repo [jwt-auth-deepdive](https://github.com/varunkonnojutech-lab/jwt-auth-deepdive).
