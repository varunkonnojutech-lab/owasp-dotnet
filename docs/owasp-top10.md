# OWASP Top 10 (2021) — guided walkthrough

Run the API (`dotnet run --project src/OwaspDemo.Api`, http://localhost:5050) and work
through each item below. Every section has three parts: **the flaw**, **the attack** (copy-paste
curl), and **the fix** (what the `/secure/*` endpoint does differently).

> All demo data is in memory. Restarting the API resets everything — including the
> login lockout counters and the log sink.

## A01 — Broken Access Control

**The flaw.** `GET /vuln/notes/{id}` returns any note by id. It never asks who you are,
and never checks whether the note is yours. This is the single most common serious
web vulnerability — OWASP ranks it #1 because it is everywhere: missing ownership
checks on `/orders/{id}`, `/users/{id}/profile`, `/documents/{id}`.

**The attack.**

```bash
# Bob's private note, no authentication whatsoever
curl -s http://localhost:5050/vuln/notes/2
# {"id":2,"owner":"bob","title":"Salary review","body":"Bob's private salary-review notes."}
```

**The fix.** `/secure/notes/{id}` requires an `X-User` header (standing in for a real
authenticated identity) and returns 403 unless the caller owns the note. The rule:
**deny by default, check ownership on every object access** — not just at login, but
on every request. 401 when unauthenticated, 403 when authenticated but not the owner.

```bash
curl -s -H "X-User: alice" http://localhost:5050/secure/notes/2  # 403
curl -s -H "X-User: bob"   http://localhost:5050/secure/notes/2  # 200
```

## A02 — Cryptographic Failures

**The flaw.** `/vuln/hash` returns an MD5 hash. MD5 is fast (billions of guesses per
second on a GPU), unsalted (the same password always produces the same hash), and
rainbow-tabled — `5f4dcc3b5aa765d61d8327deb882cf99` is `password`, and every attacker
already knows it.

**The attack.**

```bash
curl -s "http://localhost:5050/vuln/hash?password=password"
# {"algorithm":"MD5 (broken)","hash":"5f4dcc3b5aa765d61d8327deb882cf99"}
```

**The fix.** `/secure/hash` uses PBKDF2-SHA256 with a random 16-byte salt and 210,000
iterations (`Rfc2898DeriveBytes.Pbkdf2`). The same password gives a different hash
every time, verification re-derives with the stored salt, and the iteration count
makes brute force expensive. In .NET, prefer `PasswordHasher<T>` (ASP.NET Core
Identity) or PBKDF2 / bcrypt / Argon2id — never MD5 or SHA-256 alone for passwords.

## A03 — Injection

**The flaw.** `/vuln/users` builds SQL by concatenating the query string into the
statement. The database cannot tell your code apart from the attacker's input.

**The attack.**

```bash
curl -s "http://localhost:5050/vuln/users?q=%27%20OR%20%271%27%3D%271"
# {"sql":"SELECT ... WHERE name LIKE '%' OR '1'='1%'","count":4,...}  — all customers
```

**The fix.** `/secure/users` uses a parameter (`$q`) — the input is sent to the
database as *data*, never as code. The same payload returns zero rows. This applies
to every query builder: EF Core LINQ and `FromSqlInterpolated` are safe;
`FromSqlRaw` with concatenation and raw `SqlCommand` text are not.

## A04 — Insecure Design

**The flaw.** `/vuln/reset` derives the password-reset token from the username
(`RESET-` + a small hash). It is the same token every time for the same user, and
anyone who knows the scheme can compute anyone else's token and reset their password.
This is a *design* flaw, not a coding bug — no amount of careful coding fixes a
token scheme that is predictable by construction.

**The attack.**

```bash
curl -s -X POST http://localhost:5050/vuln/reset \
  -H "Content-Type: application/json" -d '{"user":"alice"}'
# run it twice — the token never changes
```

**The fix.** `/secure/reset` returns 32 bytes from `RandomNumberGenerator` (256 bits
of entropy). In production, also store only a hash of the token, make it single-use,
and expire it in 15–60 minutes.

## A05 — Security Misconfiguration

**The flaw.** `/vuln/error` returns the full exception — type, message, and stack
trace — including internal hostnames and connection-string fragments. Attackers use
verbose errors to map your infrastructure. The app also ships without security
headers.

**The attack.**

```bash
curl -s http://localhost:5050/vuln/error
# ... "Connection string 'Server=prod-db-01;...' failed: timeout after 30s."
```

**The fix.** `/secure/error` returns a generic message and logs the detail
server-side only. The app also sends `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, a `Content-Security-Policy`, and `Referrer-Policy` on
every response. In production, also: never run with `ASPNETCORE_ENVIRONMENT=Development`
in public, disable detailed errors, and keep a hardened baseline configuration.

## A06 — Vulnerable and Outdated Components

**The flaw.** There is no endpoint for this one — it lives in your dependency list.
Every NuGet package you reference is code you ship but did not write, and known
vulnerabilities in old versions are public (CVE databases) and scanned by attackers
automatically.

**The check.**

```bash
dotnet list package --vulnerable
dotnet list package --outdated
```

**The fix.** Patch promptly, and automate it: enable Dependabot (`.github/dependabot.yml`)
or Renovate so vulnerable packages raise PRs by themselves. The demo API's own
packages are pinned to current 8.0.x patch versions — verify with the command above.

## A07 — Identification and Authentication Failures

**The flaw.** `/vuln/login` compares plaintext passwords (`alice` / `hunter2`) and
never locks anyone out — an attacker can guess forever. Weak, breached, or default
passwords plus no lockout is still how most account takeovers happen.

**The attack.**

```bash
# Guess as many times as you like — nothing ever stops you
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://localhost:5050/vuln/login \
    -H "Content-Type: application/json" -d '{"user":"alice","password":"wrong"}'
done
# 401 401 401 401 401 401
```

**The fix.** `/secure/login` stores only PBKDF2 hashes, verifies with
`VerifyPassword`, and locks the account for 15 minutes after 5 failed attempts
(HTTP 429). Correct credentials: `alice` / `correct-horse-battery-staple`.
In production, add MFA, and check passwords against breached-password lists.

## A08 — Software and Data Integrity Failures

**The flaw.** `/vuln/webhook` accepts any JSON payload. If a payment provider (or
anyone pretending to be one) POSTs `{"event":"payment.received"}`, the app believes
it. Unsigned webhooks are trivially forgeable.

**The attack.**

```bash
curl -s -X POST http://localhost:5050/vuln/webhook \
  -H "Content-Type: application/json" -d '{"event":"payment.received","amount":9999}'
# {"accepted":true,...}
```

**The fix.** `/secure/webhook` requires an `X-Signature` header: HMAC-SHA256 of the
raw body with the shared secret `demo-secret`, compared in constant time
(`CryptographicOperations.FixedTimeEquals`). Sign a payload with the helper script:

```bash
bash scripts/sign-webhook.sh '{"event":"payment.received"}'
```

This is exactly how Stripe, GitHub, and Slack sign their webhooks — verify the
signature before you trust the body.

## A09 — Security Logging and Monitoring Failures

**The flaw.** `/vuln/login` writes the password into the log in clear text. Logs get
shipped to aggregators, copied into tickets, and kept for months — a plaintext
password in a log is a password breach waiting to be pasted somewhere.

**The attack.**

```bash
curl -s -X POST http://localhost:5050/vuln/login \
  -H "Content-Type: application/json" -d '{"user":"alice","password":"hunter2"}'
curl -s http://localhost:5050/vuln/logs
# ... [vuln/login] user=alice password=hunter2
```

**The fix.** `/secure/login` logs `password=***`. The rule: never log credentials,
tokens, or full PII — log *that* an event happened, with enough context to
investigate, and alert on repeated failures (the lockout in A07 is only useful if
someone notices it firing).

## A10 — Server-Side Request Forgery (SSRF)

**The flaw.** `/vuln/fetch?url=` fetches whatever URL the caller supplies. In the
cloud, `http://169.254.169.254/latest/meta-data/` is the instance-metadata endpoint —
it hands out temporary cloud credentials to anything that can reach it, and your
server can.

**The attack.**

```bash
curl -s "http://localhost:5050/vuln/fetch?url=http://169.254.169.254/latest/meta-data/"
# the server tries to fetch it (502 here — the sandbox has no metadata service)
```

**The fix.** `/secure/fetch` enforces a strict allowlist: only
`https://api.example.com/` URLs, https only — everything else is rejected with 400
*before* any request is made. In production, also block private/reserved IP ranges
after DNS resolution, since allowlists alone can be bypassed by DNS rebinding.

---

## Cheat sheet

| # | Never | Always |
|---|---|---|
| A01 | Trust an id in the URL | Check ownership on every request |
| A02 | MD5 / SHA-1 / unsalted hashes for passwords | PBKDF2 / bcrypt / Argon2id, random salt |
| A03 | Concatenate input into SQL | Parameterized queries / ORM |
| A04 | Predictable tokens | Crypto-random, single-use, expiring |
| A05 | Verbose errors, default config | Generic errors, security headers |
| A06 | Pin and forget dependencies | Scan + Dependabot, patch promptly |
| A07 | Plaintext passwords, unlimited guesses | Hash + lockout + MFA |
| A08 | Trust unsigned payloads | HMAC signatures, constant-time compare |
| A09 | Log secrets | Redact, alert on anomalies |
| A10 | Fetch user-supplied URLs | Strict allowlist, block private IPs |
