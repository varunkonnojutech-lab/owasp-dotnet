using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace OwaspDemo.Api;

/// <summary>Seeded demo data. Everything lives in memory — no external services.</summary>
public static class Store
{
    public record Note(int Id, string Owner, string Title, string Body);
    public record Customer(int Id, string Name, string Email);

    public static readonly List<Note> Notes =
    [
        new(1, "alice", "Q3 budget", "Do not share: the Q3 budget draft."),
        new(2, "bob", "Salary review", "Bob's private salary-review notes."),
        new(3, "alice", "Deploy checklist", "Run migrations before the deploy."),
    ];

    // A07 — vulnerable login: passwords stored in PLAINTEXT (never do this).
    public static readonly Dictionary<string, string> PlaintextPasswords = new()
    {
        ["alice"] = "hunter2",
        ["bob"] = "password123",
    };

    // A07 — secure login: only PBKDF2 hashes are stored.
    public static readonly Dictionary<string, string> HashedPasswords = new()
    {
        ["alice"] = Crypto.HashPassword("correct-horse-battery-staple"),
        ["bob"] = Crypto.HashPassword("correct-horse-battery-staple"),
    };

    // A07 — failed-login counters for the secure endpoint (lockout after 5).
    public static readonly Dictionary<string, (int Count, DateTimeOffset? LockedUntil)> LoginAttempts = new();
    public static readonly object LoginLock = new();

    // A09 — in-memory log sink so learners can SEE what got logged.
    public static readonly List<string> LogEntries = [];
    public static readonly object LogLock = new();

    public static void Log(string entry)
    {
        lock (LogLock) { LogEntries.Add($"{DateTimeOffset.UtcNow:HH:mm:ss} {entry}"); }
    }

    // A03 — shared in-memory SQLite database (kept open for the app lifetime).
    private static readonly SqliteConnection Connection = new("Data Source=:memory:");
    private static bool _seeded;

    public static SqliteConnection Sqlite
    {
        get
        {
            lock (Connection)
            {
                if (!_seeded)
                {
                    Connection.Open();
                    using var cmd = Connection.CreateCommand();
                    cmd.CommandText = """
                        CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
                        INSERT INTO customers VALUES (1, 'Alice Anderson', 'alice@example.com');
                        INSERT INTO customers VALUES (2, 'Bob Baker', 'bob@example.com');
                        INSERT INTO customers VALUES (3, 'Carol Carter', 'carol@example.com');
                        INSERT INTO customers VALUES (4, 'Dave Dawson', 'dave@example.com');
                        """;
                    cmd.ExecuteNonQuery();
                    _seeded = true;
                }
                return Connection;
            }
        }
    }

    public static List<Customer> QueryCustomers(string sql, params SqliteParameter[] parameters)
    {
        var results = new List<Customer>();
        using var cmd = Sqlite.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddRange(parameters);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            results.Add(new Customer(reader.GetInt32(0), reader.GetString(1), reader.GetString(2)));
        }
        return results;
    }
}

/// <summary>Cryptographic helpers — one broken, one correct, side by side.</summary>
public static class Crypto
{
    // A02 — VULNERABLE: MD5 is broken for passwords (fast, unsalted, rainbow-tabled).
    public static string HashMd5(string input)
        => Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();

    // A02 — SECURE: PBKDF2 with a random 16-byte salt, 210,000 iterations.
    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 210_000, HashAlgorithmName.SHA256, 32);
        return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string stored)
    {
        var parts = stored.Split(':');
        if (parts.Length != 2) return false;
        var salt = Convert.FromBase64String(parts[0]);
        var expected = Convert.FromBase64String(parts[1]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, 210_000, HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    // A08 — verify an HMAC-SHA256 signature over a raw request body.
    public static bool VerifyHmac(string payload, string signatureHex, string secret)
    {
        var expected = Convert.ToHexString(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(payload)))
            .ToLowerInvariant();
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes(signatureHex.ToLowerInvariant()));
    }

    public static string SignHmac(string payload, string secret)
        => Convert.ToHexString(
            HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(payload)))
            .ToLowerInvariant();
}

/// <summary>Password-reset tokens — one predictable, one random.</summary>
public static class ResetTokens
{
    // A04 — VULNERABLE: token is derived from the username. Anyone can guess it.
    public static string Predictable(string user)
        => $"RESET-{(Math.Abs(user.GetHashCode()) % 9000) + 1000}";

    // A04 — SECURE: 32 bytes from the OS CSPRNG.
    public static string Random()
        => Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
}
