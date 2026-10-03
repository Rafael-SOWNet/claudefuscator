using Microsoft.Data.Sqlite;

namespace Claudefuscator.Vault;

/// <summary>
/// Claudefuscator mappings in SQLite: a token, and the real value it stands
/// for, stored as ciphertext this server cannot read.
/// </summary>
/// <remarks>
/// <para>
/// <b>This server never holds the key, and must never be given one.</b> The
/// value arrives already encrypted by the client that discovered it. A row
/// here is a token, a nonce and an AEAD ciphertext, and nothing in this
/// class, the schema or the API accepts a key. If a change appears to need
/// one, that is the signal to stop and redesign.
/// </para>
/// <para>
/// The reason is narrower than "it is sensitive". Disk and database
/// encryption defend against a stolen disk or a leaked backup; they do not
/// defend against the application being compromised, because the application
/// can read its own database — and the application is the part exposed to
/// the network. So decryption happens somewhere this process is not.
/// </para>
/// <para>
/// What that does NOT buy, said here so nobody over-trusts it: metadata is
/// in the clear. Row count, which product holds how many, when they were
/// written and by whom, and each token's TYPE prefix. An attacker who takes
/// this database learns that 412 customer names exist even if they learn no
/// name.
/// </para>
/// </remarks>
internal sealed class VaultStore
{
    /// <summary>
    /// A cap on one request, so a caller cannot walk the table by asking
    /// about an enormous list of candidate tokens in a single round trip.
    /// Resolving a page of conversation needs tens, not thousands.
    /// </summary>
    public const int MaxTokensPerRequest = 500;

    private readonly string _connectionString;

    public VaultStore(string connectionString)
    {
        _connectionString = connectionString;
        Initialise();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private void Initialise()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();

        // The unique index is what makes write-once real rather than
        // advisory: two clients racing to submit the same discovery resolve
        // to one row instead of two. Keyed on the version as well, so
        // rotating the key writes into a fresh namespace rather than
        // colliding with rows the old key produced.
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS vault_mappings (
                token            TEXT    NOT NULL,
                token_version    TEXT    NOT NULL,
                product          TEXT    NULL,
                envelope_version INTEGER NOT NULL,
                nonce            TEXT    NOT NULL,
                ciphertext       TEXT    NOT NULL,
                created_by       TEXT    NOT NULL,
                created_at       TEXT    NOT NULL,
                PRIMARY KEY (token, token_version)
            );
            CREATE INDEX IF NOT EXISTS ix_vault_product ON vault_mappings(product);

            -- One row, replaced in place. History is not kept here on
            -- purpose: an old sealed list is still readable by anyone with
            -- the key, so keeping every revision would quietly build the
            -- very archive the version binding exists to stop being
            -- replayed.
            CREATE TABLE IF NOT EXISTS vault_identifiers (
                id               INTEGER PRIMARY KEY CHECK (id = 1),
                envelope_version INTEGER NOT NULL,
                version          INTEGER NOT NULL,
                nonce            TEXT    NOT NULL,
                ciphertext       TEXT    NOT NULL,
                updated_by       TEXT    NOT NULL,
                updated_at       TEXT    NOT NULL
            );
            """;
        command.ExecuteNonQuery();
    }

    /// <summary>
    /// The rows for these tokens that this caller may read, plus a count of
    /// those that exist but are out of scope.
    /// </summary>
    public ResolveResponse Resolve(Identity who, IReadOnlyList<string> tokens)
    {
        var wanted = tokens
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Distinct(StringComparer.Ordinal)
            .Take(MaxTokensPerRequest)
            .ToList();

        if (wanted.Count == 0)
        {
            return new ResolveResponse([], [], 0);
        }

        var readable = new List<VaultMappingDto>();
        var found = new HashSet<string>(StringComparer.Ordinal);
        var withheld = 0;

        using var connection = Open();
        using var command = connection.CreateCommand();

        var names = wanted.Select((_, i) => "$t" + i).ToList();
        command.CommandText =
            "SELECT token, token_version, product, envelope_version, nonce, ciphertext "
            + $"FROM vault_mappings WHERE token IN ({string.Join(",", names)})";
        for (var i = 0; i < wanted.Count; i++)
        {
            command.Parameters.AddWithValue(names[i], wanted[i]);
        }

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var token = reader.GetString(0);
            var product = reader.IsDBNull(2) ? null : reader.GetString(2);
            found.Add(token);

            // A mapping with no product is readable only by a caller granted
            // every product. Unassigned is the most restrictive state, so
            // forgetting to classify one under-shares rather than over-shares.
            if (!who.MayRead(product))
            {
                withheld++;
                continue;
            }

            readable.Add(new VaultMappingDto(
                token, reader.GetString(1), product,
                reader.GetInt32(3), reader.GetString(4), reader.GetString(5)));
        }

        return new ResolveResponse(
            readable,
            [.. wanted.Where(t => !found.Contains(t))],
            withheld);
    }

    /// <summary>
    /// Store mappings, write-once per (token, token version). An existing
    /// token is never overwritten; it is reported as a conflict.
    /// </summary>
    public SubmitResponse Submit(Identity who, IReadOnlyList<VaultMappingDto> mappings)
    {
        var added = 0;
        var conflicts = new List<string>();
        var rejected = new List<string>();

        using var connection = Open();
        using var transaction = connection.BeginTransaction();

        foreach (var dto in mappings.Take(MaxTokensPerRequest))
        {
            if (!IsWellFormed(dto))
            {
                rejected.Add(dto?.Token ?? string.Empty);
                continue;
            }

            // Writing into a product the caller may not read would let them
            // put rows somewhere they cannot see, which is a way to hide
            // something rather than to share it.
            if (!who.MayRead(dto.Product))
            {
                rejected.Add(dto.Token);
                continue;
            }

            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT OR IGNORE INTO vault_mappings
                    (token, token_version, product, envelope_version, nonce,
                     ciphertext, created_by, created_at)
                VALUES ($token, $version, $product, $envelope, $nonce, $ct, $by, $at)
                """;
            command.Parameters.AddWithValue("$token", dto.Token);
            command.Parameters.AddWithValue("$version", dto.TokenVersion);
            command.Parameters.AddWithValue("$product", (object?)dto.Product ?? DBNull.Value);
            command.Parameters.AddWithValue("$envelope", dto.EnvelopeVersion);
            command.Parameters.AddWithValue("$nonce", dto.Nonce);
            command.Parameters.AddWithValue("$ct", dto.Ciphertext);
            command.Parameters.AddWithValue("$by", who.Name);
            command.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("o"));

            // INSERT OR IGNORE plus the unique index does the write-once in
            // one statement: no read-then-write, so two clients racing cannot
            // both see "absent" and both insert.
            if (command.ExecuteNonQuery() == 1)
            {
                added++;
            }
            else
            {
                // Under a correct client a token determines its value, so a
                // conflict means a bug, a key mismatch, or an attempt to
                // poison. Keep the first value and say so.
                conflicts.Add(dto.Token);
            }
        }

        transaction.Commit();
        return new SubmitResponse(added, conflicts, rejected);
    }

    /// <summary>The sealed identifier list, or null when none is published.</summary>
    public IdentifierDocumentDto? GetIdentifiers()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT envelope_version, version, nonce, ciphertext, updated_by, updated_at "
            + "FROM vault_identifiers WHERE id = 1";

        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;

        return new IdentifierDocumentDto(
            reader.GetInt32(0), reader.GetInt32(1), reader.GetString(2),
            reader.GetString(3), reader.GetString(4), reader.GetString(5));
    }

    /// <summary>
    /// Replace the list. Returns false when <paramref name="document"/> is
    /// not newer than what is stored.
    /// </summary>
    /// <remarks>
    /// Refusing a version that is not an increase is the server's half of
    /// the rollback defence. The envelope binds its version cryptographically
    /// so a client will not open a replayed one, but refusing it here means
    /// a stale list never reaches a client to be rejected, and two
    /// administrators publishing concurrently cannot silently lose one
    /// edit - the second gets a refusal instead.
    /// </remarks>
    public bool PutIdentifiers(Identity who, PutIdentifiersRequest document)
    {
        var current = GetIdentifiers();
        if (current is not null && document.Version <= current.Version) return false;

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO vault_identifiers
                (id, envelope_version, version, nonce, ciphertext, updated_by, updated_at)
            VALUES (1, $envelope, $version, $nonce, $ct, $by, $at)
            ON CONFLICT(id) DO UPDATE SET
                envelope_version = $envelope, version = $version, nonce = $nonce,
                ciphertext = $ct, updated_by = $by, updated_at = $at
            """;
        command.Parameters.AddWithValue("$envelope", document.EnvelopeVersion);
        command.Parameters.AddWithValue("$version", document.Version);
        command.Parameters.AddWithValue("$nonce", document.Nonce);
        command.Parameters.AddWithValue("$ct", document.Ciphertext);
        command.Parameters.AddWithValue("$by", who.Name);
        command.Parameters.AddWithValue("$at", DateTimeOffset.UtcNow.ToString("o"));
        command.ExecuteNonQuery();
        return true;
    }

    /// <summary>How much is here, counting only what this caller may read.</summary>
    public StatsResponse Stats(Identity who)
    {
        var byProduct = new Dictionary<string, (int Count, long Bytes)>(StringComparer.Ordinal);
        var byType = new Dictionary<string, (int Count, long Bytes)>(StringComparer.Ordinal);
        var contributors = new HashSet<string>(StringComparer.Ordinal);
        var total = 0;
        long bytes = 0;
        string? oldest = null, newest = null;

        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT token, product, created_by, created_at, "
            + "length(ciphertext) + length(nonce) + length(token) FROM vault_mappings";

        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var product = reader.IsDBNull(1) ? null : reader.GetString(1);

            // Scoped, like resolve. A count is precisely the metadata the
            // encryption does not hide, so a caller granted one product must
            // not learn the size of the others.
            if (!who.MayRead(product)) continue;

            var token = reader.GetString(0);
            var rowBytes = reader.GetInt64(4);
            var createdAt = reader.GetString(3);

            total++;
            bytes += rowBytes;
            contributors.Add(reader.GetString(2));
            if (oldest is null || string.CompareOrdinal(createdAt, oldest) < 0) oldest = createdAt;
            if (newest is null || string.CompareOrdinal(createdAt, newest) > 0) newest = createdAt;

            Accumulate(byProduct, product ?? "(unassigned)", rowBytes);
            Accumulate(byType, TypeOf(token), rowBytes);
        }

        return new StatsResponse(
            total, bytes, contributors.Count, oldest, newest,
            [.. byProduct.Select(kv => new StatsGroupDto(kv.Key, kv.Value.Count, kv.Value.Bytes))
                 .OrderByDescending(g => g.Mappings).ThenBy(g => g.Name, StringComparer.Ordinal)],
            [.. byType.Select(kv => new StatsGroupDto(kv.Key, kv.Value.Count, kv.Value.Bytes))
                 .OrderByDescending(g => g.Mappings).ThenBy(g => g.Name, StringComparer.Ordinal)],
            !who.AllProducts);
    }

    private static void Accumulate(
        Dictionary<string, (int Count, long Bytes)> into, string key, long bytes)
    {
        into.TryGetValue(key, out var current);
        into[key] = (current.Count + 1, current.Bytes + bytes);
    }

    private static string TypeOf(string token)
    {
        var i = token.IndexOf('_', StringComparison.Ordinal);
        return i > 0 ? token[..i] : "(none)";
    }

    /// <summary>
    /// Anything that would produce a row no client could ever open. Not a
    /// cryptographic check — this server cannot perform one, having no key —
    /// but enough to keep junk out of the table.
    /// </summary>
    private static bool IsWellFormed(VaultMappingDto? dto)
        => dto is not null
            && !string.IsNullOrWhiteSpace(dto.Token) && dto.Token.Length <= 128
            && !string.IsNullOrWhiteSpace(dto.TokenVersion) && dto.TokenVersion.Length <= 64
            && dto.EnvelopeVersion > 0
            && IsBase64(dto.Nonce, 64)
            && IsBase64(dto.Ciphertext, 8192);

    private static bool IsBase64(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maxLength) return false;
        return Convert.TryFromBase64String(value, new byte[((value.Length * 3) / 4) + 4], out _);
    }
}
