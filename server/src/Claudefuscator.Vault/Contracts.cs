using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Claudefuscator.Vault;

/// <summary>
/// One encrypted mapping as it crosses the wire. The server never sees the
/// value these fields encrypt, and never holds a key that could.
/// </summary>
/// <param name="Token">The token, e.g. <c>HOST_c400a844</c>. Not secret.</param>
/// <param name="TokenVersion">Derivation namespace, e.g. <c>claudefuscator/v1</c>.</param>
/// <param name="Product">Need-to-know group, or null for the most restrictive state.</param>
/// <param name="EnvelopeVersion">Envelope format version.</param>
/// <param name="Nonce">AEAD nonce, base64.</param>
/// <param name="Ciphertext">AES-256-GCM ciphertext with tag, base64.</param>
public sealed record VaultMappingDto(
    string Token,
    string TokenVersion,
    string? Product,
    int EnvelopeVersion,
    string Nonce,
    string Ciphertext);

public sealed record ResolveRequest(IReadOnlyList<string> Tokens);

/// <param name="Withheld">
/// How many rows existed but were outside the caller's grants. The count is
/// returned and the tokens are not: naming them would disclose the shape of
/// what other products hold.
/// </param>
public sealed record ResolveResponse(
    IReadOnlyList<VaultMappingDto> Mappings,
    IReadOnlyList<string> Unresolved,
    int Withheld);

public sealed record SubmitRequest(IReadOnlyList<VaultMappingDto> Mappings);

public sealed record SubmitResponse(
    int Added,
    IReadOnlyList<string> Conflicts,
    IReadOnlyList<string> Rejected);

public sealed record StatsGroupDto(string Name, int Mappings, long PayloadBytes);

/// <param name="Partial">True when the caller cannot read every row, so these are their slice.</param>
public sealed record StatsResponse(
    int Mappings,
    long PayloadBytes,
    int Contributors,
    string? Oldest,
    string? Newest,
    IReadOnlyList<StatsGroupDto> ByProduct,
    IReadOnlyList<StatsGroupDto> ByType,
    bool Partial);

/// <summary>
/// The identifier list, sealed. The server stores and serves it without
/// being able to read it, exactly like a mapping.
/// </summary>
/// <param name="Version">
/// Monotonic, and bound into the envelope's additional data. That is what
/// stops a rollback: an old list cannot be replayed as the current one
/// without being re-sealed, which needs the key.
/// </param>
public sealed record IdentifierDocumentDto(
    int EnvelopeVersion,
    int Version,
    string Nonce,
    string Ciphertext,
    string? UpdatedBy,
    string? UpdatedAt);

public sealed record PutIdentifiersRequest(
    int EnvelopeVersion,
    int Version,
    string Nonce,
    string Ciphertext);

/// <summary>Who is calling, what they may read, and what they may do.</summary>
/// <param name="Name">For the audit trail only.</param>
/// <param name="AllProducts">No restriction, including products added later.</param>
/// <param name="Products">Granted products when <paramref name="AllProducts"/> is false.</param>
/// <param name="Roles">
/// Named permissions. <c>ManageIdentifiers</c> is deliberately its own role
/// rather than part of writing mappings: contributing one discovered value
/// affects one token, whereas replacing the identifier list pushes
/// configuration to every machine in the organisation. Those are different
/// powers and should be granted separately.
/// </param>
public sealed record Identity(
    string Name,
    bool AllProducts,
    IReadOnlySet<string> Products,
    IReadOnlySet<string> Roles)
{
    /// <summary>Replace the shared identifier list.</summary>
    public const string ManageIdentifiers = "ManageIdentifiers";

    public bool Has(string role) => Roles.Contains(role);

    /// <summary>
    /// A row with no product is readable only through <see cref="AllProducts"/>.
    /// Unassigned is the most restrictive state, not the least, so a mapping
    /// nobody classified under-shares rather than over-shares.
    /// </summary>
    public bool MayRead(string? product)
        => AllProducts || (product is not null && Products.Contains(product));
}

/// <summary>
/// Bearer-token authentication from a JSON file.
/// <para>
/// This is the one place the reference server deliberately differs from a
/// production deployment, which should resolve a caller against whatever
/// access list the organisation already maintains. The protocol does not
/// care how a caller is identified, only that the result is an
/// <see cref="Identity"/> — keeping that seam narrow is most of why this
/// server is useful as a reference.
/// </para>
/// </summary>
internal sealed class TokenFile
{
    private readonly Dictionary<string, Identity> _byHash;

    private TokenFile(Dictionary<string, Identity> byHash) => _byHash = byHash;

    /// <summary>
    /// Reads <c>{"tokens":[{"name","token","products":["a"],"allProducts":false}]}</c>.
    /// Tokens are hashed on load and the plaintext is dropped, so a heap dump
    /// of a running server does not hand over working credentials.
    /// </summary>
    public static TokenFile Load(string path)
    {
        var byHash = new Dictionary<string, Identity>(StringComparer.Ordinal);
        if (!File.Exists(path)) return new TokenFile(byHash);

        using var document = JsonDocument.Parse(File.ReadAllText(path));
        if (!document.RootElement.TryGetProperty("tokens", out var tokens)) return new TokenFile(byHash);

        foreach (var entry in tokens.EnumerateArray())
        {
            var token = entry.TryGetProperty("token", out var t) ? t.GetString() : null;
            if (string.IsNullOrWhiteSpace(token)) continue;

            var products = new HashSet<string>(StringComparer.Ordinal);
            if (entry.TryGetProperty("products", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var p in list.EnumerateArray())
                {
                    if (p.GetString() is { Length: > 0 } name) products.Add(name);
                }
            }

            var roles = new HashSet<string>(StringComparer.Ordinal);
            if (entry.TryGetProperty("roles", out var roleList)
                && roleList.ValueKind == JsonValueKind.Array)
            {
                foreach (var r in roleList.EnumerateArray())
                {
                    if (r.GetString() is { Length: > 0 } role) roles.Add(role);
                }
            }

            byHash[Hash(token)] = new Identity(
                entry.TryGetProperty("name", out var n) ? n.GetString() ?? "unnamed" : "unnamed",
                entry.TryGetProperty("allProducts", out var a) && a.ValueKind == JsonValueKind.True,
                products,
                roles);
        }

        return new TokenFile(byHash);
    }

    /// <summary>The caller, or null. Compared in constant time.</summary>
    public Identity? Authenticate(string? presented)
    {
        if (string.IsNullOrWhiteSpace(presented)) return null;

        var hash = Hash(presented);
        foreach (var (known, identity) in _byHash)
        {
            // Fixed-time over every entry: returning early on the first
            // mismatch would leak which prefix was right by how long the
            // answer took.
            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(known), Encoding.ASCII.GetBytes(hash)))
            {
                return identity;
            }
        }

        return null;
    }

    private static string Hash(string token)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
}

/// <summary>
/// The Claudefuscator key, wrapped so that only its owner's API token
/// opens it, stored per user so a browser can collect it once a session
/// instead of a person retyping it.
/// </summary>
/// <remarks>
/// <para>
/// This is the one place the design knowingly gives something up. For most
/// of its life the rule was that this server never holds the key in any
/// form, because that is what makes a compromise yield ciphertext rather
/// than the deanonymisation mapping for every conversation anyone has had.
/// </para>
/// <para>
/// What survives: the blob is sealed under a key derived from the user's
/// API token, and this server stores only a SHA-256 of that token. A
/// database dump, a backup or a stolen disk therefore yields something
/// nothing on the host can open.
/// </para>
/// <para>
/// What does not: a token arrives in plaintext on every request, so code
/// execution on the running host can harvest one and unwrap. No
/// arrangement avoids that once a server hands out keys at all. Weigh it
/// knowing that, rather than reading the wrapping as making it safe.
/// </para>
/// </remarks>
public sealed record WrappedKeyDto(int EnvelopeVersion, string Nonce, string Ciphertext);

public sealed record PutWrappedKeyRequest(int EnvelopeVersion, string Nonce, string Ciphertext);
