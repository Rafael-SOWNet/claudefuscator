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

/// <summary>Who is calling, and what they may read.</summary>
/// <param name="Name">For the audit trail only.</param>
/// <param name="AllProducts">No restriction, including products added later.</param>
/// <param name="Products">Granted products when <paramref name="AllProducts"/> is false.</param>
public sealed record Identity(string Name, bool AllProducts, IReadOnlySet<string> Products)
{
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

            byHash[Hash(token)] = new Identity(
                entry.TryGetProperty("name", out var n) ? n.GetString() ?? "unnamed" : "unnamed",
                entry.TryGetProperty("allProducts", out var a) && a.ValueKind == JsonValueKind.True,
                products);
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
