using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Claudefuscator.Vault;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Claudefuscator.Vault.Tests;

/// <summary>
/// The reference vault, over real HTTP.
/// <para>
/// Most of these assert that something does NOT happen. This server holds
/// the deanonymisation mapping for every tokenized conversation, so the
/// refusals are the claim and the happy path is the easy part.
/// </para>
/// </summary>
public sealed class VaultTests : IClassFixture<VaultFactory>
{
    private readonly VaultFactory _factory;

    public VaultTests(VaultFactory factory) => _factory = factory;

    private HttpClient Client(string? token)
    {
        var client = _factory.CreateClient();
        if (token is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        return client;
    }

    private static VaultMappingDto Row(string token, string? product = null, string marker = "x")
        => new(token, "claudefuscator/v1", product, 1,
               Convert.ToBase64String(new byte[12]),
               Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("sealed:" + marker)));

    // --- the credential ------------------------------------------------

    [Fact]
    public async Task Without_a_token_nothing_answers()
    {
        using var client = Client(null);

        foreach (var response in new[]
        {
            await client.PostAsJsonAsync("/api/vault/resolve", new ResolveRequest(["HOST_a1"])),
            await client.PostAsJsonAsync("/api/vault/mappings", new SubmitRequest([])),
            await client.GetAsync("/api/vault/stats"),
        })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [Fact]
    public async Task A_made_up_token_does_not_authenticate()
    {
        using var client = Client("not-a-real-token");
        var response = await client.PostAsJsonAsync("/api/vault/resolve", new ResolveRequest(["HOST_a1"]));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // --- need to know ----------------------------------------------------

    [Fact]
    public async Task A_caller_granted_one_product_cannot_read_another()
    {
        using var admin = Client(VaultFactory.AdminToken);
        await admin.PostAsJsonAsync("/api/vault/mappings", new SubmitRequest(
        [
            Row("HOST_scoped1", "alpha", "a"),
            Row("HOST_scoped2", "beta", "b"),
        ]));

        using var limited = Client(VaultFactory.AlphaToken);
        var response = await limited.PostAsJsonAsync("/api/vault/resolve",
            new ResolveRequest(["HOST_scoped1", "HOST_scoped2"]));

        var body = await response.Content.ReadFromJsonAsync<ResolveResponse>();
        Assert.NotNull(body);
        Assert.Single(body!.Mappings);
        Assert.Equal("HOST_scoped1", body.Mappings[0].Token);

        // A count, never a list. Naming the withheld tokens would disclose
        // the shape of what the other products hold.
        Assert.Equal(1, body.Withheld);
        Assert.DoesNotContain("HOST_scoped2", body.Unresolved);
    }

    [Fact]
    public async Task An_unassigned_row_is_readable_only_with_every_product()
    {
        using var admin = Client(VaultFactory.AdminToken);
        await admin.PostAsJsonAsync("/api/vault/mappings",
            new SubmitRequest([Row("HOST_unassigned", null, "u")]));

        using var limited = Client(VaultFactory.AlphaToken);
        var scoped = await (await limited.PostAsJsonAsync("/api/vault/resolve",
            new ResolveRequest(["HOST_unassigned"]))).Content.ReadFromJsonAsync<ResolveResponse>();
        Assert.Empty(scoped!.Mappings);

        var all = await (await admin.PostAsJsonAsync("/api/vault/resolve",
            new ResolveRequest(["HOST_unassigned"]))).Content.ReadFromJsonAsync<ResolveResponse>();
        Assert.Single(all!.Mappings);
    }

    [Fact]
    public async Task A_caller_cannot_write_into_a_product_it_may_not_read()
    {
        using var limited = Client(VaultFactory.AlphaToken);
        var body = await (await limited.PostAsJsonAsync("/api/vault/mappings",
            new SubmitRequest([Row("HOST_sneaky", "beta", "s")]))).Content
            .ReadFromJsonAsync<SubmitResponse>();

        // Otherwise a caller could put rows somewhere they cannot see, which
        // is a way to hide something rather than to share it.
        Assert.Equal(0, body!.Added);
        Assert.Contains("HOST_sneaky", body.Rejected);
    }

    // --- write-once ------------------------------------------------------

    [Fact]
    public async Task A_second_write_is_refused_and_the_first_value_kept()
    {
        using var admin = Client(VaultFactory.AdminToken);
        var first = Row("HOST_once", "alpha", "original");

        var a = await (await admin.PostAsJsonAsync("/api/vault/mappings",
            new SubmitRequest([first]))).Content.ReadFromJsonAsync<SubmitResponse>();
        Assert.Equal(1, a!.Added);

        var b = await (await admin.PostAsJsonAsync("/api/vault/mappings",
            new SubmitRequest([Row("HOST_once", "alpha", "poisoned")]))).Content
            .ReadFromJsonAsync<SubmitResponse>();

        // Under a correct client a token determines its value, so a conflict
        // is a bug, a key mismatch, or an attempt to poison.
        Assert.Equal(0, b!.Added);
        Assert.Contains("HOST_once", b.Conflicts);

        var read = await (await admin.PostAsJsonAsync("/api/vault/resolve",
            new ResolveRequest(["HOST_once"]))).Content.ReadFromJsonAsync<ResolveResponse>();
        Assert.Equal(first.Ciphertext, read!.Mappings[0].Ciphertext);
    }

    [Fact]
    public async Task The_same_token_under_a_new_key_namespace_is_a_separate_row()
    {
        using var admin = Client(VaultFactory.AdminToken);
        await admin.PostAsJsonAsync("/api/vault/mappings",
            new SubmitRequest([Row("HOST_rotate", "alpha", "v1")]));

        // Rotating the key means a new namespace. The old row must neither
        // block the new one nor be mistaken for it.
        var rotated = await (await admin.PostAsJsonAsync("/api/vault/mappings", new SubmitRequest(
        [
            new VaultMappingDto("HOST_rotate", "claudefuscator/v2", "alpha", 1,
                Convert.ToBase64String(new byte[12]),
                Convert.ToBase64String("sealed:v2"u8.ToArray())),
        ]))).Content.ReadFromJsonAsync<SubmitResponse>();

        Assert.Equal(1, rotated!.Added);
        Assert.Empty(rotated.Conflicts);
    }

    [Fact]
    public async Task Junk_is_rejected_rather_than_stored()
    {
        using var admin = Client(VaultFactory.AdminToken);
        var body = await (await admin.PostAsJsonAsync("/api/vault/mappings", new SubmitRequest(
        [
            new VaultMappingDto("", "claudefuscator/v1", null, 1, "AAAA", "AAAA"),
            new VaultMappingDto("HOST_bad1", "claudefuscator/v1", null, 1, "not base64!", "AAAA"),
            new VaultMappingDto("HOST_bad2", "claudefuscator/v1", null, 0, "AAAA", "AAAA"),
        ]))).Content.ReadFromJsonAsync<SubmitResponse>();

        Assert.Equal(0, body!.Added);
        Assert.Equal(3, body.Rejected.Count);
    }

    // --- no bulk export --------------------------------------------------

    [Fact]
    public async Task No_route_returns_the_whole_table()
    {
        using var admin = Client(VaultFactory.AdminToken);
        await admin.PostAsJsonAsync("/api/vault/mappings",
            new SubmitRequest([Row("HOST_secret", "alpha", "findme")]));

        foreach (var path in new[] { "/api/vault", "/api/vault/mappings", "/api/vault/all", "/api/vault/export" })
        {
            var response = await admin.GetAsync(path);
            Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.DoesNotContain("findme", await response.Content.ReadAsStringAsync(),
                StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task Healthz_says_nothing_about_what_is_stored()
    {
        using var client = Client(null);
        var response = await client.GetAsync("/healthz");
        response.EnsureSuccessStatusCode();

        // Not even a count: that is the metadata the encryption does not hide.
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("mapping", body, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("count", body, StringComparison.OrdinalIgnoreCase);
    }

    // --- statistics ------------------------------------------------------

    [Fact]
    public async Task Stats_are_scoped_and_say_when_they_are_a_slice()
    {
        using var admin = Client(VaultFactory.AdminToken);
        await admin.PostAsJsonAsync("/api/vault/mappings", new SubmitRequest(
        [
            Row("HOST_stat1", "alpha", "1"),
            Row("PERSON_stat2", "beta", "2"),
        ]));

        var full = await (await admin.GetAsync("/api/vault/stats")).Content
            .ReadFromJsonAsync<StatsResponse>();
        Assert.False(full!.Partial);

        using var limited = Client(VaultFactory.AlphaToken);
        var slice = await (await limited.GetAsync("/api/vault/stats")).Content
            .ReadFromJsonAsync<StatsResponse>();

        Assert.True(slice!.Partial);
        Assert.True(slice.Mappings < full.Mappings);
        Assert.DoesNotContain(slice.ByProduct, g => g.Name == "beta");
    }

    // --- the shape the agent parses ---------------------------------------

    [Fact]
    public async Task The_response_uses_the_field_names_the_agent_reads()
    {
        using var admin = Client(VaultFactory.AdminToken);
        await admin.PostAsJsonAsync("/api/vault/mappings",
            new SubmitRequest([Row("HOST_shape", "alpha", "shape")]));

        var response = await admin.PostAsJsonAsync("/api/vault/resolve",
            new ResolveRequest(["HOST_shape"]));

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var row = json.RootElement.GetProperty("mappings")[0];

        // agent/vault_client.py reads these exact names. The two sides are
        // configured independently; nothing but a test holds them together.
        Assert.Equal("HOST_shape", row.GetProperty("token").GetString());
        Assert.Equal("claudefuscator/v1", row.GetProperty("tokenVersion").GetString());
        Assert.Equal(1, row.GetProperty("envelopeVersion").GetInt32());
        Assert.True(row.TryGetProperty("nonce", out _));
        Assert.True(row.TryGetProperty("ciphertext", out _));
        Assert.True(row.TryGetProperty("product", out _));
        Assert.True(json.RootElement.TryGetProperty("unresolved", out _));
        Assert.True(json.RootElement.TryGetProperty("withheld", out _));
    }
}

/// <summary>Hosts the real app against a throwaway database and token file.</summary>
public sealed class VaultFactory : WebApplicationFactory<Program>, IDisposable
{
    public const string AdminToken = "reference-admin-token";
    public const string AlphaToken = "reference-alpha-token";

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "cf-vault-" + Guid.NewGuid().ToString("N"));

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        Directory.CreateDirectory(_directory);

        var tokens = Path.Combine(_directory, "tokens.json");
        File.WriteAllText(tokens, $$"""
            { "tokens": [
                { "name": "admin", "token": "{{AdminToken}}", "allProducts": true },
                { "name": "alpha-only", "token": "{{AlphaToken}}", "products": ["alpha"] }
            ] }
            """);

        builder.UseSetting("Vault:Database", Path.Combine(_directory, "vault.db"));
        builder.UseSetting("Vault:Tokens", tokens);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_directory))
        {
            try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
        }
    }
}
