using Claudefuscator.Vault;

/*
 * A reference Claudefuscator vault.
 *
 * Small on purpose. It exists so the protocol the agent speaks has a second
 * implementation and a runnable server, rather than being whatever one
 * private deployment happens to do. The repository already holds four
 * tokenizers kept honest by shared vectors, for the same reason: two sides
 * that agree on everything the tests ask can still disagree in production.
 *
 * WHAT IT IS NOT
 *
 * Not a product. Authentication is a token file rather than an identity
 * provider, storage is SQLite rather than Postgres, and there is no UI. A
 * real deployment should resolve callers against the access list the
 * organisation already maintains - the protocol does not care how, only
 * that the result is an Identity, and keeping that seam narrow is most of
 * what makes this useful as a reference.
 *
 * THE ONE PROPERTY TO PRESERVE IF YOU CHANGE ANYTHING
 *
 * This server never holds the Claudefuscator key. Rows are ciphertext
 * produced on the client; nothing here can read them, and nothing in the
 * API accepts a key. That is what lets a vault be ordinary infrastructure
 * instead of a secret-handling system. If a change appears to need a key
 * here, stop and redesign.
 */

var builder = WebApplication.CreateBuilder(args);

var databasePath = builder.Configuration["Vault:Database"] ?? "vault.db";
var tokenPath = builder.Configuration["Vault:Tokens"] ?? "tokens.json";

builder.Services.AddSingleton(new VaultStore($"Data Source={databasePath}"));
builder.Services.AddSingleton(TokenFile.Load(tokenPath));

var app = builder.Build();

/* Liveness only. No auth, and nothing about what is stored - not even a
 * count, which is the metadata the encryption does not hide. */
app.MapGet("/healthz", () => Results.Ok(new { status = "ok" }));

var vault = app.MapGroup("/api/vault");

vault.MapPost("/resolve", (ResolveRequest request, HttpContext http, VaultStore store, TokenFile tokens) =>
{
    var who = Caller(http, tokens);
    if (who is null) return Results.Unauthorized();

    // Resolve answers about the tokens it is handed and no others. There is
    // deliberately no route that returns the table: a bulk export is the
    // single thing an attacker most wants here, so it is something that
    // would have to be built on purpose rather than a default that exists.
    return Results.Ok(store.Resolve(who, request.Tokens ?? []));
});

vault.MapPost("/mappings", (SubmitRequest request, HttpContext http, VaultStore store, TokenFile tokens) =>
{
    var who = Caller(http, tokens);
    if (who is null) return Results.Unauthorized();

    return Results.Ok(store.Submit(who, request.Mappings ?? []));
});

vault.MapGet("/identifiers", (HttpContext http, VaultStore store, TokenFile tokens) =>
{
    var who = Caller(http, tokens);
    if (who is null) return Results.Unauthorized();

    // Readable by anyone who may resolve. The list and the mappings are the
    // same class of secret - both say which strings are sensitive - so
    // gating them differently would be a distinction without a difference.
    var document = store.GetIdentifiers();
    return document is null ? Results.NotFound() : Results.Ok(document);
});

vault.MapPut("/identifiers", (PutIdentifiersRequest request, HttpContext http, VaultStore store, TokenFile tokens) =>
{
    var who = Caller(http, tokens);
    if (who is null) return Results.Unauthorized();

    // Its own role, not WriteMappings. Contributing a discovered value
    // affects one token; replacing this list pushes configuration to every
    // machine in the organisation, and whoever can do that can decide what
    // everybody stops sending to Anthropic - or quietly stops hiding.
    // StatusCode(403) rather than Results.Forbid(): Forbid() delegates to
    // the authentication stack, and this server has none - it does bearer
    // auth by hand - so it answers 500 and a permission refusal looks like
    // a server fault. Caught by the test that asserts the refusal.
    if (!who.Has(Identity.ManageIdentifiers))
    {
        return Results.StatusCode(StatusCodes.Status403Forbidden);
    }

    return store.PutIdentifiers(who, request)
        ? Results.Ok(new { stored = true, version = request.Version })
        : Results.Conflict(new { stored = false, reason = "version is not newer than the stored list" });
});

vault.MapGet("/key", (HttpContext http, VaultStore store, TokenFile tokens) =>
{
    var who = Caller(http, tokens);
    if (who is null) return Results.Unauthorized();

    // Only ever this caller's own. The wrapping means the server cannot
    // open it, but serving somebody else's would still hand an attacker a
    // blob to work on offline against a token they might later obtain.
    var wrapped = store.GetWrappedKey(who);
    return wrapped is null ? Results.NotFound() : Results.Ok(wrapped);
});

vault.MapPut("/key", (PutWrappedKeyRequest request, HttpContext http, VaultStore store, TokenFile tokens) =>
{
    var who = Caller(http, tokens);
    if (who is null) return Results.Unauthorized();

    store.PutWrappedKey(who, request);
    return Results.Ok(new { stored = true });
});

vault.MapGet("/stats", (HttpContext http, VaultStore store, TokenFile tokens) =>
{
    var who = Caller(http, tokens);
    if (who is null) return Results.Unauthorized();

    return Results.Ok(store.Stats(who));
});

app.Run();

static Identity? Caller(HttpContext http, TokenFile tokens)
{
    var header = http.Request.Headers.Authorization.ToString();
    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
    return tokens.Authenticate(header["Bearer ".Length..].Trim());
}

/// <summary>Reachable so the tests can host the real app.</summary>
public partial class Program;
