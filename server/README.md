# Reference vault server

A small, runnable implementation of the vault API that
[`agent/vault_client.py`](../agent/vault_client.py) speaks. ASP.NET Core,
SQLite, bearer tokens from a file.

```bash
cd server
cat > tokens.json <<'JSON'
{ "tokens": [ { "name": "me", "token": "pick-something-random", "allProducts": true } ] }
JSON
dotnet run --project src/Claudefuscator.Vault --urls http://127.0.0.1:8099
```

Then point an agent at it:

```json
{ "vault": { "url": "http://127.0.0.1:8099" } }
```

```bash
export CLAUDEFUSCATOR_VAULT_TOKEN=pick-something-random
python tools/verify-vault-live.py        # 8 checks, end to end
```

## Why this exists

Not because one implementation was insufficient, but because **one
implementation is not a protocol.**

This repository already carries four tokenizers — JavaScript, a Python
hand-port, an ES-module copy for the mod's sandbox and a byte-identical
copy for the extension — held together by `shared/test-vectors.json`. The
reason is written into `CLAUDE.md`: two sides that agree on everything the
tests ask can still disagree in production, and when they do, restore fails
*silently*. That is not hypothetical here. A compound literal swallowing a
longer pattern match shipped in both the JavaScript and the Python core and
passed every vector, because no vector combined the two features.

The vault API had the same shape of gap: the Python client had only ever
met a Python stand-in, and the production server had only ever met C#
callers. Each side was green while the pair was unverified. This server
closes that — the same `verify-vault-live.py` run passes against it and
against the production deployment, so the protocol is now something two
implementations agree on rather than whatever one of them happens to do.

## What it is not

Not a product, and deliberately smaller than a real deployment:

| | Here | A real deployment |
|---|---|---|
| Who is calling | bearer token in a JSON file | your existing access list and identity provider |
| Storage | SQLite file | a database with backups |
| Need-to-know | products listed per token | whatever grants you already model |

Those are the seams, and keeping them narrow is most of what makes this
useful as a reference. The protocol does not care how a caller is
identified — only that the result is an `Identity` saying what they may
read.

## The property to preserve if you change anything

**This server never holds the Claudefuscator key.**

Rows arrive already encrypted by the client that discovered them. A row is
a token, a nonce and an AEAD ciphertext; nothing here can read one, and
nothing in the API accepts a key. That is what lets a vault be ordinary
infrastructure rather than a secret-handling system, and it is why a
compromise yields ciphertext instead of the deanonymisation mapping for
every conversation anybody has ever had.

If a change appears to need a key here, stop and redesign.

### What that does not buy

Said plainly, because an encrypted store invites over-trust:

- **Metadata is in the clear.** Row count, which product holds how many,
  when they were written and by whom, and each token's TYPE prefix. An
  attacker who takes the database learns that 412 customer names exist even
  though they learn no name. That is why `/api/vault/stats` is scoped to
  what the caller may read, and why `/healthz` reports no count at all.
- **Encryption is not access control.** Anyone with the key *and* access
  reads everything in their scope.
- **A compromised client is a compromised mapping**, because the key is on
  the endpoint.

## API

| Route | Purpose |
|---|---|
| `POST /api/vault/resolve` | `{tokens:[…]}` → the rows this caller may read, plus `unresolved` and a `withheld` count |
| `POST /api/vault/mappings` | submit sealed rows; write-once per `(token, tokenVersion)` |
| `GET /api/vault/stats` | counts and sizes, scoped, with `partial` when it is a slice |
| `GET /healthz` | liveness, no auth, no data |

Four behaviours are load-bearing rather than incidental:

- **No bulk export.** `resolve` answers about the tokens it is handed and no
  others. A dump of the table is the single thing an attacker most wants
  here, so it is something that has to be built deliberately rather than a
  default that happens to exist.
- **Write-once**, enforced by a unique index rather than a read-then-write,
  so two clients racing to submit the same discovery resolve to one row. A
  conflicting value is refused and reported: under a correct client a token
  determines its value, so a conflict means a bug, a key mismatch, or an
  attempt to poison.
- **Unassigned is the most restrictive state.** A row with no product is
  readable only by a caller granted every product, so forgetting to
  classify one under-shares rather than over-shares.
- **Withheld is a count, never a list.** Naming the tokens somebody was
  denied would disclose the shape of what other products hold.

## Tests

```bash
dotnet test server/Claudefuscator.Vault.slnx
```

Twelve, and most of them assert a refusal — no credential, a made-up
credential, reading another product, writing into a product you cannot
read, a second write, junk, and every URL that might return the table. The
happy path is the easy part; the refusals are the claim.

One test pins the JSON field names the Python client parses. The two sides
are configured independently and nothing else holds them together.
