# Unveil server

**Status (2026-10-03): live, and verified end to end against the deployed
server.**

Merged as `d5f82ac` in `example/ai` and deployed to `https://ai.example.com`,
as a module inside the existing application rather than a second service.

Verified against the live server, 8/8: the personal API token was accepted,
a value sealed on an employee machine was stored, read back out of Postgres,
decrypted, and confirmed to hash back to its token; a second write was
refused as a conflict; a different key could not read the row. Inspecting
the row directly showed ciphertext only, which is the claim no client can
make about itself. The verification row was deleted afterwards.

Reproduce it with `python tools/verify-vault-live.py` and a token in
`CLAUDEFUSCATOR_VAULT_TOKEN`.

What exists: the `vault_mappings` table, the `ReadMappings` /
`WriteMappings` roles, product-scoped `POST /api/vault/resolve` and
`POST /api/vault/mappings`, `GET /api/vault/stats` with an admin page at
`/admin/vault` (merge request !3, not yet merged), the client-side
encryption in `agent/vault_crypto.py`, and the agent's client in
`agent/vault_client.py`.

What does not: **no real mapping has been written yet.** The vault is
empty, and key escrow should exist before that changes — see
the deployer's own rollout checklist — the operational rollout checklist lives outside this repository, with the deployment detail it names.

**One design change from what follows.** The "Entra app registration" listed
below as a prerequisite turned out not to be needed. The agent authenticates
with a **personal API token** the user creates after signing in normally —
`ai.example.com` already has `ApiToken` and `ApiTokenAuthenticationHandler`,
which resolve a bearer token to the same claims and the same `invited_users`
lookup the browser uses. That needs no admin consent, is revocable in the
application, and keeps one authorization system instead of two. The sections
below are otherwise as designed.

A shared store of `token -> real value`, so the Chrome extension can restore
values it cannot derive for itself, and so a value one person tokenizes is
unveilable by the rest of the team. Plus a page serving the current mod and
extension builds.

## Where it lives: inside ai.example.com

Not a new service. `example/ai` already has every part the hard half of this
needs — Entra sign-in, invite-only `invited_users`, group roles, need-to-know
by product, Postgres with backups, nginx, Let's Encrypt, a deploy pipeline —
and all of it is documented in its `docs/access-control.md`. Building a
second service would mean a second app registration, a second certificate, a
second access list to keep in step, and a second place to get it wrong.

So: **a Claudefuscator module inside the existing app**, reusing its
primitives rather than paralleling them.

| This design needs | Reuse from `example/ai` |
|---|---|
| who may sign in | `invited_users`, unchanged |
| what they may do | two new entries in `Roles.All` (`Domain/Access.cs`) |
| which mappings they may read | **`products`**, unchanged — not a new "scope" concept |
| transport, host, database | the existing nginx, cert, Postgres |

Reusing `products` is the important one. `acme`, `widget` and `gadget` already
exist there as units of need-to-know, a group is already granted products,
and `AllProducts` already means "including ones created later". A mapping
simply carries a `product_id`, and the grant logic is the one already
written and tested.

### What consolidation costs

Worth saying plainly rather than discovering later.

**It widens the blast radius.** Today a compromise of `ai.example.com` yields
the indexed corpus. Afterwards it also yields the deanonymisation mapping —
the one artefact that turns every tokenized conversation back into
plaintext. The two are now one target.

That is a real increase, and still the right trade: a second service would
be a second target with less scrutiny, a separate patch cadence and an
access list that drifts out of step with the first. One well-maintained door
beats two, provided the mapping tables get the same care as the corpus and
the product grants are set deliberately rather than left at `AllProducts`.

---

## What makes this different from the AI corpus

Worth stating before the design, because it changes how much the controls
have to carry.

`ai.example.com` serves indexed source code: sensitive, but it is material the
reader could mostly obtain another way if they already work here. **This
service serves the deanonymisation mapping.** It is the one artefact that
turns every tokenized conversation — past and future, on anyone's machine —
back into plaintext. A reader who obtains the whole table retroactively
defeats the tool for everybody.

So two things are stricter here:

- **Need-to-know is per project, not per person's convenience.** Default is
  no mappings, not all of them.
- **Read access is logged per user.** Not for blame, but because "who could
  have read the customer list" is a question that must have an answer.

---

## Two properties that keep the server out of the trust path

These are not copied from `ai.example.com`; they come from this payload.

### 1. The server cannot read anything it stores

Tokens are `HMAC(key, "claudefuscator/v1/TYPE/value")`. The server stores
`token -> sealed value` pairs. It never needs the key to do that, and it is
never given one it can use: a compromised server yields ciphertext, so an
attacker cannot derive tokens for values it has never seen, and projects
whose rows it does not hold are untouched.

Nothing in the schema, the config or the API takes a usable key. If a future
change appears to need one, that is the signal to stop and redesign.

#### The one exception, and what it costs

This section used to be titled "the server never holds the key", and that
was true until browsers had to stop asking people to retype it. `PUT
/api/vault/key` now stores one blob per person:

```
AES-GCM( HKDF-SHA256(that person's API token, info="claudefuscator/enrolment/v1"),
         the Claudefuscator key,
         aad = "claudefuscator/enrolment/v1" )
```

The agent writes it once (`claudefuscator_agent.py --enrol-key`) and verifies
it by reading it back. A browser holding the same API token collects it on
first use, unwraps it in the service worker, and keeps it in
`chrome.storage.session` — memory only, gone when the browser closes.

**What this keeps.** The server stores only `SHA-256` of each API token, so
it cannot derive the wrapping key. A database dump, a backup, a stolen disk
or a read-only SQL injection yields a blob nothing on the host can open. The
row is per owner, served only to its owner, and cannot be overwritten by
anyone else.

**What it gives up, plainly.** An API token arrives in plaintext on every
request. Code execution on the *running* host can harvest one and unwrap
that person's key, and from the key everything else in the vault follows.
That is a real reduction in the worst case, and no arrangement avoids it
once a server distributes keys at all. It is the price of not typing the key
into every browser; if that trade is wrong for a deployment, do not enrol —
nothing else depends on it, and typing the key into the options page still
works.

**What it does not change.** The server still cannot read a value row, still
cannot read the identifier list, and still gains nothing from the wrapped
key by itself. "The server has the key now" is not a true summary of this.

### 2. Clients verify integrity; the server is not trusted for it

The server cannot tell a correct mapping from a poisoned one — checking
would need the key. It does not have to, because **every reader holds the
key**:

```
on reading {token, value}:  recompute HMAC(key, "…/TYPE/value")
                            accept only if it equals token
```

A mapping that fails is discarded and reported, not displayed. That makes a
write from a compromised or buggy client detectable by every reader, and it
means a malicious server cannot make the extension show a value the key does
not vouch for.

The client-side check is the whole reason this service can be ordinary
infrastructure rather than a secret-handling system.

---

## The vault: the server stores ciphertext it cannot read

**Decided: client-side encryption.** Worth doing, and worth doing
client-side rather than as a database feature.

The reason is sharper than "it is sensitive". The vault is not merely as
classified as the repositories it is derived from — it is a *distilled index
of exactly which strings are sensitive*, across every project at once.
GitLab holds identifiers scattered through code that someone has to find;
the vault holds the curated list, already separated from the noise, with the
real value attached. It is a better target than any single repository, and
one table rather than many.

That is the argument for encrypting it client-side, for the resolve-only API
below rather than a bulk export, and for never leaving a group on
`AllProducts` out of convenience.

Disk encryption and Postgres-level encryption protect against a stolen disk
or a leaked backup. They do not protect against the application being
compromised, because the application can read its own database — and the
application is the part exposed to the internet. For this payload that is
the threat that matters.

So: **the client encrypts the value before it ever leaves the machine.**

```
valueKey   = HKDF(claudefuscator key, "claudefuscator/vault/v1")
ciphertext = AEAD(valueKey, value, aad = tokenVersion | product | token)
stored     = token -> ciphertext          (the server sees only this)
```

The server holds rows it cannot interpret. A full compromise of
`ai.example.com` yields ciphertext, and the key is on employees' machines,
never on the host. That is what makes putting this next to the corpus
acceptable rather than merely convenient.

The AAD binds each row to its token, product and token version, so a row
cannot be lifted into another product or replayed under a different token
without the decryption failing.

### What it still does not protect

Say this plainly, because an encrypted store invites over-trust:

- **Metadata is in the clear.** Row count, which products hold how many
  mappings, when they were written, by whom, and each token's TYPE prefix
  (`PERSON_`, `CUSTOMER_`) and frequency. An attacker learns you have 412
  customer names even if they learn no name.
- **Anyone with the key and access reads everything in scope.** Encryption
  is not access control; `invited_users`, roles and product grants still do
  that work.
- **A compromised client is a compromised mapping.** The key is on the
  endpoint, so endpoint security is still the floor.

### Losing the key means losing the mappings

The flip side of a server that cannot read the data is a server that cannot
recover it. If the key is lost, every stored mapping is permanently opaque,
and every token in every archived conversation becomes unresolvable.

That needs a deliberate escrow decision before the first row is written, not
after. The options are an offline copy held by an administrator, a copy in
an existing secrets manager, or accepting the loss — but it has to be a
choice someone made.

### Which clients can encrypt

Here the sandbox limit found while building the mod bites.

| Client | Crypto available | Can write to the vault |
|---|---|---|
| Proxy (Python) | full | yes |
| Chrome extension | full WebCrypto | yes (reads, mainly) |
| **Mod** | `crypto.subtle` present but **no `importKey`** | **no** |

The mod already needs a pure-JS HMAC-SHA256 because the sandbox has no
usable WebCrypto. HMAC is ~80 lines and verifiable against RFC 4231;
hand-rolling an AEAD is a different proposition and not something to do for
a security boundary.

So the mod cannot be a vault writer. Three ways round it, and this is a
decision rather than a detail:

1. **Only the proxy writes.** Simple and safe. Mod-only users contribute no
   new discovered mappings until they run the proxy.
2. **The mod writes plaintext to a local file; a small local uploader
   encrypts and submits.** Keeps mod-only mode contributing, at the cost of
   one more moving part and a plaintext file on disk — which the threat
   model already permits, since local plaintext is not the threat.
3. **Pure-JS AEAD in the mod.** Most capable, least advisable.

## Access control

Three separate questions, three separate places — the same split as
`ai.example.com`, because keeping them apart is what lets each change
independently.

| Question | Decided by | Stored in |
|---|---|---|
| May this person sign in? | the access list | `invited_users` (existing) |
| What may they do? | their group's roles | `role_groups.roles` (existing) |
| Which mappings may they read? | their group's product grants | `role_group_products` (existing) |

Only the last row needs anything new, and only a `product_id` column on the
mappings table.

### Signing in is invite-only

No self-registration, no just-in-time provisioning. Entra proves identity;
it grants nothing. An address not on `invited_users` is redirected to
`/not-invited` and **no user row is created**, so a rejected attempt leaves
a log line and nothing else. The session is re-validated against
`invited_users` on a short interval, so removing someone ends live sessions.

A valid Microsoft work account is not sufficient on its own, and the app
registration's account-type setting is not the only thing between the public
and the mappings.

### Roles

Two new entries in the existing `Roles.All`; the rest already exist.

| Role | Grants | New? |
|---|---|---|
| `ReadMappings` | resolve tokens within the granted products | **new** |
| `WriteMappings` | submit newly discovered mappings | **new** |
| `ManageRepositories` | already governs product assignment | existing |
| `ManageUsers`, `ManageRoleGroups`, `ViewDebug` | unchanged | existing |

Roles come from the group, never from an Entra app role or group claim — the
application reads only claims it wrote itself.

Granting `ReadMappings` should be a deliberate act for every group **except
the built-in super-admin one**, where it is not, and cannot easily be made
so.

Observed in production on 2026-10-03, after deploy: `SuperAdmin` already
held `ReadMappings` and `WriteMappings`. `AccessSeeder` re-grants every role
in `Roles.All` to that group **on every start**, with a sound rationale —
a role added in a later release has to reach the administrators, or an
upgrade leaves them unable to see a new screen and unable to grant
themselves the role that opens it.

The consequence is worth stating rather than discovering: **removing
`ReadMappings` from `SuperAdmin` does not stick.** The next deploy restores
it.

That is defensible — an administrator with `ManageRoleGroups` could grant
themselves the role anyway, so excluding it buys little against anyone
determined — but it does mean the "deliberate grant" property holds for
ordinary groups only. Right now exactly one account is in that group, which
is a reasonable starting state, and the thing to avoid is quietly adding
people to it.

If you want removal to stick, `ReadMappings` has to be excluded from the
seeder's re-grant list, which is a change to `AccessSeeder` and a decision
about whether an administrator may ever be without it. Someone who needs the assistant does not automatically need the
mapping table.

### Need-to-know: products, as they already work

Every mapping carries a `product_id`. Groups are granted products, which is
the mechanism already in place.

Two states that must not be conflated, and the conflation is the mistake
here that fails open:

- `AllProducts = true` → no restriction, including products created later.
- `AllProducts = false` with no grants → **nothing**. Resolution returns empty.

A mapping whose product is unset is readable only via `AllProducts`.
Unassigned is the most restrictive state, so forgetting to classify a new
mapping under-shares rather than over-shares — the same property the corpus
already relies on.

Filtering happens in the query, never after. A resolve request names tokens;
the response contains only those the caller's scopes permit, and says how
many were withheld without saying what they were.

---

## API

All of it behind TLS. Plain HTTP is refused, not redirected — a redirect
still puts the first request on the wire.

| Route | Role | Purpose |
|---|---|---|
| `POST /api/resolve` | `ReadMappings` | `{tokens:[…]}` → `{mappings:{token:value}, withheld:n}` |
| `POST /api/mappings` | `WriteMappings` | submit `{scope, token, value}` pairs |
| `GET /api/products` | any | the products this caller may read |
| `GET /api/vault/stats` | `ReadMappings` | counts and sizes for the rows this caller may read |
| `GET /healthz` | none | liveness only, no data |

**Resolve takes the tokens it needs and never returns the whole table.** A
bulk export is the thing an attacker wants; make it something that has to be
built deliberately rather than a default.

**Stats are scoped the same way the values are.** A count is the metadata
this encryption does not hide — "412 customer names exist" is disclosed by
a number even when no name is — so the figures a caller sees cover only the
products they may read, the response says `partial` when that is a slice,
and the on-disk size is offered only to a caller who may read every row.
Gated on `ReadMappings` rather than an administrative role: whoever may
turn tokens into names is who may see how many there are.

Writes are **write-once per (product, token)**. A conflicting value is
rejected, recorded with the submitting user, and surfaced to an
administrator: under a correct client a token determines its value, so a
conflict means a bug, a key mismatch, or an attempt to poison.

### Key rotation

Mappings are stored against the `tokenVersion` that produced them
(`claudefuscator/v1`). Rotating the key invalidates every token, so rotation
means a new version namespace and the old rows become unreadable rather than
wrong. Never reuse a namespace across keys.

---

## Clients

| Client | Reads | Writes |
|---|---|---|
| Chrome extension | yes, for tokens on the page | no |
| Proxy | optional | yes, discovered pattern hits |
| Mod | no | yes, discovered pattern hits |

The extension needs `host_permissions` for the server's origin and an OAuth
flow, which is the point at which "the extension makes zero network calls"
stops being true. That claim has to be rewritten wherever it appears, not
quietly dropped — see the README.

Until the server exists, the extension keeps working from a pasted list, and
tokens it cannot resolve are marked in red.

---

## What was needed before this could be built

1. ~~An **Entra app registration** with admin approval.~~ **Not needed** —
   superseded by personal API tokens, which already exist. See the note at
   the top.
2. ~~A **DNS name and certificate**.~~ Not needed; it lives inside
   `ai.example.com`, which has both.
3. ~~A **Postgres instance**.~~ Not needed; it is a table in the existing
   database, which already has backups.
4. **Who administers it** — unchanged, and still a decision. `ReadMappings`
   should not be in any default group, so somebody has to grant it
   deliberately.

### Still outstanding before the first real row

The five human steps are written out in
a rollout checklist kept with the
deployment, not here: it names hosts, containers and an access list, which
is exactly the material this repository does not carry.


- **Key escrow (TEST-147).** Decided 2026-10-03: an offline copy held by an
  administrator. Note what it covers. There are two keys, and only one of
  them can be escrowed usefully in a managed store:

  | | Role | Loss means |
  |---|---|---|
  | **Claudefuscator key** | derives tokens; needed on every endpoint, offline, including the mod's sandbox | every token in every archived conversation is unresolvable, and nothing can be verified |
  | **Vault value key** | encrypts stored values; derived from the above | stored pattern hits are lost; list entries are still derivable |

  The Claudefuscator key is the catastrophic one and it cannot live in a
  non-exportable store, because the mod computes HMACs in a sandbox with a
  pure-JS implementation and no network. That is what the offline copy is
  for.

## Open questions

- Should the extension talk to the server directly, or only through the
  local proxy? Going through the proxy means one OAuth client instead of
  two, and the extension keeps a loopback-only origin — but it stops working
  in mod-only mode.
- Should writes require review before becoming readable by others? A wrong
  mapping is visible to everyone in scope until corrected.
- Retention. Mappings do not expire today. A departed customer's identifiers
  probably should.
