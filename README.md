# Claudefuscator

Keeps incidental identifiers — names, hostnames, internal IPs, email
addresses — out of what reaches Anthropic, and puts them back locally.

**Tokens are a wire format, not a storage format.** Only what crosses the
network is obfuscated. Your terminal shows real values, and tool calls write
real values to local disk and local shares.

Three surfaces, one shared key, entered independently on each. The key is
never transmitted between them, never sent to Anthropic, and never committed.

```
       your machine                                          Anthropic
 ┌─────────────────────────────────┐
 │ you type: ssh build-01.corp.example│
 │              │                  │
 │          proxy scrub            │
 │              ▼                  │
 │   "ssh HOST_c400a844"          ─┼────────────────────────▶  model
 │                                 │                             │
 │          proxy restore        ◀─┼─────────────────────────────┘
 │              ▼                  │     tokens only, both ways
 │ you read: build-01.corp.example    │
 │ disk gets: build-01.corp.example   │
 └─────────────────────────────────┘

 ┌─────────────────────────────────┐
 │ claude.ai in Chrome             │   cannot be proxied: the web app
 │ page text: HOST_c400a844        │   talks to claude.ai, not the API
 │          content script         │
 │              ▼                  │
 │ you read: build-01.corp.example    │
 └─────────────────────────────────┘
```

## Scope boundary

**Only for incidental identifiers in content that is otherwise fine to send to
Claude** — a support ticket that happens to mention a customer's name, an
internal hostname in a config snippet.

**Not a way to make proprietary content sendable.** Firmware logic,
calibration algorithms, trade secrets: that content's *substance* is the
secret, not the labels on top of it. Tokenizing identifiers does not
declassify it. For work whose substance cannot leave the building, the answer
is self-hosting a model. Full statement in [CLAUDE.md](CLAUDE.md).

## Three modes — pick one, never two

| Mode | Covers | Needs |
| --- | --- | --- |
| **Mod** (`claude-mod/`) | typed prompt, system prompt, `CLAUDE.md`, skills, tool calls, display | Claude Code **v2.1.287+**. One in-process TS module, no separate process |
| **Proxy** (`proxy/`) | the entire `/v1/messages` body, by construction | Python 3.11+, a running process on :8090 |
| **Hooks-only** (`claude-plugin/`) | tool calls and display only | nothing extra |

The mod is the better default once you are on a recent enough Claude Code:
no port, no startup order, no `ANTHROPIC_BASE_URL`, and it works in
`claude -p` and the Agent SDK. The proxy keeps two advantages — its coverage
is *structural* rather than enumerated, and it is the only one that also
protects non-Claude-Code API clients and carries the local-model fallback.

> **Correction.** Earlier versions of this README said typed prompts,
> `CLAUDE.md` and compaction were structurally unreachable and a proxy was
> the only answer. That is true of **settings hooks** — the hooks reference
> says a `UserPromptSubmit` hook *"can't replace the prompt"* — but **mods**
> are a different mechanism that can. The claim was too broad.

### Proxy mode

> Part of `proxy/` is vendored from `local-ai-proxy`, by the same author and
> also MIT. `proxy/NOTICE` records which files came from where, because
> `tools/patch-proxy.py` can replace a vendored file wholesale and cannot
> replace one of ours.

> **Kept for reference; not the path to start on.** The proxy existed
> because it was the only mode that could reach a typed prompt, `CLAUDE.md`
> and compaction. Mod mode now reaches the first two and compaction was
> measured not to leak, so the gap that justified running a proxy in front
> of every request has closed. It is not deprecated and it still works —
> it is simply no longer the obvious choice for a Claude Code user.
>
> Three things still only it can do, and the last is not a leftover:
>
> - **Clients that are not Claude Code.** A mod only exists inside Claude
>   Code; anything else speaking to the Anthropic API has no other option
>   here.
> - **The local-model fallback.** A `$`-prefixed prompt is routed to a
>   local model with real values and nothing goes upstream. That is the
>   honest answer for work whose substance cannot leave the building, and
>   it is the thing to point at when someone asks this tool to do more than
>   it should.
> - **Measuring what actually left the machine.** Configured inert — empty
>   identifier list, every pattern off — it becomes a passive wire tap that
>   records verbatim what some *other* mode produced. That is how mod mode
>   was verified and how the compaction question was settled, and no other
>   component can do it, because a thing cannot audit itself.

A local HTTP proxy between Claude Code and the Anthropic API. It sees the
entire `/v1/messages` body, so it covers everything.

| Path | Covered |
| --- | --- |
| The prompt you type | **yes** |
| `CLAUDE.md` and loaded instructions | **yes** |
| Compaction summaries | **yes** |
| Tool results (file reads, bash, grep, MCP) | **yes** |
| Assistant replies, restored on the way back | **yes** |
| Tool-call inputs, restored before execution → **real values on disk** | **yes** |

### Mod mode

One TypeScript module running inside Claude Code. It rewrites at a dozen
specific events rather than at one request body:

| Path | Event |
| --- | --- |
| The prompt you type | `prompt.submit` → `next({...e, text})` |
| System prompt sections | `prompt.section` |
| First-message context and the loaded instruction files, where `CLAUDE.md` arrives | `prompt.context` (`blocks[].text` **and** `instructionFiles[].content`) |
| Skill text, Claude Code's own reminders | `skill.prompt`, `prompt.attachment` |
| Tool arguments, restored so disk gets real values | `tool.call` |
| Tool results, scrubbed before Claude reads them | `tool.call` |
| Real values back on screen | `ui.render` |

Two differences from proxy mode worth knowing:

- **The transcript holds tokens, not real values.** `prompt.submit` rewrites
  the stored prompt, and `ui.render` restores it only for display. Harmless
  — tokens on disk are not the threat — but it is the opposite of proxy mode.
- **Compaction is covered**, though not by rewriting. A mod cannot rewrite a
  summary (`session.compact` accepts only `{ skip: reason }`), but the
  summarizer reads the conversation *as the model saw it* — already
  tokenized — so the summary comes back in tokens. Measured: 12 requests,
  5.4 MB, one confirmed compaction, zero real identifiers.

**Status: verified on Claude Code 2.1.288.** `claude plugin validate` passes,
`claude plugin test` runs 11 tests against the engine itself, and two live
`claude -p` runs confirmed both a typed prompt and `CLAUDE.md` content
reaching the model tokenized:

```
you type : deploy DEV-100-000123 to build-01.corp.example for Jane Example
model got: deploy SERIAL_10099796 to HOST_b6812726 for PERSON_bc09b0fa

asked to quote its own project instructions, the model answered
  (`PERSON_bc09b0fa`, `example.com`)
where the file actually reads
  (`Jane Example`, `example.com`)
```

Needs `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1` on this build. See
[claude-mod/TESTING.md](claude-mod/TESTING.md).

> **A mod has no usable WebCrypto.** Its sandbox exposes a `crypto.subtle`
> with no `importKey`, so the shared core carries a pure-JS HMAC-SHA256 and
> falls back to it. Both implementations are asserted equal over every
> committed vector and an RFC 4231 known-answer — without that, the mod and
> the extension would derive different tokens and restore would silently
> fail. The documented claim that `crypto.subtle` is available did not hold,
> and only running the mod showed it.

### Hooks-only mode

Settings hooks, for when you are running neither of the above. Strictly less
coverage, because of a documented limitation: `UserPromptSubmit`
*"can't replace the prompt; it only injects `additionalContext` alongside
it."*

| Path | Covered |
| --- | --- |
| Tool results | yes, `PostToolUse` → `updatedToolOutput` |
| Tool arguments containing tokens | yes, `PreToolUse` → `updatedInput` |
| Assistant text on screen | yes, `MessageDisplay` → `displayContent` |
| The prompt you type | **no** — detect and warn only |
| `CLAUDE.md`, compaction summaries | **no** |

**Do not run two of them.** Scrubbing is idempotent so nothing breaks, but
you get two layers doing the same work and twice the places to look when
something is not scrubbed. The `PostToolUse` hook additionally rewrites tool
results *in your local transcript*, storing tokens where proxy mode would
keep real values.

## What is still not protected, in either mode

- **The claude.ai composer.** The extension deliberately never writes into
  editable regions — restoring a token there would put the real value into the
  box you are about to send. Nothing stops you typing a real hostname into
  claude.ai yourself.
- **Equality and frequency.** Stable tokens mean the same value always maps to
  the same token, so it is visible that some value occurs nine times — just
  not what it is. Inherent to the requirement, not a bug.
- **Anything not on your list and not matched by a pattern.** Coverage is what
  you configure.
- **Pattern matches cannot be restored by the Chrome extension.** It only
  knows the values on the shared list. The proxy and terminal can.

## How tokens work

```
token = TYPE_<first 8 hex of HMAC-SHA256(key, "claudefuscator/v1/TYPE/normalised-value")>
```

Stable, key-dependent, and length-hiding. Critically, **one-way**: a token
cannot be decrypted. Each side restores by recomputing the HMAC over the
identifier list it already holds, which is why the same list goes into every
side and why no mapping is ever transmitted.

Aliases collapse onto the canonical entry's token, so restore emits the
canonical spelling — round-tripping preserves the *value*, not the exact
bytes, wherever aliases are involved.

A truncated HMAC can collide, which would make restore ambiguous, so a
collision is a **hard error** at config-load time on every side. Raise
`tokenLength` if you hit one.

### Four implementations, one wire format

`shared/claudefuscator-core.js` is canonical. It is byte-copied into the
plugin and the extension (`tools/sync-core.js`), and hand-ported to Python for
the proxy (`proxy/claudefuscator_core.py`).

A byte-copy cannot work across languages, and the mod additionally takes a
**pure-JS HMAC** path because its sandbox has no usable WebCrypto. So the
guard is `shared/test-vectors.json` — a fixed key and value set with expected
outputs — asserted by the JS suite, the Python suite, and the mod's own
engine test, with the two HMAC implementations checked against each other and
against RFC 4231. If any of them disagree, something goes red.

### What counts as an identifier — four layers

| Layer | What it is | Precedence |
| --- | --- | --- |
| **generic** | Built-in regex: `email`, `privateIp` (RFC1918 + CGNAT + link-local; public and loopback deliberately untouched), `mac`, `internalHost` | lowest |
| **packs** | Reusable vocabulary: company, product, part and process names. The terms that are the same across every project at one employer. `config/packs/*.local.json` | ↓ |
| **identifiers** | This project's own list | ↓ |
| **allowList** | Never tokenize these, whatever matched them | **highest** |

`packs` and `identifiers` resolve into one flat list before anything is
tokenized (`shared/config-merge.js`, mirrored in `proxy/config_merge.py`).
The proxy and plugin do it themselves; for the extension, run
`node tools/merge-config.js` and paste the flat result into its options page.

**No person-name detection by design.** Heuristic name matching mangles code
identifiers and misses real names; a scrubber that silently misses a name
while looking like it caught one is worse than one whose coverage you can
enumerate. Names go on the list.

#### The allow-list is not optional in practice

A personal filter is built from vocabulary, and vocabulary collides with
language. *Kern*, *Boring*, *Post*, *Meet*, *Bank* are ordinary Dutch words
**and** plausible product names. Add one to a pack without an allow-list and
every ordinary use of it gets tokenized — mangling your text and telling
Claude less than nothing. `config/allowlist-nl-en.json` is a starting set of
common Dutch and English words; it wins over patterns *and* identifiers.

Short acronyms are the sharp edge. `XYZ` will not match inside `AcmeTest`
(boundaries handle that) but it will fire on every standalone `XYZ` anywhere.
Set `caseSensitive: true` so only the exact casing matches. The merge step
warns about any bare term of three characters or fewer.

#### Code identifiers

`compound: true` also matches **inside** a code identifier, so `Acme` hits in
`AcmeClient`, `ACME_TIMEOUT` and `acme_x`. It implies `caseSensitive` and
gives **each spelling its own token**, so code round-trips byte-exact instead
of being case-folded — without that, `ACME_TIMEOUT` comes back as
`Acme_TIMEOUT`, a different symbol, silently breaking the file. List every
spelling you want hit; unlisted ones are left alone.

This renames a **label** inside code. It does not hide what the code does —
see [the scope boundary](#scope-boundary).

#### Building a pack without leaking it to Claude

There is a bootstrapping problem: the list of terms you want hidden from
Claude is itself sensitive, so asking Claude to read your repos and build
that list sends the whole list to Anthropic in the process.

`tools/harvest-vocab.js` scans local directories and proposes candidate
vocabulary, printing **counts only** — never the terms — and writing them to
a gitignored file for you to prune in your own editor:

```bash
node tools/harvest-vocab.js ~/git/some-repo ~/OneDrive/docs --min 4
#   scanned   10771 files, 92.1 MB
#   candidates 8522 seen, 200 proposed
#     PRODUCT    100
#     TERM       100
#   written   config/packs/harvested.local.json
```

PascalCase code identifiers are **off** by default (`--symbols` to include
them): a codebase is overwhelmingly ordinary class names, which drown out
real vocabulary. There is a `--print` flag; do not use it under an agent.

**Everything proposed is a candidate.** Over-tokenizing costs answer quality:
every term you add is a term Claude can no longer reason about.

## Layout

```
claudefuscator/
├── CLAUDE.md                      scope boundary + standing rules
├── shared/
│   ├── claudefuscator-core.js     canonical tokenizer (edit here only)
│   └── test-vectors.json          cross-language parity contract
├── tools/                         sync-core, gen-vectors, patch-proxy
├── test/                          JS suite (node --test)
├── proxy/                         vendored local-ai-proxy + the veil layer
│   ├── veil.py                    scrub request / restore SSE response
│   ├── claudefuscator_core.py     Python port of the tokenizer
│   ├── lite_llm_proxy.py          the server (patched by tools/patch-proxy.py)
│   └── TESTING.md
├── claude-mod/                    mod mode (Claude Code v2.1.287+)
│   ├── hooks/register.js          event wiring
│   ├── hooks/veil.js              the pure, testable part
│   └── TESTING.md
├── claude-plugin/                 hooks-only mode
│   └── TESTING.md
├── chrome-extension/              claude.ai restore side (MV3)
│   └── TESTING.md
├── agent/                         loopback unveil service (see below)
│   └── claudefuscator_agent.py
├── server/                        reference vault (ASP.NET Core + SQLite)
│   └── README.md                  why a second implementation exists
└── e2e/                           headless browser test of the extension
```

### The local agent

One loopback service on `127.0.0.1:8091` that the mod, the extension and the
proxy all resolve tokens through. It exists so there is **one** place that
holds the key and, later, **one** client of the shared vault:

```
mod   --+   x-claudefuscator-auth: HMAC(key, "claudefuscator/mappings/v1")[:32]
ext   --+-> agent (127.0.0.1) ----- TLS + Entra ----> shared vault
proxy --+       holds key, does crypto
```

It is a separate process rather than an endpoint on the proxy because it has
to work in mod-only mode, where no proxy runs, and because the mod's sandbox
cannot encrypt for the vault — the agent does that on its behalf.

```bash
CLAUDEFUSCATOR_KEY=... CLAUDEFUSCATOR_CONFIG=... python agent/claudefuscator_agent.py
```

| Route | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | up, and how many mappings — never which |
| `POST /resolve` | header | the tokens you ask about, and only those |
| `POST /mappings` | header | submit discovered values, write-once |

There is deliberately **no bulk export**, and no CORS header is sent, so a
page may send a request but can never read the response.

#### Checking two copies are the same key

```bash
python agent/claudefuscator_agent.py --fingerprint
# key fingerprint: 5b5d91b5  (claudefuscator/v1)
```

Escrow raises a question nobody can answer by looking: is the sealed copy
the key actually in use? Comparing the keys means both parties revealing
them to each other, which is how a copy ends up pasted into a chat window.

The fingerprint is an HMAC over a fixed label, truncated. Derived from the
key, so it differs if one character does; one-way, so it discloses
nothing; stable, so two people in different rooms can read eight
characters to each other. It is deliberately **not** the value the agent
authenticates with — printing that would be printing a credential rather
than a checksum, and there is a test for the distinction.

#### The shared vault

The agent resolves from the local list, then a plaintext cache at
`~/.claudefuscator/discovered.json`, then — if configured — the shared vault
inside `ai.example.com`, so a value a colleague's machine discovered resolves
on yours.

```json
{ "vault": { "url": "https://ai.example.com", "product": "Widget" } }
```

```bash
export CLAUDEFUSCATOR_VAULT_TOKEN=aiplatform_pat_...   # never in the config file
```

The credential is a personal API token you create after signing in to
`ai.example.com` normally — not an Entra client of Claudefuscator's own. The
server resolves it to the same claims and the same `invited_users` lookup
the browser uses, so removing someone from the access list stops their agent
too. It is read from the environment because a config file is shared, diffed
and sometimes pasted.

Four properties, all tested:

- **The server never holds the key.** Values are sealed on this machine
  before they leave it; the server stores a token, a nonce and ciphertext,
  and nothing in its schema or API takes a key.
- **The server is not trusted to be right.** Every row that comes back is
  opened under your key *and* then checked by re-deriving its token. A row
  that decrypts cleanly but does not hash back is refused — a writer holding
  the key can seal a wrong value, and only this check catches that.
- **Local wins.** A vault row never displaces a value this machine derived
  or discovered itself.
- **It fails soft.** An unreachable vault costs red marks in the browser,
  never a broken agent, and anything already cached keeps resolving — which
  is why the host's out-of-hours downtime is tolerable.

`https` is required; only loopback may be plain, for exercising a local
server.

#### Seeing what the vault holds

`https://ai.example.com/admin/vault`, or `GET /api/vault/stats`: mapping
count, payload and on-disk size, contributors, and a breakdown by product
and token type. Nothing there decrypts anything.

The figures are **scoped to what you may read**, and that is deliberate
rather than incidental. A count is the one thing this encryption does not
hide — "412 customer names exist" is disclosed by a number even when no
name is — so a global total would hand every reader the disclosure the
design is careful about everywhere else. The response says `partial` when
you are seeing a slice, and on-disk size is shown only to someone who may
read every row.

The server side is merged (`d5f82ac`) and deployed. See
`docs/UNVEIL-SERVER.md` for the design.

#### Pointing the mod at it

Opt-in, by one key in your config. Absent means off, and the mod behaves
exactly as it did before:

```json
{ "agent": { "url": "http://127.0.0.1:8091" } }
```

The mod then hands the agent each **pattern hit** it discovers — an IP, a
MAC, an internal hostname — so the browser can unveil values that are on
nobody's list and that it therefore cannot derive. List entries are not
sent: both sides already derive those from the key and the same list, so
putting them on the wire would buy nothing.

Three properties of that submission are deliberate:

- **The URL must be loopback.** A config naming any other host is refused
  and logged, not honoured. An agent URL pointing off the machine would ship
  the real values to it, which is the one thing this tool exists to prevent.
  The shared vault is reached *by* the agent, never from the mod.
- **It is fire-and-forget.** `$.http.fetch` has no timeout, so awaiting it
  would let a wedged agent hang your prompt. A late mapping costs a red
  highlight until the next flush; a prompt that never returns costs the
  session.
- **A missing agent is reported once per session, not once per prompt.** An
  agent that is simply not running is the normal case in mod-only mode, and
  a warning every turn trains people to ignore Claudefuscator's output.

`claude plugin validate` lists the call, so the network access is visible to
anyone auditing the mod rather than buried in the source:

```
./register.js calls: $.env.get (via load), $.fs.read (via load),
                     $.http.fetch (via scheduleFlush), $.session.cwd (via load), $.ui.log
```

## Install

```bash
claude plugin marketplace add Rafael-SOWNet/claudefuscator
claude plugin install claudefuscator@claudefuscator
```

`claudefuscator-hooks@claudefuscator` is the hooks-only plugin, for a Claude
Code older than 2.1.287. It covers tool output and **cannot rewrite a prompt
you type** — in that mode an identifier you type yourself is sent.

Updating is one command and never silent:

```bash
claude plugin marketplace update claudefuscator
claude plugin update claudefuscator      # takes effect on restart
```

**The extension is the part that does not update itself.** Loaded unpacked,
it never will: pull and press reload on `chrome://extensions`. That matters
more than it sounds, because a stale extension fails in the quiet
direction — it keeps restoring everything it already knows and marks newer
tokens red, so nothing looks broken. Reload it before suspecting the vault.

## Setup

```bash
cp config/claudefuscator.example.json claudefuscator.local.json   # gitignored
```

The key does **not** go in that file.

**Proxy mode:**

```bash
cd proxy
export CLAUDEFUSCATOR_KEY="your-key"
export CLAUDEFUSCATOR_CONFIG="../claudefuscator.local.json"
python lite_llm_proxy.py            # prints ACTIVE/INACTIVE on startup

ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude
```

**Hooks-only mode:** `claude --plugin-dir ./claude-plugin`. The key is declared
`sensitive: true` so Claude Code stores it in your OS credential store, not in
`settings.json` — the only source with no plaintext key on disk.

**Chrome extension:** not installed anywhere yet. `chrome://extensions` →
Developer mode → Load unpacked → `chrome-extension/`. Enter the same key and
list in the options page; it shows a key *fingerprint* so you can confirm both
sides match without displaying the key. Stored in `chrome.storage.local`,
never `chrome.storage.sync`, which would upload the key to a Google account.

## Testing

```bash
npm test          # JS core + parity vectors          (110 tests)
npm run test:py   # Python: proxy, veil, agent, vault  (185 passed, 2 xfailed)
npm run e2e       # headless browser, real extension  (20 checks)
npm run test:all  # all three
npm run test:server # reference vault server (needs the .NET SDK; not in test:all)
```

Per-surface verification notes, with commands:
[proxy](proxy/TESTING.md) · [plugin](claude-plugin/TESTING.md) ·
[extension](chrome-extension/TESTING.md).

## Status

Verified end to end on 2026-10-02:

- **Real Claude Code through the proxy to the real API.** The typed prompt
  `deploy DEV-100-000123 to build-01.corp.example for Jane Example` left as
  `deploy SERIAL_b3a7d66e to HOST_c400a844 for PERSON_f8e0d978`; the reply came
  back with real values in the terminal; **no real identifier appeared
  anywhere in 261 KB of wire traffic**. Extra `HOST_*` and `EMAIL_*` tokens
  showed up from `CLAUDE.md` and session context being scrubbed too — the
  coverage hooks cannot reach.
- **Headless browser, real extension, 20/20 checks**: restore in conversation
  text, in streamed `characterData` mutations, and inside a sandboxed
  opaque-origin artifact iframe including in-place updates; composer,
  textarea, input and `role=textbox` all correctly left alone; token-shaped
  text untouched; both highlight rules injected; a pattern hit resolved
  through a stand-in agent; a **poisoned mapping refused** rather than
  displayed; and the agent the only host contacted.
- `claude plugin validate ./claude-plugin` passes; the mod passes
  `claude plugin test` with 11 tests against the engine itself.

> **The zero-network claim is gone, as predicted, and here is what replaced
> it.** Resolving values the extension cannot derive means asking something.
> The extension now contacts exactly one host — the loopback agent named in
> its own `host_permissions` — through a background worker that is its only
> `fetch`. `permissions` is still `["storage"]`. Two things keep this
> narrow: `background.js` derives the hosts it may reach *from the
> manifest*, so config cannot widen them, and the content script verifies
> every returned value against the key before showing it, so the agent is a
> source and not an authority. See
> [docs/UNVEIL-SERVER.md](docs/UNVEIL-SERVER.md).

The local agent carries 67 tests of its own, run by `npm run test:py`. Those
cover what it refuses — no bulk export, no CORS header, no answer without the
auth header, write-once on conflict — and that it derives the same tokens as
the other four implementations.

**The mod's client to it is verified against real processes**, on 2026-10-03:
the real `register.js`, given a real `$.http.fetch`, scrubbed
`box 10.44.2.9 and mac 02:42:ac:11:00:02 are down` to
`box IP_321eac62 and mac MAC_3cbd5b8a are down`, submitted both discovered
pairs to a running agent, and the agent then resolved both — and answered
403 to the same request without the auth header. That was a hand-run
integration check, not part of `npm run test:all`, which covers the same
paths against a fake `$.http.fetch` (12 tests).

**The extension's client is covered by the browser E2E**, against a
stand-in agent rather than the real one: the real `background.js` and
`content.js`, in a real browser, resolving a token nothing on the list
derives, refusing a poisoned one, and contacting no other host.

**Verified against the live vault on 2026-10-03.** `tools/verify-vault-live.py`
run against the deployed `https://ai.example.com`: the personal API token was
accepted, a value sealed on this machine was stored, read back out of
Postgres, decrypted and confirmed to hash back to its token; a second write
was refused as a conflict; and a different key could not read the row.
8/8. Inspecting the row directly showed ciphertext only — the plaintext
appears nowhere in the column, which is the claim the client cannot make
about itself. Test row deleted afterwards; the vault holds nothing.

**The server side is also proven over real HTTP**, not just at the store:
9 endpoint tests in `example/ai` drive the real authentication pipeline with
a real bearer token — no token, a made-up token, `WriteMappings` alone
refused a read, and the **JSON field names this repo's agent parses pinned
by name**, because the two sides are configured independently and nothing
but a test holds them together. That run also found a pre-existing bug in
`ai.example.com`: `UseStatusCodePagesWithReExecute` was rewriting every
refused API POST into `400 The request has an incorrect Content-type.`
Fixed in the same branch.

**The vault round trip is covered by 18 tests** against a stand-in server,
including that a poisoned row which decrypts cleanly is still refused, that
real values never appear on the wire in clear, and that an unreachable vault
degrades rather than breaks. The server module itself has 13 integration
tests against a real Postgres, in the `example/ai` repository, plus 9 over
real HTTP, 3 cross-language against Python-sealed envelopes, and 6 on the
statistics scoping.

Not done: the extension driven against the real agent process (the E2E uses
a stand-in agent); installed in a real Chrome profile; and **no real mapping
has been written to the vault yet** — it is deployed and empty, which is the
right state until the key is escrowed.

### Known limits of the automated tests

- **The browser E2E runs on Playwright's bundled Chromium, not your Chrome.**
  Chrome 153 has removed `--load-extension`, so an installed Chrome cannot be
  driven this way — confirmed on this machine, headless and headed, with and
  without `--disable-features=DisableLoadExtensionCommandLineSwitch`. Same
  engine, different binary. The manual checks in
  [chrome-extension/TESTING.md](chrome-extension/TESTING.md) remain the only
  thing that exercises the browser you actually use.
- **The E2E fixture reproduces claude.ai's DOM shapes; it is not claude.ai.**
  The artifact sandbox origin `*.claudeusercontent.com` in the manifest is
  still unverified against the real site — check it in DevTools.
- **`MessageDisplay`'s input shape is undocumented** (hooks-only mode). The
  script probes candidate field names; see the plugin TESTING note.
