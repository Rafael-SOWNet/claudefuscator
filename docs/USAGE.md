# Claudefuscator — usage guide

Practical setup and daily use. For *why* it works this way, see the
[README](../README.md); for the scope boundary, [CLAUDE.md](../CLAUDE.md).

**Pick one mode, never two** — see [Do not run both](#do-not-run-both).

| Mode | Use it when | Section |
| --- | --- | --- |
| **Mod** | you are on Claude Code v2.1.287+ and want one in-process module, no separate server | [§3b](#3b-mod-mode-claude-code-v212287) |
| **Proxy** | you want coverage of the whole request by construction, the local-model fallback, or protection for non-Claude-Code clients | [§3](#3-proxy-mode) |
| **Hooks-only** | you are running neither of the above | [§4](#4-hooks-only-mode-no-proxy) |

Mod mode is the lighter setup; proxy mode is the stronger guarantee. Both
cover the prompt you type, which hooks-only mode cannot.

---

## 0. One-time: requirements

| Need | For | Check |
| --- | --- | --- |
| Python 3.11+ | the proxy | `python --version` |
| Node 18+ | plugin, tooling, tests | `node --version` |
| `requests` | the proxy | `python -c "import requests"` |
| `cryptography` | the agent's vault encryption | `python -c "import cryptography"` |
| an `ai.example.com` API token | the shared vault, optional | set `CLAUDEFUSCATOR_VAULT_TOKEN` |
| Chrome | the extension | — |

```bash
cd /path/to/claudefuscator  # wherever you cloned it
npm install                 # dev tooling only (Playwright, for the browser test)
```

---

## 1. Pick a key

One secret, entered **independently** on every side. It is never transmitted
between them and never sent to Anthropic.

```bash
# any long random string; generate one if you like
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

32 bytes rather than 24 for one reason: everything here is symmetric
(HMAC-SHA256, HKDF-SHA256, AES-256-GCM), so the only quantum attack that
applies is Grover's, which halves the effective strength. 32 bytes leaves
~128 bits against that; 24 leaves ~96. There is no public-key crypto
anywhere in Claudefuscator, so Shor's algorithm has nothing to work on, and
a key generated this way needs no migration plan. An existing 24-byte key
is fine and not urgent to rotate — changing it makes every token in every
archived conversation unrestorable.

Keep it somewhere you can retrieve it (a password manager). If you lose it,
every token already in a conversation becomes unrestorable — the mapping only
ever exists as a derivation from the key.

> Do not paste the key into a chat, a commit, or any file in the repo.
> `.gitignore` covers the obvious filenames, but it cannot save you from
> putting it somewhere unexpected.

### Two ways to run it

Everything below works in either, and you can start local and move later —
the key does not change, so nothing already tokenized breaks.

| | **Local mode** | **Central vault mode** |
|---|---|---|
| Who has the key | you, typed into each side | you, typed into the agent; collected by browsers |
| The identifier list | a file you edit and copy around | published once, fetched by everybody |
| What you need running | nothing | a Claudefuscator server, and the agent for the browser |
| Good for | one person, one machine, trying it out | a team that must hide the same things |

**Local mode** is the default and needs no server. Set `CLAUDEFUSCATOR_KEY`
and `CLAUDEFUSCATOR_CONFIG`, paste the same key and list into the extension,
done. Everything in sections 2–5 applies as written.

**Central vault mode** adds a server so the list is governed in one place
and browsers stop asking people to retype the key. Three steps on top of
local mode:

```bash
# 1. a personal API token, created in the server's UI, kept out of files
export CLAUDEFUSCATOR_VAULT_TOKEN='…'

# 2. publish the list everyone should use (needs the manage-identifiers role)
claudefuscator-agent --publish-identifiers claudefuscator.merged.local.json --version 7

# 3. optional: enrol your key, so your browsers collect it instead of
#    being typed into. Read the trade-off first - docs/UNVEIL-SERVER.md.
claudefuscator-agent --enrol-key
```

and in the config file, the vault's address (the token never goes here):

```json
{
  "identifiers": [],
  "vault": { "enabled": true, "url": "https://ai.example.com", "product": "widget" }
}
```

Step 3 is genuinely optional and separable: without it the server still
governs the list, and each browser still has its key typed in once. With
it, a browser holding your API token collects the key on first use and
keeps it in memory until the browser closes. What that costs is written out
in `docs/UNVEIL-SERVER.md` under "the one exception" — read it before
enrolling, not after.

---

## 2. Configure your words

### Where the files live

| File | Contains | Committed? |
| --- | --- | --- |
| `claudefuscator.local.json` | **your** project config — the main file you edit | no, gitignored |
| `config/claudefuscator.example.json` | annotated template to copy | yes |
| `config/packs/*.local.json` | reusable org vocabulary | no, gitignored |
| `config/packs/example-org.json` | pack shape reference | yes |
| `config/allowlist-nl-en.json` | ~450 ordinary Dutch/English words, never tokenized | yes |

Start here:

```bash
cp config/claudefuscator.example.json claudefuscator.local.json
```

### The four layers

Later layers win over earlier ones.

```
generic patterns  →  packs  →  identifiers  →  allowList
(email, IPs,         (org      (this          (never tokenize,
 MACs, hostnames)     vocab)    project)       beats everything)
```

A minimal `claudefuscator.local.json`:

```json
{
  "tokenLength": 8,
  "internalDomains": ["corp.example", "lan"],
  "packs": ["config/packs/mine.local.json"],
  "allowList": ["kern", "post", "bank"],
  "identifiers": [
    { "type": "PERSON", "value": "Jane Example", "aliases": ["J. Example"] },
    { "type": "HOST",   "value": "build-01.corp.example" },
    { "type": "PRODUCT","value": "WIDGET-800" },
    { "type": "PROCESS","value": "XYZ", "caseSensitive": true },
    { "type": "ORG",    "value": "Acme", "aliases": ["ACME", "acme"], "compound": true }
  ]
}
```

`type` is a free label and becomes the token prefix, so `PERSON` →
`PERSON_7d10f128`. Pick types that make the tokens readable to you.

### Entry options

| Option | Effect | Use for |
| --- | --- | --- |
| *(default)* | case-insensitive; aliases collapse onto one token; restore emits the canonical `value` | people, companies, hostnames |
| `caseSensitive: true` | only this exact casing matches; each spelling gets its own token | short acronyms, so `abc` is left alone while `ABC` is caught |
| `compound: true` | also matches **inside** code identifiers (`Acme` → `AcmeClient`, `ACME_TIMEOUT`). Implies `caseSensitive` and per-spelling tokens so code round-trips byte-exact | a company or product name embedded in a symbol |

> `compound` renames a **label** inside code. It does not hide what the code
> does, and it is not a route to pasting a proprietary module — see the scope
> boundary in [CLAUDE.md](../CLAUDE.md).

### The allow-list matters more than it looks

Org vocabulary collides with ordinary language constantly. *Kern*, *Boring*,
*Post*, *Meet*, *Bank* are real Dutch words **and** plausible product names.
Add one to a pack without an allow-list and every ordinary use gets
tokenized — mangling your text and telling Claude less than nothing.

Pull in the shipped list by referencing it as a pack, or paste its
`allowList` array into your config:

```json
{ "packs": ["config/allowlist-nl-en.json", "config/packs/mine.local.json"] }
```

**Short acronyms are the sharp edge.** `XYZ` will not match inside `XyzTest`
(boundaries handle that), but it fires on every standalone `XYZ` anywhere.
Set `caseSensitive: true`. The merge step warns about any bare term of three
characters or fewer.

### Building a pack from your own repos

There is a bootstrapping problem: the list of terms you want hidden from
Claude is itself sensitive, so having Claude read your repos to build it
sends the whole list to Anthropic in the process.

`harvest-vocab.js` solves that by printing **counts only** — never the terms:

```bash
node tools/harvest-vocab.js ~/git/some-repo "$HOME/OneDrive - Your Org" --min 4

#   scanned   10771 files, 92.1 MB
#   candidates 8522 seen, 200 proposed (min 4 uses, 2+ files)
#     PRODUCT    100
#     TERM       100
#   written   config/packs/harvested.local.json
```

Then **open that file in your own editor** and prune it. Everything in it is
a candidate; the script cannot tell a product name from a word you happen to
use a lot.

#### The heuristics it uses

All local, no model involved. Five signals, in order:

| # | Signal | What it does |
| --- | --- | --- |
| 1 | **shape** | only acronyms (`XYZ`), part codes (`WIDGET-800`, must contain a digit) and — opt-in — PascalCase are considered. Plain lowercase words are never harvested |
| 2 | **stopwords** | `config/allowlist-nl-en.json` plus any `--dict` wordlist, applied per PascalCase part too, so `DataReader` dies while `AcmeReader` survives |
| 3 | **baseline** | terms that also occur in code you did **not** write are generic by definition |
| 4 | **spread** | a term must appear in ≥ 2 files; one file usually means a local variable |
| 5 | **ubiquity** | a term in >50% of files is boilerplate. Only applied once the corpus has ≥ 20 files — below that every real term is in "most" of them |

| Flag | Effect |
| --- | --- |
| `--baseline <dir>` | control corpus; terms seen there are dropped. **The strongest signal available** — point it at a third-party library or `node_modules`. Repeatable |
| `--dict <file>` | extra newline-separated stopword list, e.g. `/usr/share/dict/words` (available in WSL). Removes far more ordinary language than a hand-written list |
| `--min <n>` | minimum occurrences (default 3) |
| `--min-files <n>` | minimum distinct files (default 2) |
| `--max-doc-freq <f>` | drop terms appearing in more than this fraction of files (default 0.5) |
| `--max <n>` | cap on proposals, split evenly per shape (default 400) |
| `--out <f>` | where to write |
| `--symbols` | also propose PascalCase code identifiers. **Off by default** — a codebase is overwhelmingly ordinary class names, which drown out real vocabulary |
| `--print` | also print the terms. **Never use this under an agent** |

A baseline is worth the extra scan. On a real run it removed 179 generic
terms that would otherwise have competed for the proposal budget:

```bash
node tools/harvest-vocab.js ~/git/your-repo   --baseline ~/git/some-third-party-lib   --dict /usr/share/dict/words   --min 4

#   scanned    10771 files, 92.1 MB
#   baseline   3884 files, 323 generic terms excluded
#   candidates 8402 seen, 300 proposed
#   rejected   6346 too rare, 154 single-file, 0 ubiquitous, 179 in baseline
```

The `rejected` line tells you whether your thresholds are sane. Lots of
"too rare" is normal. Lots of "single-file" means the corpus is fragmented.
Lots of "ubiquitous" means you are scanning boilerplate.

> Over-tokenizing costs answer quality directly: every term you add is a term
> Claude can no longer reason about. Prune aggressively.

### Checking your config

```bash
node tools/merge-config.js          # resolves packs, reports warnings
node tools/merge-config.js --stats  # + per-type counts
```

This prints counts and warnings but **not** your vocabulary, so it is safe to
run while Claude is watching. It writes the flattened config to
`claudefuscator.merged.local.json` — that is the file you paste into the
Chrome extension.

---

## 3. Proxy mode

The proxy sits between Claude Code and the Anthropic API, scrubs the whole
outgoing request, and restores the response on the way back. It covers the
prompt you type, `CLAUDE.md`, and compaction summaries — none of which a hook
can reach.

### Start it

```powershell
$env:CLAUDEFUSCATOR_KEY     = "your-key"
$env:CLAUDEFUSCATOR_CONFIG  = "$HOME\git\tokenveil\claudefuscator.local.json"

cd $HOME\git\tokenveil\proxy
python lite_llm_proxy.py
```

```bash
# bash equivalent
export CLAUDEFUSCATOR_KEY="your-key"
export CLAUDEFUSCATOR_CONFIG="$HOME/claudefuscator.local.json"
cd <claudefuscator>/proxy && python lite_llm_proxy.py
```

It must print **`Claudefuscator: ACTIVE (...)`** on startup. `INACTIVE` means
it is relaying unscrubbed.

> **Run it from `proxy/`.** `detect.py` loads `rules.toml` relative to the
> working directory.

### Point Claude Code at it

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude
```

Or use the wrapper, which health-checks the proxy, replaces a stale one, and
cleans up the environment variable on exit:

```powershell
cd $HOME\git\tokenveil\proxy
.\start-claude.ps1              # normal: real Claude, veiled, local fallback on refusal
.\start-claude.ps1 -Bare        # local model only, through the proxy
.\start-claude.ps1 -LocalOnly   # straight to llama-server, no proxy
```

Any other flag (`-p`, `--resume`, …) passes straight through to `claude`.

`start-proxy.ps1` also launches a local llama-server. That script lives
outside this repo; override its location with:

```powershell
$env:CLAUDEFUSCATOR_LOCAL_SERVER = "D:\your\path\start-server.ps1"
```

### Check it is actually on

```bash
curl -s http://127.0.0.1:8090/health
# {"status":"ok","claudefuscator":"ACTIVE (5 list entries; patterns: ...)"}
```

### Environment variables

| Variable | Purpose |
| --- | --- |
| `CLAUDEFUSCATOR_KEY` | the shared key. **Required** — without it the proxy is inert |
| `CLAUDEFUSCATOR_CONFIG` | path to your config. Falls back to `./claudefuscator.local.json`, then `~/.claudefuscator/identifiers.json` |
| `CLAUDEFUSCATOR_WIRE_LOG` | append every outgoing request to this file, to verify what leaves. Delete it afterwards — it is a full copy of the conversation |
| `CLAUDEFUSCATOR_LOCAL_SERVER` | path to the llama-server launcher used by `start-proxy.ps1` |

### What the local model gets

**Real values.** It runs on your machine, so there is nothing to hide from
it, and tokens would only make its answers worse. A `$` prefix forces a
prompt to the local model and nothing goes upstream:

```bash
claude -p '$explain this calibration routine'
```

That is the right tool for work whose substance cannot leave the building.

---

## 3b. Mod mode (Claude Code v2.1.287+)

A single TypeScript module that runs inside Claude Code. No port, no
separate process, no `ANTHROPIC_BASE_URL`, and it works in `claude -p` and
the Agent SDK too.

Verified on Claude Code 2.1.288. Needs **v2.1.287+**, and on this build also
`CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1` — without it the hooks module simply
does not load, and the engine says so.

```bash
claude --version                           # must be >= 2.1.287
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1
export CLAUDEFUSCATOR_KEY="your-key"
export CLAUDEFUSCATOR_CONFIG="$PWD/claudefuscator.local.json"

npm run test:mod                           # validate + 7 engine tests
claude --plugin-dir ./claude-mod           # load it for one session
```

The session's first line must say `Claudefuscator: ACTIVE (...)`.
**`INACTIVE` means nothing is being scrubbed.**

For an interactive session you can set the key through `/config` instead, and
it goes to your OS credential store. It is deliberately not a *required*
field, because a required one fails the load wherever nothing can prompt
(`claude -p`, CI, the Agent SDK). A relative `config_path` resolves against
the **plugin directory**, not the working directory.

### Keeping it scoped

Nothing above installs the mod. It loads only for the session you pass
`--plugin-dir` to, and three things must line up before it does anything:

1. `--plugin-dir ./claude-mod` on that invocation
2. `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1` in that process
3. a key and an identifier config — without them it loads inert and says
   `INACTIVE`

To check what is actually enabled on your machine:

```bash
claude plugin list | grep -i claudefuscator     # expect nothing
```

Two ways it could become global without you meaning it:

- **`CLAUDE_CODE_PLUGIN_DIRS`** loads plugin directories exactly as
  `--plugin-dir` does, for apps you cannot pass a flag to. Putting
  `claude-mod` in it enables the mod everywhere, including sessions you did
  not intend.
- **Exporting `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1` from a shell profile**
  does not load this mod on its own, but it turns mods on generally. Prefer
  setting it per command until you want that.

Installing it properly (`/plugin install` from a marketplace) is a separate,
deliberate step and is not covered here yet.

Two behavioural differences from proxy mode:

- **Your transcript holds tokens, not real values.** The prompt is rewritten
  on the way out and restored only for display. Tokens on disk are not the
  threat, so this is fine — but it is the reverse of proxy mode.
- **Compaction is not covered.** A mod can skip compaction but cannot
  rewrite a summary.

Tool calls still write **real** values to disk: arguments are restored
before the tool runs.

---

## 4. Hooks-only mode (no proxy)

Less coverage: `UserPromptSubmit` cannot rewrite a prompt, so **what you type
is not protected** — you only get a warning.

```bash
claude --plugin-dir ./claude-plugin
```

On first enable Claude Code prompts for two values:

- **Claudefuscator key** — declared `sensitive: true`, so it goes to your OS
  credential store (Credential Manager / Keychain / libsecret), never to
  `settings.json`. This is the only key source with no plaintext key on disk.
- **Identifier list** — path to your `claudefuscator.local.json`.

Every session opens with a status line saying whether scrubbing is on,
because the dangerous failure mode is silence.

`promptPolicy` in your config controls the typed-prompt behaviour:

| Value | Behaviour |
| --- | --- |
| `"warn"` (default) | the identifier **is sent**; you get told afterwards |
| `"block"` | the prompt is rejected before the model sees it, with the tokenized version to paste back |

---

## 5. Chrome extension

claude.ai in the browser talks to claude.ai, not to the Anthropic API, so it
cannot be proxied. The extension restores tokens in the page instead.

### Install

1. `chrome://extensions`
2. Enable **Developer mode** (top right)
3. **Load unpacked** → select `chrome-extension/` in this repo
4. Consider a separate Chrome profile for the first run

The card shows a **service worker** link: that is `background.js`, which is
the only part of the extension allowed to make a network call. Everything
the page itself does is offline.

### Configure

1. Open the extension's **Details → Extension options**
2. **Key** — the same key as the other side. The page shows a truncated
   *fingerprint* so you can confirm both match without displaying the key
3. **Identifier list** — paste the contents of
   `claudefuscator.merged.local.json` (from `node tools/merge-config.js`),
   because the extension cannot read files or resolve packs
4. **Save**. Open claude.ai tabs pick it up without a reload
5. **Test** derives the tokens locally so you can compare them against the
   other side

#### Or: collect both from the server

In central vault mode you leave **Key** empty and fill in **Vault API
token** instead, with the vault's url in the identifier-list JSON:

```json
{ "identifiers": [], "vault": { "url": "https://ai.example.com" } }
```

Press **Collect key and shared list now**. The extension fetches the list
and unwraps the key you enrolled with `--enrol-key`, and holds both in
memory for this browser session — nothing is written to disk, and closing
the browser discards them. The next session collects them again.

A typed **Key** always wins over a collected one, so a filled-in field is
never silently ignored. If collection fails the page says why; it does not
fall back to scrubbing nothing in silence.

### What it does and does not do

- Restores tokens in conversation text, in streamed updates, and inside
  artifacts (including as they re-render).
- **Never** writes into the composer, a textarea, or any editable region —
  restoring a token there would put the real value into the box you are about
  to send.
- Restores pattern matches (an IP or email it was never told about) **only
  if a local agent is configured and running** — on its own the extension
  knows nothing but the values on your list, and marks the rest red.
- Contacts at most two hosts: the loopback agent, for values it cannot
  derive, and your Claudefuscator server, for the shared list and your
  enrolled key. `permissions` is still `["storage"]`; `host_permissions`
  names those origins and nothing else; the only `fetch` lives in
  `background.js`, and it will not call an origin the manifest does not
  list. Every value it gets back is checked against your key before it is
  shown, so neither an agent nor a server can make the page display a value
  your key does not vouch for. A shared list can change *what* is hidden; it
  cannot change where anything is sent.

Stored in `chrome.storage.local` — deliberately **not** `chrome.storage.sync`,
which would upload the key and your real identifiers to a Google account.

> **If artifacts are not restored**, the sandbox origin may have changed.
> Open DevTools, select the artifact iframe, run `location.origin`, and add
> that host to `content_scripts[0].matches` in `manifest.json`.

---

## Do not run both

Scrubbing is idempotent, so nothing breaks — but two layers do the same work
and you get twice the places to look when something is not scrubbed. The
`PostToolUse` hook additionally rewrites tool results **in your local
transcript**, storing tokens where proxy mode would keep real values.

```bash
curl -s http://127.0.0.1:8090/health          # proxy running?
claude plugin list | grep -i claudefuscator   # mod or plugin enabled?
```

Exactly one of those should be true.

---

## Daily use

Once set up, there is nothing to do. Confirm it is on, then work normally:

```bash
curl -s http://127.0.0.1:8090/health | grep -o 'ACTIVE[^"]*'
ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude
```

When you meet a new identifier worth hiding, add it to
`claudefuscator.local.json`, restart the proxy, and re-paste the merged
config into the extension so both sides still agree.

---

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `INACTIVE (no CLAUDEFUSCATOR_KEY set)` | key not exported | set it in the shell that starts the proxy |
| `INACTIVE (no identifier config found)` | config not found | set `CLAUDEFUSCATOR_CONFIG`, or run the proxy from a directory containing `claudefuscator.local.json` |
| `token collision at tokenLength=8` | two values hash to the same short token | raise `tokenLength` **on every side** |
| Tokens visible in the terminal | the proxy is not restoring | check `/health`; confirm `ANTHROPIC_BASE_URL` is set for *that* shell |
| Tokens visible on claude.ai | key or list mismatch | compare the options-page fingerprint with the other side; re-paste the merged config |
| An ordinary word keeps getting tokenized | over-broad entry | add it to `allowList`, or set `caseSensitive` |
| A hostname is missed | not on the list and not under `internalDomains` | add the domain to `internalDomains`, or the host to `identifiers` |
| `400 claudefuscator_scrub_failed` | the veil could not parse a request and refused to forward it | this is fail-closed working; check the proxy output |
| `FileNotFoundError: rules.toml` | proxy started from the wrong directory | run it from `proxy/` |
| `hooks: Invalid input: expected record, received undefined` on `claude plugin validate ./claude-mod` | Claude Code older than v2.1.287 does not understand a mod's `modules` key | update Claude Code |
| Mod loaded but nothing is scrubbed | the session's first line said `INACTIVE` | set the key and config path in the plugin's prompts |
| Code comes back with wrong casing | a `compound` spelling was not listed | add that exact spelling to `aliases` |

---

## Verifying it for yourself

Do not take the above on trust:

```bash
npm test          # JS core + cross-language vectors
npm run test:py   # Python core, veil layer, proxy integration
npm run e2e       # headless browser, real extension
npm run test:all
```

Per-surface verification notes, with commands that prove each claim:
[proxy](../proxy/TESTING.md) · [plugin](../claude-plugin/TESTING.md) ·
[extension](../chrome-extension/TESTING.md).
