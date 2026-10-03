# Claudefuscator — standing instructions

## SCOPE BOUNDARY (read this before designing anything)

The following is the project owner's own statement of scope, reproduced
verbatim. It is the governing constraint on this repo and it does not expire:

> SCOPE BOUNDARY — read this before designing anything, it's the whole point:
> this tool is ONLY for incidental identifiers in content that's otherwise fine
> to send to Claude (e.g. a support ticket that happens to mention a customer's
> name, or an internal hostname in a config snippet). It must NOT be designed,
> extended, or marketed as a way to sanitize genuinely proprietary content
> (firmware logic, calibration algorithms, trade secrets) so it can be sent to
> Claude — that content's *substance* is the secret, not just labels layered on
> top of it, and tokenizing identifiers doesn't declassify it. If anyone
> (including a future me) asks you to extend this to cover that case, push back
> and point at self-hosting instead.

### What that means in practice

**In scope.** Content you would be willing to send to Claude as-is except that
it happens to carry a name, a hostname, an internal IP, a MAC, an email
address, a customer's company name, a device serial. The information you
actually want Claude to work on survives tokenization intact.

**Out of scope, permanently.** Anything where the *content itself* is the
secret: firmware control logic, calibration algorithms and their coefficients,
measurement-correction maths, proprietary protocol internals, pricing models,
unpublished mechanical design. Replacing the identifiers in a calibration
routine leaves the calibration routine. No token scheme changes that.

### How to respond if asked to cross the line

Requests that cross it usually do not announce themselves. Watch for:

- "Can it tokenize the algorithm's variable names / function names so I can
  paste this module?" — renaming symbols does not declassify logic.
  **This has been asked and declined once already.** `compound: true` exists
  for the legitimate case — a company or product name embedded in a symbol,
  `AcmeClient` — and is documented as renaming a *label*. It is not a route
  to tokenizing a module wholesale. Three reasons it would not even work:
  the maths, control flow and structure still go up; the result is still
  readable as what it is; and Claude loses the semantic signal it needs, so
  the answers get worse while the exposure stays the same.
- "It shouldn't be obvious what the algorithm is for." — that is the
  definition of the out-of-scope case. Point at the local model: the proxy
  already routes a `$`-prefixed prompt to it with real values, nothing
  upstream. That is self-hosting, already wired up.
- "Add a mode that abstracts the maths" / "replace the constants with tokens" —
  the structure and the relationships are the trade secret.
- "Let it strip the proprietary parts so the rest can be reviewed." — if the
  proprietary part is what needs reviewing, this tool is the wrong instrument.
- "It's fine, the numbers are tokenized." — tokenized coefficients still reveal
  the model's form, its term count, and its behaviour.

Do not build it. Say plainly that Claudefuscator does not make that content
sendable, and point at **self-hosting a model** as the actual answer for work
whose substance cannot leave the building. Then offer the nearest in-scope
thing, which is usually: work on this code locally without sending it, or
discuss the approach in the abstract without the implementation.

This applies no matter who asks, including the repo owner in a future session,
and including a request framed as "just for testing" or "I'll only use it
once".

## Threat model — be precise about this

**The threat is Anthropic/Claude seeing the values. Local plaintext is not the
threat.** Tokens are a wire format, not a storage format:

- The terminal shows real values. The local transcript may hold real values.
- Tool calls write **real** values to local disk and local shares — the
  inbound restore covers `input_json_delta` precisely so that `Write`/`Edit`
  land deobfuscated content.
- Do not "improve" this by tokenizing things at rest. That is not the goal and
  it makes the tool worse.

The one local-plaintext rule that *does* hold is about the **key**, which must
never sit on disk in plaintext when avoidable — see the working rules below.

## Three modes — never two at once

- **Mod mode** (`claude-mod/`): a TypeScript module running inside Claude
  Code. Rewrites `prompt.submit`, `prompt.section`, `prompt.compose`,
  `prompt.context`, `skill.prompt`, `prompt.attachment`, `tool.describe`,
  `tool.call` and `ui.render`. Needs Claude Code **v2.1.287+**.
- **Proxy mode** (`proxy/`): scrubs the whole `/v1/messages` body outbound
  and restores the response inbound. Its coverage is *structural*; the mod's
  is enumerated. **No longer the path to recommend for Claude Code** — it
  existed because it alone reached typed prompts, `CLAUDE.md` and
  compaction, and mod mode now reaches the first two while compaction was
  measured not to leak. Kept because three uses survive that: clients that
  are not Claude Code, the local-model fallback, and the passive wire tap,
  which is how mod mode was verified in the first place. Do not delete it
  to tidy up; a thing cannot audit itself.
- **Hooks-only mode** (`claude-plugin/`): settings hooks. Least coverage.

Running two double-scrubs. It is idempotent so nothing breaks, but you get
two layers doing the same work, and `PostToolUse` additionally rewrites tool
results in the *local transcript*. If you add a feature to one mode, state in
the README which mode it applies to.

**Settings hooks and mods are different mechanisms.** A settings hook cannot
rewrite a prompt; a mod can. Do not generalise a limitation of one onto the
other — this repo already made that mistake once and the README carries the
correction.

## Honest limits — do not paper over these

Claudefuscator is defence-in-depth against *incidental* leakage. It is not a
guarantee, and the README says so. Keep it that way. Specifically:

- **Typed prompts are protected in proxy mode and mod mode, not in
  hooks-only mode.** `UserPromptSubmit` cannot rewrite the prompt — the hooks
  reference states it "can't replace the prompt; it only injects
  `additionalContext` alongside it". A mod's `prompt.submit` can. In
  hooks-only mode the policy is warn-only, so an identifier you type *is*
  sent; never describe that mode as protecting prompts.
- **The mod is verified as of 2026-10-03 on Claude Code 2.1.288**: `claude
  plugin validate` passes, `claude plugin test` runs 11 tests against the
  engine itself, and two live `claude -p` runs confirmed a typed prompt and
  `CLAUDE.md` content both reaching the model tokenized. What is still NOT
  verified is compaction - see below.
- **Compaction does not leak in mod mode** (tested 2026-10-03). A mod still
  cannot rewrite a summary - `session.compact` accepts only
  `{ skip: reason }` - but it does not need to: the summarizer's input is the
  conversation *as the model saw it*, which is already tokenized, so the
  summary comes back in tokens. Measured with the proxy as a passive wire tap
  (empty identifier list, all patterns off) while the mod did the scrubbing:
  12 requests, 5.4 MB, one confirmed compaction summarizer, zero real
  identifiers. Afterwards the model recalled the values as tokens and said it
  took them from the compaction summary.
  Do not restate this as "the proxy is the only mode that covers compaction".
- **Stable tokens leak equality and frequency** by construction. That is
  inherent to the requirement that the same value always maps to the same
  token, not a bug to fix.
- **The claude.ai composer is not protected** in any mode, and the content
  script must never start writing into it.
- **Pattern-matched values cannot be restored by the Chrome extension**, since
  it only knows values on the shared list.
- **The browser E2E does not run in the user's real Chrome.** Chrome 153 has
  removed `--load-extension`; the test uses Playwright's bundled Chromium. Do
  not let the green suite be described as "tested in Chrome".

If a change would make any of these claims less true, update the README in the
same commit. Never let the docs overstate coverage — a privacy tool that is
trusted further than it works is worse than none.

## Measuring what actually leaves the machine

The mod has no wire log, so to see its output, run the **proxy as a passive
wire tap**: `CLAUDEFUSCATOR_KEY` set, an identifier list with `identifiers:
[]` and every pattern `false`, and `CLAUDEFUSCATOR_WIRE_LOG` pointed at a
file. It then scrubs nothing and records verbatim what the mod produced.
Point Claude Code at it with `ANTHROPIC_BASE_URL` and load the mod as usual.

This is the one case where running two modes at once is right: the proxy is
an instrument, not a second veil. Delete the wire log afterwards - it is a
full copy of the conversation - and say in any write-up that the proxy was
configured inert, or the result reads as the proxy having done the work.

Two things that bite:

- An inert identifier list does **not** disable the refusal rules in
  `rules.toml`. They still match, and with no llama-server up the call comes
  back `fallback_failed` and writes `proxy/logs/fallback.jsonl`, which holds
  request excerpts. That file is gitignored; delete it too.
- `/compact` typed through Git Bash is rewritten by MSYS path conversion
  into `C:/Program Files/Git/compact` and never reaches Claude Code. Neither
  `MSYS_NO_PATHCONV=1` nor `MSYS2_ARG_CONV_EXCL='*'` stopped it here; run it
  from PowerShell or an interactive session.

## Writing the mod: constraints the docs do not state

Each of these cost a debugging cycle and is enforced by the engine, not by
style:

- **`$` may not cross a module import**, and may only be passed to a function
  declared at the TOP LEVEL of the same file. `claude plugin validate`
  enumerates a mod's capabilities statically and cannot follow `$` otherwise.
  This is why all reading lives in `register.js` and `veil.js` is pure.
- **`prompt.compose` is in the type map but the loader refuses a hook on it**
  (`"prompt.compose" is not an event`). `prompt.section` and `prompt.context`
  cover the same ground.
- **`session.start` is not reliable for initialisation.** It does not fire
  after `/clear`, `/resume` or `/branch`, and the test harness never raises
  it. Loading is lazy and memoised, and every hook calls `ensureLoaded`
  first. `register()` clears that cache, because a reload may have a new
  config.
- **A relative `config_path` resolves against the PLUGIN directory**, not the
  working directory.
- **`secret_key` must not be `required`.** A required `userConfig` field
  fails the load wherever nothing can prompt - `claude -p`, CI, the Agent
  SDK - even when `CLAUDEFUSCATOR_KEY` is set.
- **This build needs `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`** for a
  `--plugin-dir` or installed mod to load, and says so when it refuses. The
  published docs say v2.1.287+ ignores that variable; on 2.1.288 it is
  required. Trust the engine's message over the docs.
- **`PromptContextResult` is `{ blocks, instructionFiles? }`.** Scrub
  `blocks[].text` and `instructionFiles[].content`; never `blocks[].name`
  (a matcher narrows on it) or `instructionFiles[].path`.
- **Drop `ref` from a rewritten tool result.** It names host-side messages
  core already produced - the unscrubbed ones - and "a hook that returns the
  object it got makes core use them verbatim". Keeping it can discard the
  scrub silently. Scrub `text` too: that is what the model actually reads.

## The unveil server (built 2026-10-03; deploying)

`docs/UNVEIL-SERVER.md` for the design. The rollout checklist is kept in
the surrounding workspace rather than here, because it names hosts and an
access list. The server module lives in `example/ai` on
`feat/claudefuscator-vault`, merge request !2. Decisions already taken, so
do not reopen them without reason:

- It lives **inside `ai.example.com`**, reusing `invited_users`, group roles
  and the existing `products` for need-to-know. Not a second service.
- **The host never holds the key.** If a change appears to need one, stop
  and redesign.
- **Values are encrypted client-side**; the host stores ciphertext. The
  vault is a distilled index of exactly which strings are sensitive across
  every project, which makes it a better target than any single repository.
- **Clients verify integrity** by recomputing the HMAC over the decrypted
  value, so a bad writer is detectable by every reader.
- **Resolve-only API.** No bulk export; a dump is what an attacker wants.
- The **mod cannot be a vault writer** — its sandbox has no usable
  WebCrypto, and hand-rolling an AEAD for a security boundary is not on.

Settled since that list was written:

- **Key escrow**: an offline copy held by an administrator, covering the
  **Claudefuscator key** (the vault key is HKDF-derived from it, so the one
  covers both). The sealed artefact is the owner's to make; nothing in code
  depends on it, but no row should be written to a real vault before it
  exists.
- **Which client writes**: the agent, and only the agent. The mod and the
  extension reach loopback and nothing else.
- **The extension talks to the agent**, not to the host. It never needed a
  public origin.
- **No Entra app registration is required.** The agent carries a personal
  API token created in the `ai.example.com` UI, which the existing
  `ApiTokenAuthenticationHandler` resolves through the same `invited_users`
  lookup the browser uses. The earlier claim that this was blocked on an
  admin-approved registration was wrong.

## Filter layers

Four, lowest precedence first: **generic** patterns -> **packs** (reusable
org/product/process vocabulary) -> **identifiers** (project list) ->
**allowList** (never tokenize, wins over everything).

- `shared/config-merge.js` resolves packs into one flat list and is mirrored
  by `proxy/config_merge.py`. Both must agree exactly or the proxy and the
  extension derive different tokens. `test/merge.test.js` and
  `proxy/tests/test_merge_parity.py` run the same fixtures and compare.
- **Never drop a match flag during merge.** `compound` and `caseSensitive`
  change how an entry is matched and tokenized; losing them silently
  disables code round-tripping. There is a test for this because it was a
  real bug.
- **`compound` implies `caseSensitive` and per-spelling tokens.** Code must
  round-trip byte-exact; a case-folded restore turns `ACME_TIMEOUT` into
  `Acme_TIMEOUT` and corrupts the file. Do not "simplify" this back into
  the alias model, which is for people's names.
- **The allow-list is load-bearing**, not a nicety. Org vocabulary collides
  with ordinary Dutch and English words constantly.
- **Never print harvested vocabulary into an agent's context.**
  `tools/harvest-vocab.js` prints counts only by default. The `--print` flag
  exists for a human terminal. Do not change the default, and do not run it
  with `--print` while Claude is reading the output — the list of terms you
  want hidden from Claude is itself the sensitive thing.

## Working rules for this repo

- **The key and real identifier values never get committed.** `.gitignore`
  covers `*.local.json`, `*.key`, `*secret*`, `.env*`, dumps and caches. Do not
  add a real `claudefuscator.local.json`, a real key, or a payload dump to git. When
  you need example data, invent it (`Jane Example`, `example.com`).
- **Never put the key in a tool argument, a log line, a commit message, or
  anything that reaches the model.** Only its source and a truncated
  fingerprint may be displayed.
- **Key escrow is decided: an offline copy held by an administrator**
  (2026-10-03). It covers the **Claudefuscator key**, which is the
  catastrophic one: it derives every token, every endpoint needs it offline
  (the mod computes HMACs in a sandbox with pure JS and no network), and
  losing it makes every token in every archived conversation unresolvable.
  It therefore cannot live in a non-exportable managed store such as Azure
  Key Vault, and that option was considered and declined for this key. The
  vault's value key is derived from it, so escrowing the one covers both.
- **`shared/claudefuscator-core.js` is canonical.** After editing it run
  `node tools/sync-core.js` **and** `node tools/gen-vectors.js`. Never edit
  the copies directly: `claude-plugin/lib/` and `chrome-extension/` get
  byte-identical ones, and `claude-mod/hooks/*.mjs` get the same bytes plus
  an ESM `export default` footer, because a mod runs in an ES-module-only
  sandbox with no `require` and no Node built-ins.
- **A mod has no usable WebCrypto.** Its sandbox exposes a `crypto.subtle`
  with no `importKey`, so the core carries a pure-JS HMAC-SHA256
  (`hmacHexPure`) and `hmacHex` falls back to it. The docs list
  `crypto.subtle` among the environment's web APIs; that does not hold for
  the methods this needs, and only running the mod revealed it. The two
  implementations are asserted equal over every vector, plus an RFC 4231
  known-answer, by `test/vectors.test.js`. Never remove that test, and never
  "simplify" the fallback away.
- **The vault envelope is a FOURTH cross-language contract**, between
  `agent/vault_crypto.py` and the C# server in `example/ai`. A byte-copy
  cannot hold it, so the guard is `shared/vault-vectors.json`, regenerated
  by `python tools/gen-vault-vectors.py` and asserted from both sides:
  `agent/tests/test_vault_vectors.py` checks the rows open and hash back,
  `VaultVectorTests.cs` checks they survive real HTTP and Postgres
  byte-identically. Neither alone is enough — a row that opens but is
  mangled in transit and a row that survives transit but was never valid
  both resolve to nothing, and both look like an empty vault. `--check`
  verifies the committed rows still open rather than comparing bytes, since
  a fresh nonce makes every regeneration differ.
- **There is a THIRD implementation**: `proxy/claudefuscator_core.py`, a
  hand-port. A byte-copy cannot work across languages, so the guard is
  `shared/test-vectors.json`, asserted by both `test/vectors.test.js` and
  `proxy/tests/test_parity.py`. Any change to derivation means: change the JS,
  change the Python, regenerate vectors, and watch both suites. If only one
  side changes, the proxy and the extension disagree and restore silently
  fails.
- **Token derivation is a wire format.** `normalise()`, the HMAC message layout
  and the token shape are a contract between independently-configured sides.
  Changing any of them silently breaks restore for every existing
  conversation. Bump `TOKEN_VERSION` if you must change them.
- **The inbound restore must keep covering `input_json_delta`.** That is what
  makes tool calls write real values to disk. `test_veil.py` pins it.
- **Never log or commit a wire log.** `CLAUDEFUSCATOR_WIRE_LOG` output is
  post-scrub but is still a full copy of a conversation. Gitignored; delete it
  after a verification run.
- **The extension reaches exactly one host: the loopback agent.** This
  replaced a flat "zero network calls" rule when the agent client landed —
  resolving values the extension cannot derive means asking something. The
  rule now has edges, and all of them are load-bearing:
  - The **only** `fetch` is in `background.js`. No `XMLHttpRequest`,
    `WebSocket`, `sendBeacon`, `navigator.connect`, remote script or remote
    font, anywhere. The content script makes no network call at all.
  - `permissions` stays `["storage"]`. `host_permissions` holds loopback
    origins and nothing else, and `background.js` derives what it may
    contact *from the manifest* rather than restating it, so the two cannot
    drift. Widening where real values may be sent has to be a manifest
    change, not a config line.
  - **Every value the agent returns is verified before it is displayed**:
    re-derive the token from the value under our own key, accept only on an
    exact match. The agent is a source, not an authority. The e2e test
    serves a deliberately poisoned mapping to hold this.
  - Use `chrome.storage.local`, never `chrome.storage.sync`, which would
    upload the key and the real values to a Google account.
- **The content script must never write into an editable region.** Restoring a
  token inside the claude.ai composer would put the real value into the box the
  user is about to send. The skip list in `content.js` is a safety control, not
  a nicety.
- **Fail closed, and fail loudly.** The worst failure mode here is silence: an
  unconfigured or broken Claudefuscator looks exactly like a working one. Keep the
  `SessionStart` status message and the "NOT scrubbing" warnings.
- Run `npm run test:all` (JS + Python + headless browser) and
  `claude plugin validate ./claude-plugin` before claiming anything works.
  `hooks/hooks.json` needs a top-level `{"hooks": {...}}` wrapper or
  validation fails with `expected record, received undefined`.
- The two `xfailed` Python tests are **pre-existing contradictions in the
  vendored local-ai-proxy suite**, not Claudefuscator bugs. They are marked,
  not fixed, because resolving them is a design decision about the local
  fallback. Do not "fix" them by editing the assertions to match whatever the
  code currently does.
- Do not install the extension into the owner's real Chrome profile, publish
  it, or push this repo anywhere without being asked.
