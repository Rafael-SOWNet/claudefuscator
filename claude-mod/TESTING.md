# Verifying the mod

Verified on **Claude Code 2.1.288**, 2026-10-03. This note says exactly what
that means and what it still does not cover.

---

## Run it

```bash
npm run test:mod     # claude plugin validate + claude plugin test
```

That wrapper sets `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`. **This build will
not load a mod's hooks module without it** — not for `plugin test` and not
for `--plugin-dir` — and refuses with *"hooks modules are not turned on in
this build yet (early access)"*. The published docs say v2.1.287+ ignores
that variable; on 2.1.288 it is required. Trust the engine's message.

`claude plugin validate` also prints the mod's entire capability surface.
Read it — this is the list an installer would audit:

```
hooks:      session.start, prompt.submit, prompt.section, prompt.context,
            skill.prompt, prompt.attachment, tool.describe, tool.call,
            ui.render{component=AssistantMessage|UserMessage|ToolResult|ToolUse}
calls:      $.env.get (via load), $.fs.read (via load), $.ui.log
env writes: nothing
env reads:  CLAUDEFUSCATOR_CONFIG, CLAUDEFUSCATOR_KEY
```

No network, no process spawn, no model calls.

---

## What is verified

### Against the engine (`claude plugin test`, 7 tests)

These load the real plugin, with the test's hooks sitting *beneath* it in
place of the engine's own behaviour — so they assert what Claude Code
actually hands the mod, not what the docs say it does.

| Test | Claim |
| --- | --- |
| the typed prompt reaches the model scrubbed | `prompt.submit` genuinely rewrites — the thing a settings hook cannot do |
| a prompt with no identifiers is untouched | no needless rewriting |
| the same value gets the same token every time | stability |
| with no identifier config the mod is inert | asserts it is **not** scrubbing, so a pass cannot imply protection that is absent |
| a tool result is scrubbed before Claude reads it | outbound |
| tool arguments are restored, so the tool runs on real values | inbound — a `Write` puts real values on disk |
| the mod derives the tokens the proxy and the extension expect | cross-surface agreement, against constants produced by the WebCrypto path |

That last one matters most. The mod's sandbox has **no usable WebCrypto**, so
it takes the core's pure-JS HMAC path while the proxy and the extension take
the WebCrypto one. If those two ever diverge, restore silently fails
everywhere. `test/vectors.test.js` pins them to each other and to an
RFC 4231 known-answer vector.

### Live, against the real API

Two `claude -p` runs with the mod loaded:

```
typed    : deploy DEV-100-000123 to build-01.corp.example for Jane Example
model got: deploy SERIAL_10099796 to HOST_b6812726 for PERSON_bc09b0fa
```

and, asked to quote its own project instructions verbatim, the model answered
`` (`PERSON_bc09b0fa`, `example.com`) `` where the file reads
`(Jane Example, example.com)` — so **`CLAUDE.md` content reached the model
tokenized**, which is the coverage settings hooks cannot provide.

(`claude -p` draws nothing, so `ui.render` does not run there. That is why
the tokens are visible in the output rather than restored — exactly what
makes the test readable.)

---

### Compaction (settled 2026-10-03)

A mod cannot rewrite a compaction summary — `session.compact` accepts only
`{ skip: reason }` — so the question was whether a compaction request carries
real values. It does not, and the reason is structural: the summarizer reads
the conversation **as the model saw it**, which is already tokenized, so the
summary is produced from tokens and comes back in tokens.

Measured with the proxy as a **passive wire tap** — `identifiers: []`, every
pattern `false`, `CLAUDEFUSCATOR_WIRE_LOG` set — so it scrubbed nothing and
recorded exactly what the mod produced:

```
12 requests, 5.4 MB of wire traffic
one confirmed compaction summarizer ("create a detailed summary of the
  conversation so far")
real identifiers found: 0
tokens found: HOST x44, PERSON x56, SERIAL x29
```

Asked afterwards what it remembered, the model answered
`HOST_f101b98c, PERSON_16528133, SERIAL_3a6e3b41` and said it took them from
the compaction summary.

The same run closed the other suspected leak vector. A `Write` whose
arguments the mod restored put **real** values on disk
(`build-01.corp.example owned by Jane Example unit DEV-100-000123`) while the
same tool call appeared on the wire as
`HOST_f101b98c owned by PERSON_16528133 unit SERIAL_3a6e3b41`. The restore
happens after the wire, so restored arguments never re-enter the outbound
conversation.

To repeat it, see "Measuring what actually leaves the machine" in CLAUDE.md.
Note `/compact` through Git Bash is mangled by MSYS path conversion into
`C:/Program Files/Git/compact`; run it from PowerShell or an interactive
session.

## What is NOT verified

- **`prompt.section` and `prompt.attachment` in a real session.** They are
  unit-tested and the engine accepts the hooks, but no live run has been
  observed exercising them specifically.
- **The Desktop app and the VS Code extension.** Only the terminal has been
  used.

---

## Setting it up for real use

```bash
export CLAUDEFUSCATOR_KEY="your-key"
export CLAUDEFUSCATOR_CONFIG="$PWD/claudefuscator.local.json"
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1

claude --plugin-dir ./claude-mod
```

The first line of the session must read `Claudefuscator: ACTIVE (...)`.
**`INACTIVE` means nothing is being scrubbed.**

`secret_key` is deliberately **not** a required `userConfig` field: a
required field fails the load wherever nothing can prompt — `claude -p`, CI,
the Agent SDK — even when `CLAUDEFUSCATOR_KEY` is set. Set it through
`/config` for an interactive session, or through the environment otherwise.

A relative `config_path` resolves against the **plugin directory**, not the
working directory. Use an absolute path if that surprises you.

---

## Do not run two modes

The mod, the proxy and the settings-hook plugin all scrub. Scrubbing is
idempotent so nothing breaks, but two layers mean twice the places to look
when something is not scrubbed.

```bash
curl -s http://127.0.0.1:8090/health          # proxy running?
claude plugin list | grep -i claudefuscator   # mod or plugin enabled?
```

Exactly one of those should be true.
