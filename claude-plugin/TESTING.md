# Verifying the plugin side

Two questions this note answers with commands rather than assurances:

- **Does the key ever land on disk in plaintext?**
- **Does any real identifier value survive into a transcript, log, or cache?**

Plus three checks for behaviour the docs do not specify.

Everything below assumes you are in the repo root.

---

## Check 0 — unit tests and manifest

```bash
npm test                                  # 26 tests; also fails if the two
                                          # core copies have drifted
claude plugin validate ./claude-plugin    # must print "Validation passed"
```

`hooks/hooks.json` needs a top-level `{"hooks": {...}}` wrapper. Without it
validation fails with `hooks: Invalid input: expected record, received
undefined`.

---

## Check 1 — the hooks do what they claim, on synthetic payloads

Each hook is a plain stdin→stdout filter, so you can drive it directly without
starting a session. Use a throwaway key and a fake list.

```bash
export CLAUDEFUSCATOR_KEY="scratch-key-not-real"
export CLAUDEFUSCATOR_CONFIG="$PWD/config/claudefuscator.example.json"

# scrub: real -> token, before the model sees it
echo '{"session_id":"t","tool_name":"Read","tool_response":"10.42.7.19 build-01.corp.example Jane Example"}' \
  | node claude-plugin/scripts/post-tool-use.js

# restore into tool args: token -> real, so local tools work
echo '{"session_id":"t","tool_name":"Bash","tool_input":{"command":"ssh HOST_xxxxxxxx uptime"}}' \
  | node claude-plugin/scripts/pre-tool-use.js

# restore on screen: token -> real, display only
echo '{"session_id":"t","message":"HOST_xxxxxxxx is down"}' \
  | node claude-plugin/scripts/message-display.js
```

Substitute the real token values from the first command's output into the
second and third.

**Expected:** the first prints `updatedToolOutput` with tokens and no real
values; the others print the real values back. Empty output means "no change",
which is the correct response when there is nothing to do.

### Fail-safe behaviour

```bash
# Unconfigured -> completely inert (empty output, no error)
env -u CLAUDEFUSCATOR_KEY node claude-plugin/scripts/post-tool-use.js <<< '{"tool_response":"Jane Example"}'

# Broken config -> loud, never silent
echo '{ not json' > /tmp/bad.json
CLAUDEFUSCATOR_CONFIG=/tmp/bad.json node claude-plugin/scripts/post-tool-use.js <<< '{"tool_response":"x"}'
```

The second must print a `systemMessage` containing **"NOT scrubbing"**. Silence
here would be indistinguishable from working correctly, which is the failure
mode this plugin is most exposed to.

---

## Check 2 — the key is not on disk in plaintext

The key is declared `sensitive: true` in `plugin.json`, so Claude Code stores
it in the OS credential store and not in `settings.json`. Verify, don't assume.

```bash
# 1. It must NOT appear in any settings file.
grep -rIl "YOUR-ACTUAL-KEY" ~/.claude/ 2>/dev/null          # expect no output
grep -rI "secret_key" ~/.claude/settings.json 2>/dev/null   # expect no value
```

```powershell
# 2. Windows: it should be in Credential Manager, not a file.
cmdkey /list | Select-String -Pattern "claude|anthropic"
```

```bash
# 3. Nothing under the repo, either.
grep -rIl "YOUR-ACTUAL-KEY" . --exclude-dir=.git   # expect no output
git ls-files | grep -Ei "local\.json|\.key$|secret"  # expect no output
```

On macOS use `security find-generic-password`; on Linux, `secret-tool search`.

If you used `CLAUDEFUSCATOR_KEY_FILE`, the key **is** on disk in plaintext by
definition — that is why it is the last-preference source. Prefer the plugin's
`userConfig` prompt or the env var.

> The key is never logged. `runtime.js` reports only the key's *source*, and
> the extension options page shows only a truncated HMAC *fingerprint* over a
> fixed label. Neither reveals the key.

---

## Check 3 — no real value survives into transcripts, logs or caches

This is the check that actually matters, and it needs a real session.

```bash
# 1. Run a session that reads a file containing a value on your list.
claude --plugin-dir ./claude-plugin
#   > read ./some-file-with-an-internal-hostname
#   ... then exit
```

```bash
# 2. Grep the transcript for the real value. Expect NO matches.
grep -rI "build-01.corp.example" ~/.claude/projects/ | head

# 3. Expect the TOKEN to be there instead. This is the positive control:
#    no matches for either means the hook never ran.
grep -rIo "HOST_[0-9a-f]\{8\}" ~/.claude/projects/ | head
```

```bash
# 4. Debug logs. Hook stdout goes to the debug log for most events, so check it.
claude --debug --plugin-dir ./claude-plugin      # reproduce, then:
grep -rI "build-01.corp.example" ~/.claude/ | head  # expect no output
```

```bash
# 5. The discovered-value cache. With the default cacheDiscovered:false it must
#    not exist at all.
ls -la ~/.claude/plugins/data/*claudefuscator*/sessions/ 2>/dev/null   # expect: no such directory
```

If you set `cacheDiscovered: true`, that directory **will** contain real values
in plaintext (the file says so in its own `warning` field). That is the
documented trade for restoring pattern matches. Delete it when done:

```bash
rm -rf ~/.claude/plugins/data/*claudefuscator*/sessions/
```

**Interpreting step 2 honestly:** a clean grep proves the value did not reach
the transcript *by that path*. It does not prove the value never reached
Anthropic — if it was in a prompt you typed, or in `CLAUDE.md`, or in a
pre-scrub compaction summary, no hook touched it. See the README's "Not
protected" list.

---

## Check 4 — is `updatedInput` echoed back to the model? (unresolved)

`pre-tool-use.js` puts **real values** into tool arguments so local tools work.
If Claude Code sends the updated input back to the model, that would leak them —
the exact thing this plugin exists to prevent. The docs do not say either way.

Settle it empirically:

```bash
# Run a session where Claude greps for a tokenized hostname, then:
grep -rI "build-01.corp.example" ~/.claude/projects/ | head
```

- **No matches** → `updatedInput` is not echoed; the hook is safe. Good.
- **Matches inside a `tool_use` / input block** → it *is* echoed. Set
  `"restoreToolInput": false` in your config and report it. Tool calls on
  tokenized values will then fail, which is inconvenient but leaks nothing.

Until you have run this, treat `restoreToolInput: true` as unverified.

---

## Check 5 — confirm the `MessageDisplay` input field

The hooks reference documents `displayContent` going out but no input schema
coming in, so `message-display.js` probes candidate field names. Find out which
one your version sends:

```bash
export CLAUDEFUSCATOR_DUMP="$PWD/md.dump.jsonl"    # gitignored by the *.dump.jsonl rule
claude --plugin-dir ./claude-plugin
#   ... have Claude say something containing a token, then exit
node -e "for(const l of require('fs').readFileSync(process.env.CLAUDEFUSCATOR_DUMP,'utf8').trim().split('\n')) console.log(Object.keys(JSON.parse(l)).join(', '))" | sort -u
rm "$CLAUDEFUSCATOR_DUMP"
```

Compare the field names against `CANDIDATE_FIELDS` in
`scripts/message-display.js` and add the real one to the front of that list if
it is missing.

`MessageDisplay` payloads carry model output — tokens, not real values — so
dumping them is comparatively low-risk. **Do not** point `CLAUDEFUSCATOR_DUMP` at a
`PostToolUse` run: those payloads are pre-scrub and contain real values.

---

## Check 6 — cross-side token parity

The Chrome extension can only restore tokens if it derives the identical value.
Same key + same list must give the same token in Node and in the browser.

```bash
node -e "
const c=require('./shared/claudefuscator-core.js');
(async()=>{
  const cfg=JSON.parse(require('fs').readFileSync('./claudefuscator.local.json','utf8'));
  const v=await c.buildVault(process.env.CLAUDEFUSCATOR_KEY,cfg);
  for(const [t,val] of v.tokenToValue) console.log(t,'<-',val);
})()"
```

Then click **Test** on the extension options page with the same key and list.
The two token columns must match exactly. They should, because both sides run
byte-identical copies of the core — `npm test` enforces that — but this checks
the key and list actually match too.
