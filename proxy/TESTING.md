# Verifying the proxy side

The proxy is the strongest of the three surfaces: it sees the entire
`/v1/messages` body, so it covers the three things Claude Code hooks
structurally cannot reach — the prompt you typed, `CLAUDE.md` content, and
compaction summaries.

This note is how you confirm that rather than take it on trust.

Run everything from the repo root unless stated otherwise.

---

## Check 0 — the automated suites

```bash
python -m pytest proxy -q      # 84 passed, 2 xfailed
```

The two `xfailed` are **pre-existing contradictions in the vendored
local-ai-proxy tests**, not Claudefuscator problems, and they are marked
rather than fixed because resolving them is a design decision about the local
fallback feature. See [PROXY-NOTES.md](PROXY-NOTES.md).

The suites that matter here:

| File | What it proves |
| --- | --- |
| `tests/test_parity.py` | The Python tokenizer derives byte-identical tokens to the JS one, from `shared/test-vectors.json`. Without this, the proxy and the Chrome extension would disagree and restore would silently fail. |
| `tests/test_veil.py` | Scrub/restore unit behaviour, including a token split across two SSE deltas and a restored value that needs JSON escaping. |
| `tests/test_proxy_integration.py` | The patched proxy against a **fake upstream that records what it received**. This is the real claim: assertions run on the bytes a server actually got. |

---

## Check 1 — nothing real leaves the machine, against the real API

The integration tests use a fake upstream. To verify against the actual
Anthropic API — where you cannot inspect what the far end received — log what
the proxy sends.

```bash
cp config/claudefuscator.example.json claudefuscator.local.json
# edit it: put a value you can grep for in `identifiers`

cd proxy
export CLAUDEFUSCATOR_KEY="some-test-key"
export CLAUDEFUSCATOR_CONFIG="$(cd .. && pwd)/claudefuscator.local.json"
export CLAUDEFUSCATOR_WIRE_LOG="$(cd .. && pwd)/live.wire.jsonl"
python lite_llm_proxy.py
```

It prints its status on startup, and `/health` repeats it:

```bash
curl -s http://127.0.0.1:8090/health
# {"status":"ok","claudefuscator":"ACTIVE (3 list entries; patterns: ...)"}
```

**If it says `INACTIVE`, nothing is being scrubbed.** Stop and fix that first.

In another shell, send a prompt containing a value from your list:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8090 \
  claude -p "Repeat exactly: deploy to build-01.corp.example for Jane Example"
```

Two things to confirm:

```bash
# 1. The REPLY shows real values -> restore works.
#    (It should echo build-01.corp.example, not HOST_xxxxxxxx.)

# 2. The WIRE shows none of them -> scrub works.
for real in "build-01.corp.example" "Jane Example" "build-01" "Jane"; do
  printf '%-24s ' "$real"
  grep -c -F "$real" live.wire.jsonl || true     # every line must be 0
done

# 3. Tokens are there instead, so the hit was not simply dropped.
grep -oE '(HOST|PERSON|SERIAL|IP|EMAIL|MAC)_[0-9a-f]{8}' live.wire.jsonl | sort | uniq -c
```

Expect more tokens than you put in the prompt: your `CLAUDE.md`, skills and
session context pass through here too, and get scrubbed as well. That is the
point of doing this in the proxy rather than in a hook.

**Delete the wire log afterwards.** It is post-scrub, but it is still a full
copy of the conversation:

```bash
rm live.wire.jsonl
```

---

## Check 2 — fail-closed, not fail-open

A body the veil cannot parse must never be forwarded.

```bash
curl -s -X POST http://127.0.0.1:8090/v1/messages \
  -H 'Content-Type: application/json' --data '{ not json' | head -c 300
```

Expect HTTP 400 and `"type": "claudefuscator_scrub_failed"`. Covered
automatically by `test_unscrubbable_body_is_not_forwarded`, which also asserts
the fake upstream received nothing.

---

## Check 3 — unconfigured means inert, and says so

```bash
cd proxy
env -u CLAUDEFUSCATOR_KEY python lite_llm_proxy.py
# prints: Claudefuscator: INACTIVE (no CLAUDEFUSCATOR_KEY set)
```

In this state the proxy relays **unscrubbed**. `test_unconfigured_proxy_relays_unchanged`
asserts exactly that, deliberately — a passing test must not imply protection
that is not there.

---

## Check 4 — the local fallback model gets REAL values

By design. The local model runs on this machine, so there is nothing to hide
from it, and feeding it tokens would only make its answers worse.

```bash
# With llama-server up on :9931, a "$" prefix forces the local path:
ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude -p '$what host is build-01.corp.example'
```

The wire log stays empty for that request, because nothing went upstream.

---

## Check 5 — tool calls land real values on disk

This is the "tokens are a wire format, not a storage format" guarantee. The
inbound restore covers `input_json_delta`, so a `Write`/`Edit` tool call is
restored *before* Claude Code executes it.

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:8090 \
  claude -p "Create a file called host.txt containing exactly: build-01.corp.example"

cat host.txt        # must be the real hostname, NOT HOST_xxxxxxxx
rm host.txt
```

If this ever shows a token, the restore pass is not covering tool inputs and
`test_tool_use_input_is_restored_so_disk_gets_real_values` should have caught
it — check that test first.

---

## Check 6 — hooks must be OFF in proxy mode

Running both double-scrubs. It is harmless for correctness (scrubbing is
idempotent) but wrong for you: the `PostToolUse` hook rewrites tool results
**in the local transcript**, so your own machine ends up storing tokens where
you wanted real values.

```bash
# Confirm the plugin is not also enabled:
claude plugin list | grep -i claudefuscator
```

Either disable the plugin, or run hooks-only without the proxy. Not both.
