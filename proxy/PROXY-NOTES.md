# local-ai-proxy

> **Status: kept for reference, not the recommended path.**
>
> This was vendored because the proxy was once the only way to reach a
> typed prompt, `CLAUDE.md` and compaction. Mod mode now reaches the first
> two, and compaction was measured not to leak, so the reason to run a
> proxy in front of every request has gone. Nothing here is deprecated or
> broken — it is simply no longer where a Claude Code user should start.
>
> It is kept rather than deleted because three uses survive:
>
> 1. **Clients that are not Claude Code.** A mod only exists inside Claude
>    Code.
> 2. **The local-model fallback** below — a `$`-prefixed prompt served
>    locally with real values, nothing upstream. That is the answer for
>    content whose substance cannot leave the building, as opposed to
>    content that merely carries a name.
> 3. **The passive wire tap.** Configured inert, it records verbatim what
>    another mode emitted. That is how mod mode was verified and how the
>    compaction question was settled. No other component can do it, because
>    a thing cannot audit itself.
>
> **Provenance is not recorded, and that matters before this repository is
> made public.** This arrived as `local-ai-proxy-main.zip`; the `-main.zip`
> naming means a forge download, so there is an upstream somewhere, but no
> author, URL or licence terms came with it. The repository root carries an
> MIT `LICENSE` that nominally covers this directory too. If this code is
> the repository owner's own, say so here and the question is closed. If it
> is not, its upstream licence has to be vendored alongside it or this
> directory removed before anything is published publicly.

Local HTTP proxy (port 8090) between Claude Code and the Anthropic API. It forwards `/v1/messages` to the real API and falls back to a local Qwen3-14B (llama.cpp `llama-server`, port 9931) when the upstream answer looks like a refusal, or when the user asks for it.

Windows + PowerShell project. Python 3.11+ (uses `tomllib`; developed on 3.14), dependency: `requests`, dev: `pytest`.

## How it works

Request flow in `lite_llm_proxy.py` (`ProxyHandler.do_POST`):

1. Non-`/v1/messages` paths are relayed to upstream unchanged. `GET /health` returns `{"status":"ok"}`.
2. **Local-only**: header `x-api-key: local-no-key` skips upstream, serves everything from the local model.
3. **Manual override**: a latest user message starting with `$` skips upstream; the `$` is stripped.
4. Otherwise forward upstream. For streams, `sse.parse_sse` + `detect.holdback` buffer the first `holdback_chars` of text, and `detect.make_decision` regex-matches it against `rules.toml` rules (`.search()`, case-insensitive). A `stop_reason == "refusal"` (classifier refusal) always passes through. On match, `local_request` replays the request to the local model.
5. Fallback requests are sanitized in `local_request._sanitize`: thinking blocks, `cache_control` blocks and `<system-reminder>` text blocks are dropped, `max_tokens` is capped to `local_max_tokens`, model is swapped to `local_model`. Responses are prefixed with a `⚠ [local fallback: rule "..."]` marker; streaming fallbacks send SSE `: keepalive` comments every 10s.
6. Every fallback is appended to `logs/fallback.jsonl` (gitignored).

Files: `lite_llm_proxy.py` (server), `detect.py` (rules + decision + logging), `local_request.py` (local model calls), `sse.py` (SSE parsing), `rules.toml` (settings + refusal regexes), `tests/`.

**Working directory matters:** `rules.toml` and `logs/` are resolved relative to CWD, so always run from this directory (`start-proxy.ps1` pins it).

## Running

```powershell
.\start-claude.ps1               # default: real Claude via your subscription login, proxied, local fallback on refusal or "$" prefix
.\start-claude.ps1 -Bare         # local model only, still through the proxy (sanitized); uses dummy key local-no-key
.\start-claude.ps1 -LocalOnly    # direct to llama-server :9931, no proxy
.\start-claude.ps1 -NoClaudeMd   # sets CLAUDE_CODE_DISABLE_CLAUDE_MDS=1 (undocumented env var; re-check after Claude Code updates)
.\start-proxy.ps1                # just start llama-server + proxy
python lite_llm_proxy.py         # proxy alone (from this directory)
```

`start-claude.ps1` has no `param()` block on purpose, so any other flags (`-p`, `--resume`, ...) pass straight through to `claude`. It health-checks the proxy, replaces a stale process on 8090, and sets `ANTHROPIC_BASE_URL=http://127.0.0.1:8090` for the session (cleaned up on exit). With `-Bare`/`-LocalOnly` it also sets `CLAUDE_CODE_MAX_CONTEXT_TOKENS` from llama-server's `/props` `n_ctx`.

Default mode leaves `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` unset so Claude Code uses its normal subscription login; the proxy forwards the client's own auth headers upstream.

## Machine-specific setup (not in this repo)

Paths are hardcoded for this machine; adapt when moving it:

- `D:\local-ai\proxy\` — this repo (hardcoded in both `.ps1` scripts).
- `D:\local-ai\start-server.ps1` — **lives outside this repo.** `start-proxy.ps1` runs it as `-Model josiefied -Port 9931`. It launches `D:\llm\llama-mainline\build\bin\llama-server.exe` (mainline llama.cpp) with a GGUF from `D:\AI-Models\gguf\` (default `josiefied-qwen3-14b-abliterated-v3-Q6_K.gguf`), 64K ctx with YaRN, q8_0 KV cache. Without it (or an equivalent llama-server on :9931) the local fallback returns 502 `fallback_failed`.
- `local_model = "qwen3-14b-local"` in `rules.toml` is only a label sent to llama-server.

## Tests

```powershell
python -m pytest -q
```

Known state: 9 pass, 2 fail (`test_marker_injection`, `test_sanitize_request` in `tests/test_local_request.py`) because `tests/test_rules.toml` line 13 uses Python raw-string syntax (`r"..."`, `\'`) which is not valid TOML. Fix the fixture before trusting the suite.

## Conventions

- Comments explain *why* (real-world client quirks observed); keep that style.
- Settings and refusal rules live in `rules.toml`; add new refusal patterns there as `[[rules]]` rather than in code. Use `.search()` semantics (patterns may match mid-text).
- The dummy key `local-no-key` is intentional, not a secret.
- Never commit `logs/` (contains real request excerpts), `.remember/`, or `.claude/`.
