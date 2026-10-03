"""Claudefuscator veil layer for the proxy.

The proxy is a far better choke point than the Claude Code hooks: it sees the
entire /v1/messages body, so it covers the three things hooks structurally
cannot reach - the prompt you typed, CLAUDE.md content, and compaction
summaries.

Direction of travel:

    outbound (to Anthropic)   scrub_request_body()    real  -> tokens
    inbound  (from Anthropic) restore_sse_body()      tokens -> real
                              restore_json_body()

Tokens are a WIRE-ONLY representation. Because the inbound restore runs over
tool_use inputs as well as assistant text, Claude Code receives real values
and therefore writes real values to local disk and local shares. Nothing on
this machine ends up holding a token unless the proxy is bypassed.

What is deliberately NOT scrubbed outbound is listed in _SKIP_REQUEST_KEYS:
rewriting those would corrupt the API contract rather than protect anything.
"""

import json
import os
import re

import claudefuscator_core as core
import config_merge

# Top-level request keys that must reach the API untouched. These carry no
# user content - mangling a model id or a tool name breaks the request, and a
# tool NAME is API surface, not an identifier worth hiding.
_SKIP_REQUEST_KEYS = {'model', 'max_tokens', 'temperature', 'top_p', 'top_k',
                      'stream', 'stop_sequences', 'metadata', 'service_tier'}

# Inside a content block, these are structural, not prose.
_SKIP_BLOCK_KEYS = {'type', 'id', 'tool_use_id', 'name', 'cache_control',
                    'media_type', 'encoding', 'signature'}

# SSE payload fields that carry model-authored text or tool-call JSON. These
# are what the inbound restore has to cover. `partial_json` is the one that
# matters for the "local disk gets real values" guarantee: it is the streamed
# tool_use input, so a Write/Edit lands real content on disk.
_RESTORE_DELTA_KEYS = {'text', 'partial_json', 'thinking'}


class Veil:
    """Holds the vault plus a record of what crossed, for the status endpoint."""

    def __init__(self, secret, config):
        self.vault = core.build_vault(secret, config)
        self.scrubbed_count = 0
        self.restored_count = 0

    # ---- outbound ------------------------------------------------------

    def scrub_text(self, text):
        out, hits = self.vault.scrub(text)
        self.scrubbed_count += len(hits)
        return out, hits

    def scrub_request_body(self, body):
        """Scrub a /v1/messages request body. Takes and returns bytes.

        Returns (body_bytes, hits). On any parse failure the body is returned
        unchanged with an empty hit list, and the caller decides whether to
        fail closed - see lite_llm_proxy.
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise VeilError('request body is not JSON, refusing to forward unscrubbed')

        hits = []

        def scrub_leaf(s):
            out, h = self.vault.scrub(s)
            hits.extend(h)
            return out

        for key, value in list(data.items()):
            if key in _SKIP_REQUEST_KEYS:
                continue
            if key == 'tools':
                # Tool SCHEMAS are API surface (names, JSON-schema keys) but
                # their descriptions are free text written by whoever defined
                # the tool and can carry a hostname. Scrub descriptions only.
                data[key] = [_scrub_tool(t, scrub_leaf) for t in value]
                continue
            data[key] = _map_content(value, scrub_leaf)

        self.scrubbed_count += len(hits)
        out = json.dumps(data, ensure_ascii=False).encode('utf-8')

        # Opt-in wire log: exactly what is about to leave the machine. This is
        # the only way to verify the claim against the REAL Anthropic API,
        # where you cannot inspect what the far end received. Off unless
        # CLAUDEFUSCATOR_WIRE_LOG is set; the file is post-scrub, but it is
        # still a full copy of your conversation, so it is gitignored and
        # worth deleting after a verification run.
        wire_log = os.environ.get('CLAUDEFUSCATOR_WIRE_LOG')
        if wire_log:
            try:
                with open(wire_log, 'a', encoding='utf-8') as f:
                    f.write(out.decode('utf-8') + '\n')
            except OSError:
                pass

        return out, hits

    # ---- inbound -------------------------------------------------------

    def restore_json_body(self, body):
        """Restore a non-streaming JSON response. Takes and returns str."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body
        restored = core.map_strings(data, self._restore_counting)
        return json.dumps(restored, ensure_ascii=False)

    def restore_sse_body(self, body):
        """Restore a complete, already-buffered SSE response body.

        The proxy fetches upstream without stream=True, so the whole body is
        in memory here. That removes the hard part: a token split across two
        text_delta chunks would need a tail-holdback replacer, but we can
        instead reassemble each content block, restore once, and put the
        result in that block's first delta.

        Operates per `data:` line and re-serialises through json.dumps, so a
        restored value containing a quote or a backslash is escaped correctly.
        A naive string replace over the raw body would corrupt the JSON.
        """
        lines = body.split('\n')

        # Pass 1: find the delta events per content-block index, in order.
        # (index, line_no, field) for every restorable delta payload.
        blocks = {}
        parsed = {}
        for i, line in enumerate(lines):
            if not line.startswith('data: '):
                continue
            raw = line[6:]
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
            parsed[i] = payload
            if payload.get('type') != 'content_block_delta':
                continue
            delta = payload.get('delta') or {}
            field = next((k for k in _RESTORE_DELTA_KEYS if isinstance(delta.get(k), str)), None)
            if field is None:
                continue
            blocks.setdefault((payload.get('index'), field), []).append(i)

        # Pass 2: per block, join -> restore -> put it all in the first delta
        # and blank the rest. The client concatenates deltas, so the result is
        # identical, and granularity was already lost upstream by buffering.
        changed_lines = {}
        for (index, field), line_nos in blocks.items():
            joined = ''.join(parsed[n]['delta'][field] for n in line_nos)
            restored = self._restore_counting(joined)
            if restored == joined:
                continue
            for pos, n in enumerate(line_nos):
                payload = parsed[n]
                payload['delta'][field] = restored if pos == 0 else ''
                changed_lines[n] = 'data: ' + json.dumps(payload, ensure_ascii=False)

        # Pass 3: non-delta events (content_block_start carries a complete
        # tool_use `input` on some paths; message_start carries nothing useful
        # but is cheap to cover).
        for i, payload in parsed.items():
            if i in changed_lines or payload.get('type') == 'content_block_delta':
                continue
            restored = core.map_strings(payload, self._restore_counting)
            if restored != payload:
                changed_lines[i] = 'data: ' + json.dumps(restored, ensure_ascii=False)

        if not changed_lines:
            return body
        for n, new_line in changed_lines.items():
            lines[n] = new_line
        return '\n'.join(lines)

    # ---- mapping service ----------------------------------------------

    def auth_token(self):
        """Proof that the caller holds the same key, without sending the key.

        /mappings serves REAL identifier values, so it cannot be open to
        anything that can reach the loopback interface. A browser page cannot
        read the response (no CORS headers are sent), but another process on
        the machine could, and this is what stops it.
        """
        return core.hmac_hex(self.vault.secret, 'claudefuscator/mappings/v1')[:32]

    def mappings(self):
        """token -> real value, for every entry the vault can resolve.

        List entries are derivable by anyone holding the key and the list.
        `discovered` is the part that is not: pattern hits whose real value
        nothing else has recorded, which is exactly what the browser side
        cannot work out for itself.
        """
        out = dict(self.vault.token_to_value)
        out.update(self.vault.discovered)
        return out

    def _restore_counting(self, s):
        out = self.vault.restore(s)
        if out != s:
            self.restored_count += 1
        return out


class VeilError(Exception):
    """Raised when the veil cannot do its job. The proxy fails closed on this."""


def _map_content(value, fn):
    """Walk message content, skipping structural keys inside blocks."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [_map_content(v, fn) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out[k] = v if k in _SKIP_BLOCK_KEYS else _map_content(v, fn)
        return out
    return value


def _scrub_tool(tool, fn):
    """Scrub a tool definition's prose, leaving its name and schema keys."""
    if not isinstance(tool, dict):
        return tool
    out = dict(tool)
    if isinstance(out.get('description'), str):
        out['description'] = fn(out['description'])
    schema = out.get('input_schema')
    if isinstance(schema, dict):
        out['input_schema'] = _scrub_schema_descriptions(schema, fn)
    return out


def _scrub_schema_descriptions(node, fn):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            # Only `description` is prose; `properties` keys are API surface.
            out[k] = fn(v) if (k == 'description' and isinstance(v, str)) \
                else _scrub_schema_descriptions(v, fn)
        return out
    if isinstance(node, list):
        return [_scrub_schema_descriptions(v, fn) for v in node]
    return node


# ---- configuration -----------------------------------------------------

def load_config(path=None):
    """Find the identifier list. Same search order as the Claude Code side so
    one file drives both."""
    candidates = [
        path,
        os.environ.get('CLAUDEFUSCATOR_CONFIG'),
        os.path.join(os.getcwd(), 'claudefuscator.local.json'),
        os.path.expanduser('~/.claudefuscator/identifiers.json'),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            with open(candidate, 'rb') as f:
                cfg = json.load(f)
            # Resolve packs -> one flat identifier list. Must match
            # shared/config-merge.js exactly or the proxy and the Chrome
            # extension derive different tokens.
            merged = config_merge.merge_config(
                cfg, config_merge.file_pack_loader(os.path.dirname(candidate)), candidate
            )
            return merged['config'], candidate
    return None, None


def load_key():
    """Env var only on this side. The proxy has no credential-store access,
    and putting the key in rules.toml would commit it."""
    key = os.environ.get('CLAUDEFUSCATOR_KEY', '').strip()
    return key or None


def build_from_env(config_path=None):
    """Returns (veil, status_string). veil is None when not configured, which
    makes the proxy relay unchanged - the same inert-when-unconfigured rule
    the Claude Code side follows."""
    key = load_key()
    if not key:
        return None, 'INACTIVE (no CLAUDEFUSCATOR_KEY set)'

    config, source = load_config(config_path)
    if config is None:
        return None, 'INACTIVE (no identifier config found)'

    try:
        veil = Veil(key, config)
    except Exception as e:  # collision, bad config
        return None, f'INACTIVE ({e})'

    n = len(veil.vault.token_to_value)
    patterns = ', '.join(p['name'] for p in veil.vault.patterns) or 'none'
    return veil, f'ACTIVE ({n} list entries; patterns: {patterns}; config: {source})'
