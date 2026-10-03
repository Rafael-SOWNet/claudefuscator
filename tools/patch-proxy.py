"""One-shot patcher that wires veil.py into the vendored lite_llm_proxy.py.

Kept as a file rather than done by hand so the integration points are
reviewable as a diff, and so re-vendoring a newer local-ai-proxy is a matter
of re-running this and fixing whatever no longer matches.

Every replacement asserts its anchor is present exactly once; a silent no-op
here would leave the proxy forwarding unscrubbed.
"""

import pathlib
import sys

TARGET = pathlib.Path(__file__).resolve().parents[1] / 'proxy' / 'lite_llm_proxy.py'
src = TARGET.read_text(encoding='utf-8')

if 'import veil' in src:
    print('already patched; nothing to do')
    sys.exit(0)

EDITS = []

# 1. import + module-level veil instance
EDITS.append((
    "import sse\nimport detect\nimport local_request\n",
    "import sse\nimport detect\nimport local_request\nimport veil as veil_mod\n"
))

EDITS.append((
    "SETTINGS = _load_settings()\n",
    """SETTINGS = _load_settings()

# Claudefuscator. Built once at import. None means "not configured", in which
# case the proxy relays unchanged -- the same inert-when-unconfigured rule the
# Claude Code side follows, because a privacy tool that bricks every request
# when unconfigured just gets switched off.
VEIL, VEIL_STATUS = veil_mod.build_from_env()
print(f'Claudefuscator: {VEIL_STATUS}')
"""
))

# 2. health endpoint reports veil status, so "is it actually on?" is one curl
EDITS.append((
    "        body = json.dumps({'status': 'ok'}).encode('utf-8')\n",
    "        body = json.dumps({'status': 'ok', 'claudefuscator': VEIL_STATUS}).encode('utf-8')\n"
))

# 3. scrub outbound. Note what is NOT scrubbed: the local-fallback path keeps
#    the original body, because the local model runs on this machine and
#    giving it tokens would degrade its answers for no privacy gain.
EDITS.append((
    """        if local_only_mode or forced_fallback:
            rule = 'manual_override' if forced_fallback else 'bare_local_only'
            self._handle_fallback({'type': 'fallback', 'rule': rule}, body, '', 0, stream)
            return

        # Forward to upstream API server
        upstream_start = time.time()
        upstream_response = self._forward_to_upstream(body, stream)
        upstream_ms = (time.time() - upstream_start) * 1000
""",
    """        if local_only_mode or forced_fallback:
            # Local model only: send REAL values. It runs on this machine, so
            # there is nothing to hide from it, and tokens would only make its
            # answers worse.
            rule = 'manual_override' if forced_fallback else 'bare_local_only'
            self._handle_fallback({'type': 'fallback', 'rule': rule}, body, '', 0, stream)
            return

        # Scrub before anything leaves the machine. Fails CLOSED: if the body
        # cannot be parsed and scrubbed, it is not forwarded.
        upstream_body = body
        if VEIL is not None:
            try:
                upstream_body, veil_hits = VEIL.scrub_request_body(body)
            except veil_mod.VeilError as e:
                self._veil_failed(str(e))
                return

        # Forward to upstream API server
        upstream_start = time.time()
        upstream_response = self._forward_to_upstream(upstream_body, stream)
        upstream_ms = (time.time() - upstream_start) * 1000
"""
))

# 4. restore inbound, streaming. Covers text_delta AND input_json_delta, so a
#    tool_use input reaches Claude Code -- and therefore local disk -- real.
EDITS.append((
    """            if decision['type'] == 'pass':
                self._relay_events(upstream_response['body'])
            else:
                self._handle_fallback(decision, body, holdback['held_text'], upstream_ms, stream)
""",
    """            if decision['type'] == 'pass':
                out = upstream_response['body']
                if VEIL is not None:
                    out = VEIL.restore_sse_body(out)
                self._relay_events(out)
            else:
                # Fallback gets the ORIGINAL body: local model, real values.
                self._handle_fallback(decision, body, holdback['held_text'], upstream_ms, stream)
"""
))

# 5. restore inbound, non-streaming
EDITS.append((
    """            if decision['type'] == 'pass':
                self._relay_response(upstream_response)
            else:
                self._handle_fallback(decision, body, held_text, upstream_ms, stream)
""",
    """            if decision['type'] == 'pass':
                if VEIL is not None:
                    upstream_response = dict(upstream_response)
                    upstream_response['body'] = VEIL.restore_json_body(upstream_response['body'])
                self._relay_response(upstream_response)
            else:
                self._handle_fallback(decision, body, held_text, upstream_ms, stream)
"""
))

# 6. fail-closed responder
EDITS.append((
    "    def _relay_request(self):\n",
    """    def _veil_failed(self, reason):
        # Fail closed. Returning an error is noisy and obvious; forwarding an
        # unscrubbed body would be silent and would defeat the whole point.
        payload = {
            'type': 'error',
            'error': {
                'type': 'claudefuscator_scrub_failed',
                'message': f'Claudefuscator refused to forward this request unscrubbed: {reason}',
            },
        }
        self._relay_response({
            'status': 400,
            'body': json.dumps(payload),
            'headers': {'Content-Type': 'application/json'},
        })

    def _relay_request(self):
"""
))

for anchor, replacement in EDITS:
    count = src.count(anchor)
    if count != 1:
        print(f'ABORT: anchor found {count} times, expected 1:\n---\n{anchor[:200]}\n---')
        sys.exit(1)
    src = src.replace(anchor, replacement)

TARGET.write_text(src, encoding='utf-8')
print(f'patched {TARGET.name}: {len(EDITS)} edits applied')
