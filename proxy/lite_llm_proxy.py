import http.server
import hmac
import socketserver
import re
import tomllib
import json
import time
import threading
from urllib.parse import urlparse
import requests
import sse
import detect
import local_request
import veil as veil_mod

PORT = 8090

# start-claude.ps1 -Bare sends this exact dummy key to signal "skip upstream
# entirely and serve every request from the local model" -- talking straight
# to the local server would skip the <system-reminder> stripping below.
LOCAL_ONLY_API_KEY = 'local-no-key'

# Headers that are specific to a single hop and must not be copied
# verbatim between the client <-> proxy <-> upstream/local legs.
# content-encoding is included because `requests` transparently decompresses
# the upstream body (resp.text/resp.content) while leaving the original
# Content-Encoding header in resp.headers -- relaying it verbatim would tell
# the client to decompress an already-decompressed body.
_HOP_BY_HOP_HEADERS = {'connection', 'keep-alive', 'transfer-encoding', 'content-length', 'host', 'content-encoding'}


def _load_settings(path='rules.toml'):
    with open(path, 'rb') as f:
        return tomllib.load(f)['settings']


SETTINGS = _load_settings()

# Claudefuscator. Built once at import. None means "not configured", in which
# case the proxy relays unchanged -- the same inert-when-unconfigured rule the
# Claude Code side follows, because a privacy tool that bricks every request
# when unconfigured just gets switched off.
VEIL, VEIL_STATUS = veil_mod.build_from_env()
print(f'Claudefuscator: {VEIL_STATUS}')


def _strip_dollar_override(body):
    """If the latest user message's text starts with "$", strip that character
    and signal that the request should skip upstream entirely and go straight
    to the local fallback model -- a manual override independent of detect's
    refusal-pattern rules."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body, False

    for msg in reversed(data.get('messages', [])):
        if msg.get('role') != 'user':
            continue

        content = msg.get('content')
        if isinstance(content, str):
            if not content.startswith('$'):
                return body, False
            msg['content'] = content[1:]
            return json.dumps(data).encode('utf-8'), True

        if isinstance(content, list):
            # The client's own typed message is the *last* text block -- real
            # requests prepend injected context (e.g. <system-reminder> blocks)
            # as earlier text blocks in the same message.
            text_blocks = [b for b in content if b.get('type') == 'text']
            if not text_blocks:
                return body, False
            block = text_blocks[-1]
            text = block.get('text', '')
            if not text.startswith('$'):
                return body, False
            block['text'] = text[1:]
            return json.dumps(data).encode('utf-8'), True
        return body, False

    return body, False


def _normalize_events(events):
    """Merge each SSE event's JSON data payload into its own dict.

    sse.parse_sse() only gives back {'type', 'data': <raw json string>};
    detect.holdback()/make_decision() expect the payload's fields (e.g.
    content_block, stop_reason) hoisted onto the event itself.
    """
    normalized = []
    for event in events:
        entry = {'type': event['type']}
        raw = event.get('data', '').strip()
        if raw:
            try:
                entry.update(json.loads(raw))
            except json.JSONDecodeError:
                pass
        normalized.append(entry)
    return normalized


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/mappings':
            self._serve_mappings()
            return
        if self.path != '/health':
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({'status': 'ok', 'claudefuscator': VEIL_STATUS}).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Compare the path only, not the raw request target: real clients append
        # a query string (observed: "/v1/messages?beta=true"), and an exact-string
        # comparison against '/v1/messages' silently fails for every real request,
        # falling through to the plain relay and skipping detection entirely.
        parsed_url = urlparse(self.path)
        if parsed_url.path != '/v1/messages':
            self._relay_request()
            return

        # Parse request body
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        # Check if streaming. This is a body field per the real Anthropic API
        # ("stream": true), not a query param -- a real client never sets
        # ?stream=true, so reading it from the query string always came back
        # False, silently mis-parsing every real SSE response as plain JSON.
        try:
            stream = json.loads(body).get('stream', False)
        except json.JSONDecodeError:
            stream = False

        local_only_mode = self.headers.get('x-api-key') == LOCAL_ONLY_API_KEY

        # Manual override: a prompt starting with "$" skips the real model
        # entirely and goes straight to the local fallback, "$" stripped.
        body, forced_fallback = _strip_dollar_override(body)

        if local_only_mode or forced_fallback:
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

        # Handle response
        if upstream_response['status'] != 200:
            self._relay_response(upstream_response)
            return

        # Process streaming response
        if stream:
            events = _normalize_events(sse.parse_sse(upstream_response['body']))
            holdback = detect.holdback(events)
            decision = detect.make_decision(holdback, body)

            if decision['type'] == 'pass':
                out = upstream_response['body']
                if VEIL is not None:
                    out = VEIL.restore_sse_body(out)
                self._relay_events(out)
            else:
                # Fallback gets the ORIGINAL body: local model, real values.
                self._handle_fallback(decision, body, holdback['held_text'], upstream_ms, stream)
        else:
            # Non-streaming case
            response_data = json.loads(upstream_response['body'])
            held_text = response_data['content'][0]['text']
            decision = detect.make_decision(held_text, body)

            if decision['type'] == 'pass':
                if VEIL is not None:
                    upstream_response = dict(upstream_response)
                    upstream_response['body'] = VEIL.restore_json_body(upstream_response['body'])
                self._relay_response(upstream_response)
            else:
                self._handle_fallback(decision, body, held_text, upstream_ms, stream)

    def _forward_to_upstream(self, body, stream):
        # Forward the request to the upstream model server and return its
        # response as a plain dict: {status, body, headers, reason}.
        headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in _HOP_BY_HOP_HEADERS
        }
        try:
            resp = requests.post(
                SETTINGS['upstream_url'] + self.path,
                data=body,
                headers=headers,
                timeout=SETTINGS.get('upstream_timeout_s', 600),
            )
        except requests.exceptions.RequestException as e:
            return {'status': 502, 'body': '', 'headers': {}, 'reason': str(e)}

        return {
            'status': resp.status_code,
            'body': resp.text,
            'headers': dict(resp.headers),
            'reason': resp.reason,
        }

    def _relay_events(self, raw_sse_body):
        # Relay the upstream SSE stream back to the client, byte-for-byte.
        body = raw_sse_body.encode('utf-8') if isinstance(raw_sse_body, str) else raw_sse_body
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _relay_response(self, response):
        # Relay a plain HTTP response (status/headers/body dict) back to the client.
        body = response['body']
        body_bytes = body.encode('utf-8') if isinstance(body, str) else body
        self.send_response(response['status'])
        for key, value in response.get('headers', {}).items():
            if key.lower() not in _HOP_BY_HOP_HEADERS:
                self.send_header(key, value)
        self.send_header('Content-Length', str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)

    def _handle_fallback(self, decision, original_body, held_text, upstream_ms, stream):
        if stream:
            self._stream_fallback(decision, original_body, held_text, upstream_ms)
            return

        # Non-streaming: a single JSON response either way, so waiting for the
        # complete generation before replying is normal, expected behavior.
        local_response = local_request.make_local_request(original_body, decision['rule'])

        if local_response['status'] != 200:
            reason = local_response.get('reason', local_response['body'])
            detect.log_fallback(decision['rule'], held_text, upstream_ms, 0, local_response['status'])
            self._relay_fallback_failure(decision, reason)
        else:
            local_ms = local_response.get('duration', 0) * 1000
            detect.log_fallback(decision['rule'], held_text, upstream_ms, local_ms, 200)
            self._relay_response({
                'status': 200,
                'body': local_response['body'],
                'headers': {'Content-Type': 'application/json'},
            })

    def _stream_fallback(self, decision, original_body, held_text, upstream_ms):
        # Streaming: write each SSE chunk to the client as the local model
        # produces it, instead of building the whole response first. A
        # realistic-length generation buffered in full left the client with
        # 70+ seconds of total silence -- long enough to time out and reset
        # the connection well before the response completed.
        start_time = time.time()
        error, events = local_request.start_streaming_local_request(original_body, decision['rule'])

        if error is not None:
            detect.log_fallback(decision['rule'], held_text, upstream_ms, 0, error['status'])
            self._relay_fallback_failure(decision, error['reason'])
            return

        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

        # A large conversation can mean minutes of local prompt processing
        # before the model emits its first token -- streaming the marker
        # immediately isn't enough on its own, since the client can still see
        # a long silent gap afterward and decide the connection has stalled.
        # SSE comment lines (": ...") are spec-defined no-ops for exactly this
        # keep-alive purpose; ping one periodically until real content flows.
        write_lock = threading.Lock()
        stop_pinging = threading.Event()

        def _keepalive():
            while not stop_pinging.wait(timeout=10):
                with write_lock:
                    try:
                        self.wfile.write(b': keepalive\n\n')
                        self.wfile.flush()
                    except OSError:
                        return

        pinger = threading.Thread(target=_keepalive, daemon=True)
        pinger.start()
        try:
            for chunk in events:
                with write_lock:
                    self.wfile.write(chunk.encode('utf-8'))
                    self.wfile.flush()
        finally:
            stop_pinging.set()
            pinger.join(timeout=1)

        local_ms = (time.time() - start_time) * 1000
        detect.log_fallback(decision['rule'], held_text, upstream_ms, local_ms, 200)

    def _relay_fallback_failure(self, decision, reason):
        # Local fallback failed too; tell the client rather than silently hanging.
        payload = {
            'type': 'error',
            'error': {
                'type': 'fallback_failed',
                'message': f'Local fallback for rule "{decision["rule"]}" failed: {reason}',
            },
        }
        self._relay_response({
            'status': 502,
            'body': json.dumps(payload),
            'headers': {'Content-Type': 'application/json'},
        })

    def _serve_mappings(self):
        """token -> real value, for the Chrome extension.

        The browser side can derive a token for anything on its own list, but
        not for a pattern hit (an IP, an email, a host nobody listed): those
        exist only here. Serving them lets the extension restore them too.

        Served on the loopback interface only, and only to a caller that
        proves it holds the same key. No CORS headers, so a web page cannot
        read the response; the header check is what stops another local
        process. The values are real, so treat this endpoint as sensitive.
        """
        if VEIL is None:
            self._relay_response({
                'status': 503,
                'body': json.dumps({'error': 'Claudefuscator is not configured'}),
                'headers': {'Content-Type': 'application/json'},
            })
            return

        presented = self.headers.get('x-claudefuscator-auth') or ''
        expected = VEIL.auth_token()
        # Constant-time compare: this guards real identifier values.
        if not hmac.compare_digest(presented, expected):
            self._relay_response({
                'status': 403,
                'body': json.dumps({'error': 'bad or missing x-claudefuscator-auth'}),
                'headers': {'Content-Type': 'application/json'},
            })
            return

        mappings = VEIL.mappings()
        self._relay_response({
            'status': 200,
            'body': json.dumps({'mappings': mappings, 'count': len(mappings)}),
            'headers': {
                'Content-Type': 'application/json',
                'Cache-Control': 'no-store',
            },
        })

    def _veil_failed(self, reason):
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
        # Relay non-/v1/messages requests to the upstream API server unchanged.
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''
        response = self._forward_to_upstream(body, False)
        self._relay_response(response)

if __name__ == '__main__':
    with socketserver.TCPServer(('', PORT), ProxyHandler) as httpd:
        print(f'Starting proxy on port {PORT}')
        httpd.serve_forever()
