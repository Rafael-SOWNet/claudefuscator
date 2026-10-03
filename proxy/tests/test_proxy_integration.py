"""End-to-end test of the patched proxy against a FAKE Anthropic upstream.

This is the test that actually proves the product claim, because it inspects
the bytes an upstream server received rather than the bytes a unit test fed
in. The fake upstream records every request body verbatim; the assertions are
that no real identifier appears anywhere in it.

No network access and no API key: the fake upstream is a local HTTP server on
an ephemeral port.
"""

import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import lite_llm_proxy  # noqa: E402
import veil as veil_mod  # noqa: E402

KEY = 'proxy-integration-test-key'
CONFIG = {
    'tokenLength': 8,
    'internalDomains': ['corp.example'],
    'identifiers': [
        {'type': 'PERSON', 'value': 'Jane Example', 'aliases': ['J. Example']},
        {'type': 'HOST', 'value': 'build-01.corp.example'},
    ],
}

REAL_HOST = 'build-01.corp.example'
REAL_PERSON = 'Jane Example'
REAL_IP = '10.42.7.19'

# Every real string that must never appear in what upstream received.
FORBIDDEN = [REAL_HOST, REAL_PERSON, REAL_IP, 'build-01', 'Jane', 'Example']


class _FakeUpstream(BaseHTTPRequestHandler):
    """Records what it was sent and echoes the tokens back in an SSE stream."""

    received = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(length)
        _FakeUpstream.received.append(raw.decode('utf-8'))

        data = json.loads(raw)
        # Echo the last user message back, so whatever tokens went up come
        # back down and the restore path is exercised with real token values.
        content = data['messages'][-1]['content']
        echoed = content if isinstance(content, str) else content[-1].get('text', '')

        if data.get('stream'):
            body = _sse([
                ('message_start', {'type': 'message_start', 'message': {'id': 'msg_1'}}),
                ('content_block_start', {'type': 'content_block_start', 'index': 0,
                                         'content_block': {'type': 'text', 'text': ''}}),
                # Split mid-string to exercise cross-delta reassembly.
                ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                         'delta': {'type': 'text_delta',
                                                   'text': 'Echo: ' + echoed[:len(echoed) // 2]}}),
                ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                         'delta': {'type': 'text_delta',
                                                   'text': echoed[len(echoed) // 2:]}}),
                ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
                ('message_delta', {'type': 'message_delta', 'stop_reason': 'end_turn'}),
                ('message_stop', {'type': 'message_stop'}),
            ]).encode()
            ctype = 'text/event-stream'
        else:
            body = json.dumps({
                'id': 'msg_1', 'type': 'message', 'role': 'assistant',
                'content': [{'type': 'text', 'text': 'Echo: ' + echoed}],
                'stop_reason': 'end_turn',
            }).encode()
            ctype = 'application/json'

        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _sse(events):
    out = []
    for etype, payload in events:
        out.append(f'event: {etype}')
        out.append('data: ' + json.dumps(payload))
        out.append('')
    return '\n'.join(out)


def _serve(handler):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f'http://127.0.0.1:{server.server_address[1]}'


@pytest.fixture
def stack(monkeypatch):
    """Fake upstream + the real patched proxy, both on ephemeral ports."""
    _FakeUpstream.received = []
    upstream, upstream_url = _serve(_FakeUpstream)

    monkeypatch.setitem(lite_llm_proxy.SETTINGS, 'upstream_url', upstream_url)
    monkeypatch.setattr(lite_llm_proxy, 'VEIL', veil_mod.Veil(KEY, CONFIG))

    proxy, proxy_url = _serve(lite_llm_proxy.ProxyHandler)
    try:
        yield proxy_url
    finally:
        proxy.shutdown()
        upstream.shutdown()


def _post(proxy_url, payload):
    return requests.post(
        proxy_url + '/v1/messages',
        data=json.dumps(payload),
        headers={'Content-Type': 'application/json'},
        timeout=30,
    )


def _assert_upstream_clean():
    assert _FakeUpstream.received, 'upstream received nothing'
    for body in _FakeUpstream.received:
        for real in FORBIDDEN:
            assert real not in body, f'{real!r} reached upstream in: {body[:400]}'


# ---- the core claim ---------------------------------------------------

def test_streaming_request_reaches_upstream_scrubbed(stack):
    resp = _post(stack, {
        'model': 'claude-opus-4',
        'stream': True,
        'max_tokens': 100,
        'messages': [{'role': 'user',
                      'content': f'why is {REAL_HOST} at {REAL_IP} down? ask {REAL_PERSON}'}],
    })
    assert resp.status_code == 200
    _assert_upstream_clean()
    # ...and the tokens are actually there, so the hit was not simply dropped.
    assert 'HOST_' in _FakeUpstream.received[0]
    assert 'PERSON_' in _FakeUpstream.received[0]
    assert 'IP_' in _FakeUpstream.received[0]


def test_client_gets_real_values_back(stack):
    """Restore on the way down, including across the delta split the fake
    upstream deliberately introduces."""
    resp = _post(stack, {
        'model': 'm', 'stream': True, 'max_tokens': 100,
        'messages': [{'role': 'user', 'content': f'check {REAL_HOST} please'}],
    })
    assert REAL_HOST in resp.text, 'client did not get the real value back'
    assert 'HOST_' not in resp.text, 'a token leaked through to the client'


def test_non_streaming_round_trip(stack):
    resp = _post(stack, {
        'model': 'm', 'stream': False, 'max_tokens': 100,
        'messages': [{'role': 'user', 'content': f'ping {REAL_HOST}'}],
    })
    _assert_upstream_clean()
    assert REAL_HOST in resp.json()['content'][0]['text']


def test_system_prompt_is_scrubbed(stack):
    """CLAUDE.md content arrives here; no hook can reach it."""
    _post(stack, {
        'model': 'm', 'stream': False, 'max_tokens': 100,
        'system': [{'type': 'text', 'text': f'The build host is {REAL_HOST}.'}],
        'messages': [{'role': 'user', 'content': 'hello'}],
    })
    _assert_upstream_clean()


def test_tool_results_are_scrubbed(stack):
    _post(stack, {
        'model': 'm', 'stream': False, 'max_tokens': 100,
        'messages': [
            {'role': 'user', 'content': 'read it'},
            {'role': 'assistant', 'content': [
                {'type': 'tool_use', 'id': 'tu_1', 'name': 'Read', 'input': {'file_path': '/etc/hosts'}}]},
            {'role': 'user', 'content': [
                {'type': 'tool_result', 'tool_use_id': 'tu_1',
                 'content': f'{REAL_IP} {REAL_HOST}'}]},
        ],
    })
    _assert_upstream_clean()


def test_model_and_structure_survive(stack):
    _post(stack, {
        'model': 'claude-opus-4-20250101', 'stream': False, 'max_tokens': 1234,
        'messages': [{'role': 'user', 'content': f'hi from {REAL_HOST}'}],
    })
    sent = json.loads(_FakeUpstream.received[0])
    assert sent['model'] == 'claude-opus-4-20250101'
    assert sent['max_tokens'] == 1234


# ---- failure behaviour ------------------------------------------------

def test_unscrubbable_body_is_not_forwarded(stack):
    """Fail closed: a body the veil cannot parse must never reach upstream."""
    resp = requests.post(
        stack + '/v1/messages',
        data=b'{ this is not json',
        headers={'Content-Type': 'application/json'},
        timeout=30,
    )
    assert resp.status_code == 400
    assert resp.json()['error']['type'] == 'claudefuscator_scrub_failed'
    assert not _FakeUpstream.received, 'an unscrubbable body was forwarded anyway'


def test_unconfigured_proxy_relays_unchanged(monkeypatch):
    """Inert when unconfigured, rather than blocking every request."""
    _FakeUpstream.received = []
    upstream, upstream_url = _serve(_FakeUpstream)
    monkeypatch.setitem(lite_llm_proxy.SETTINGS, 'upstream_url', upstream_url)
    monkeypatch.setattr(lite_llm_proxy, 'VEIL', None)
    proxy, proxy_url = _serve(lite_llm_proxy.ProxyHandler)
    try:
        resp = _post(proxy_url, {
            'model': 'm', 'stream': False, 'max_tokens': 10,
            'messages': [{'role': 'user', 'content': f'hi {REAL_HOST}'}],
        })
        assert resp.status_code == 200
        # Unconfigured means NOT scrubbing - assert that honestly rather than
        # letting a passing test imply protection that is not there.
        assert REAL_HOST in _FakeUpstream.received[0]
    finally:
        proxy.shutdown()
        upstream.shutdown()


def test_health_reports_veil_status(stack):
    body = requests.get(stack + '/health', timeout=10).json()
    assert body['status'] == 'ok'
    assert 'claudefuscator' in body


# ---- /mappings -------------------------------------------------------

def test_mappings_requires_the_key_derived_header(stack):
    """It serves REAL values, so an unauthenticated read must fail."""
    r = requests.get(stack + '/mappings', timeout=10)
    assert r.status_code == 403
    assert 'auth' in r.json()['error']
    assert 'Jane' not in r.text


def test_mappings_rejects_a_wrong_token(stack):
    r = requests.get(stack + '/mappings',
                     headers={'x-claudefuscator-auth': 'f' * 32}, timeout=10)
    assert r.status_code == 403


def test_mappings_serves_the_table_to_a_caller_holding_the_key(stack):
    import claudefuscator_core as core
    auth = core.hmac_hex(KEY, 'claudefuscator/mappings/v1')[:32]
    r = requests.get(stack + '/mappings',
                     headers={'x-claudefuscator-auth': auth}, timeout=10)
    assert r.status_code == 200
    body = r.json()
    assert body['count'] == len(body['mappings'])
    assert REAL_HOST in body['mappings'].values()
    assert r.headers.get('Cache-Control') == 'no-store'


def test_mappings_includes_discovered_values(stack):
    """The part the browser cannot derive for itself: a pattern hit whose
    real value nothing else recorded."""
    import claudefuscator_core as core
    _post(stack, {
        'model': 'm', 'stream': False, 'max_tokens': 10,
        'messages': [{'role': 'user', 'content': 'the box at 10.44.2.9 is down'}],
    })
    auth = core.hmac_hex(KEY, 'claudefuscator/mappings/v1')[:32]
    body = requests.get(stack + '/mappings',
                        headers={'x-claudefuscator-auth': auth}, timeout=10).json()
    assert '10.44.2.9' in body['mappings'].values(), 'pattern hit was not recorded'


def test_mappings_is_unavailable_when_unconfigured(monkeypatch):
    _FakeUpstream.received = []
    upstream, upstream_url = _serve(_FakeUpstream)
    monkeypatch.setitem(lite_llm_proxy.SETTINGS, 'upstream_url', upstream_url)
    monkeypatch.setattr(lite_llm_proxy, 'VEIL', None)
    proxy, proxy_url = _serve(lite_llm_proxy.ProxyHandler)
    try:
        r = requests.get(proxy_url + '/mappings', timeout=10)
        assert r.status_code == 503
    finally:
        proxy.shutdown()
        upstream.shutdown()
