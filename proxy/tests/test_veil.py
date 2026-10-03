"""Tests for the proxy veil layer.

The claims under test, in order of how much damage a regression would do:

  1. No real identifier survives in an outbound request body - including in
     the prompt you typed, which the Claude Code hooks structurally cannot
     reach.
  2. Tool-call inputs come back RESTORED, so Write/Edit put real values on
     local disk. Tokens are a wire representation, not a storage format.
  3. A body that cannot be scrubbed is never forwarded (fail closed).
  4. Restoring never corrupts JSON, even when the real value contains
     characters that need escaping.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import veil as veil_mod  # noqa: E402

KEY = 'proxy-veil-test-key'
CONFIG = {
    'tokenLength': 8,
    'internalDomains': ['corp.example'],
    'identifiers': [
        {'type': 'PERSON', 'value': 'Jane Example', 'aliases': ['J. Example']},
        {'type': 'HOST', 'value': 'build-01.corp.example'},
        # A value whose restored form needs JSON escaping.
        {'type': 'PATH', 'value': 'C:\\Users\\jane\\"notes".txt'},
    ],
}

REAL_HOST = 'build-01.corp.example'
REAL_PERSON = 'Jane Example'
REAL_PATH = 'C:\\Users\\jane\\"notes".txt'


@pytest.fixture
def veil():
    return veil_mod.Veil(KEY, CONFIG)


def token_for(veil, value):
    out, _ = veil_mod.Veil(KEY, CONFIG).scrub_text(value)
    return out


# ---- outbound ---------------------------------------------------------

def test_typed_prompt_is_scrubbed(veil):
    """The gap the hooks cannot close: the user's own message."""
    body = json.dumps({
        'model': 'claude-opus-4',
        'messages': [{'role': 'user', 'content': f'why is {REAL_HOST} down? ask {REAL_PERSON}'}],
    }).encode()
    out, hits = veil.scrub_request_body(body)
    text = out.decode()
    assert REAL_HOST not in text
    assert REAL_PERSON not in text
    assert 'HOST_' in text and 'PERSON_' in text
    assert len(hits) == 2


def test_system_prompt_and_tool_results_are_scrubbed(veil):
    """CLAUDE.md content arrives as `system`; file reads arrive as
    tool_result blocks. Hooks reach neither / only the latter."""
    body = json.dumps({
        'model': 'm',
        'system': [{'type': 'text', 'text': f'Project host is {REAL_HOST}'}],
        'messages': [{
            'role': 'user',
            'content': [
                {'type': 'tool_result', 'tool_use_id': 'tu_1',
                 'content': [{'type': 'text', 'text': f'10.42.7.19 {REAL_HOST}'}]},
            ],
        }],
    }).encode()
    out, _ = veil.scrub_request_body(body)
    text = out.decode()
    assert REAL_HOST not in text
    assert '10.42.7.19' not in text
    # Structural fields survive untouched.
    assert json.loads(text)['messages'][0]['content'][0]['tool_use_id'] == 'tu_1'


def test_structural_fields_are_not_mangled(veil):
    body = json.dumps({
        'model': 'claude-opus-4-20250101',
        'max_tokens': 4096,
        'stream': True,
        'messages': [{'role': 'user', 'content': 'hello'}],
        'tools': [{
            'name': 'Read',
            'description': f'Read a file from {REAL_HOST}',
            'input_schema': {'type': 'object', 'properties': {'file_path': {'type': 'string'}}},
        }],
    }).encode()
    out, _ = veil.scrub_request_body(body)
    data = json.loads(out)
    assert data['model'] == 'claude-opus-4-20250101'
    assert data['max_tokens'] == 4096
    assert data['stream'] is True
    assert data['tools'][0]['name'] == 'Read'              # API surface, kept
    assert 'file_path' in data['tools'][0]['input_schema']['properties']
    assert REAL_HOST not in data['tools'][0]['description']  # prose, scrubbed


def test_unparseable_body_fails_closed(veil):
    with pytest.raises(veil_mod.VeilError):
        veil.scrub_request_body(b'not json at all')


# ---- inbound ----------------------------------------------------------

def _sse(events):
    out = []
    for etype, payload in events:
        out.append(f'event: {etype}')
        out.append('data: ' + json.dumps(payload))
        out.append('')
    return '\n'.join(out)


def test_text_deltas_are_restored(veil):
    host_token, _ = veil.scrub_text(REAL_HOST)
    body = _sse([
        ('message_start', {'type': 'message_start', 'message': {'id': 'm1'}}),
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': {'type': 'text_delta', 'text': f'Host {host_token}'}}),
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': {'type': 'text_delta', 'text': ' is down'}}),
        ('message_stop', {'type': 'message_stop'}),
    ])
    out = veil.restore_sse_body(body)
    assert REAL_HOST in out
    assert host_token not in out


def test_token_split_across_two_deltas_is_restored(veil):
    """The case that would break a naive per-chunk replacer."""
    host_token, _ = veil.scrub_text(REAL_HOST)
    half = len(host_token) // 2
    body = _sse([
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': {'type': 'text_delta', 'text': 'see ' + host_token[:half]}}),
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': {'type': 'text_delta', 'text': host_token[half:] + ' now'}}),
    ])
    out = veil.restore_sse_body(body)
    assert REAL_HOST in out, 'split token was not reassembled before restore'


def test_tool_use_input_is_restored_so_disk_gets_real_values(veil):
    """The guarantee behind "local disk gets deobfuscated values": the
    tool_use input is restored before Claude Code ever executes the call."""
    host_token, _ = veil.scrub_text(REAL_HOST)
    fragments = ['{"command": "ssh ', host_token, ' uptime"}']
    body = _sse([
        ('content_block_start', {'type': 'content_block_start', 'index': 0,
                                 'content_block': {'type': 'tool_use', 'id': 'tu_1', 'name': 'Bash'}}),
    ] + [
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': {'type': 'input_json_delta', 'partial_json': f}})
        for f in fragments
    ])
    out = veil.restore_sse_body(body)

    rebuilt = ''
    for line in out.split('\n'):
        if not line.startswith('data: '):
            continue
        payload = json.loads(line[6:])
        delta = payload.get('delta') or {}
        if delta.get('type') == 'input_json_delta':
            rebuilt += delta['partial_json']
    assert json.loads(rebuilt)['command'] == f'ssh {REAL_HOST} uptime'


def test_blocks_are_restored_independently(veil):
    host_token, _ = veil.scrub_text(REAL_HOST)
    person_token, _ = veil.scrub_text(REAL_PERSON)
    body = _sse([
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': {'type': 'text_delta', 'text': host_token}}),
        ('content_block_delta', {'type': 'content_block_delta', 'index': 1,
                                 'delta': {'type': 'text_delta', 'text': person_token}}),
    ])
    out = veil.restore_sse_body(body)
    assert REAL_HOST in out and REAL_PERSON in out


def test_restored_value_needing_json_escaping_keeps_the_stream_parseable(veil):
    """A naive string replace over the raw SSE body would emit a bare
    backslash and a bare quote inside a JSON string and corrupt it."""
    path_token, _ = veil.scrub_text(REAL_PATH)
    body = _sse([
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': {'type': 'text_delta', 'text': f'wrote {path_token}'}}),
    ])
    out = veil.restore_sse_body(body)
    payloads = [json.loads(l[6:]) for l in out.split('\n') if l.startswith('data: ')]
    assert payloads[0]['delta']['text'] == f'wrote {REAL_PATH}'


def test_unknown_tokens_are_left_alone(veil):
    body = _sse([
        ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                 'delta': {'type': 'text_delta', 'text': 'MAX_deadbeef HOST_zzzzzzzz'}}),
    ])
    assert veil.restore_sse_body(body) == body


def test_non_streaming_response_is_restored(veil):
    host_token, _ = veil.scrub_text(REAL_HOST)
    body = json.dumps({'content': [{'type': 'text', 'text': f'{host_token} is down'}]})
    out = veil.restore_json_body(body)
    assert json.loads(out)['content'][0]['text'] == f'{REAL_HOST} is down'


# ---- round trip -------------------------------------------------------

def test_full_round_trip_leaves_no_real_value_on_the_wire(veil):
    original = f'Deploy to {REAL_HOST} and tell {REAL_PERSON}, ip 10.42.7.19'
    body = json.dumps({'model': 'm', 'messages': [{'role': 'user', 'content': original}]}).encode()

    wire, _ = veil.scrub_request_body(body)
    wire_text = wire.decode()
    for real in [REAL_HOST, REAL_PERSON, '10.42.7.19', 'Jane', 'build-01']:
        assert real not in wire_text, f'{real} crossed the wire'

    # What comes back carries the same tokens; restore must undo it exactly.
    echoed = json.loads(wire)['messages'][0]['content']
    sse = _sse([('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                         'delta': {'type': 'text_delta', 'text': echoed}})])
    restored = json.loads(
        [l[6:] for l in veil.restore_sse_body(sse).split('\n') if l.startswith('data: ')][0]
    )['delta']['text']
    assert restored == original


# ---- configuration ----------------------------------------------------

def test_unconfigured_is_inert_not_broken(monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_KEY', raising=False)
    built, status = veil_mod.build_from_env()
    assert built is None
    assert 'INACTIVE' in status


def test_status_reports_active_when_configured(tmp_path, monkeypatch):
    cfg = tmp_path / 'ids.json'
    cfg.write_text(json.dumps(CONFIG), encoding='utf-8')
    monkeypatch.setenv('CLAUDEFUSCATOR_KEY', KEY)
    built, status = veil_mod.build_from_env(str(cfg))
    assert built is not None
    assert status.startswith('ACTIVE')
    assert '3 list entries' in status
