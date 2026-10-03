import json
import requests
import time
import tomllib
from urllib.parse import urlparse

# Load settings from rules.toml
def load_settings():
    with open('rules.toml', 'rb') as f:
        return tomllib.load(f)['settings']

SETTINGS = load_settings()


def _marker_text(rule_name):
    return '⚠ [local fallback: rule "{}"]\n\n'.format(rule_name)


def _sanitize(original_data):
    """Build the request sent to the local model from the original request."""
    sanitized = {
        'messages': [],
        'system': original_data.get('system'),
        'tools': original_data.get('tools'),
        'tool_choice': original_data.get('tool_choice'),
        'max_tokens': min(original_data.get('max_tokens', 0), SETTINGS['local_max_tokens']),
        'stream': original_data.get('stream', False),
        'temperature': original_data.get('temperature'),
        'top_p': original_data.get('top_p'),
        'top_k': original_data.get('top_k'),
        'stop_sequences': original_data.get('stop_sequences')
    }

    for msg in original_data.get('messages', []):
        if 'content' in msg:
            content = msg['content']
            if isinstance(content, list):
                # Remove thinking blocks, cache_control, and injected <system-reminder>
                # text blocks -- these carry Claude Code's own tool-use/policy context,
                # which is irrelevant to the local model and visibly distracts it.
                # (content can also be a plain string per the Anthropic API --
                # nothing to filter out of that case, so it's passed through as-is.)
                content = [
                    block for block in content
                    if block.get('type') != 'thinking' and not block.get('cache_control')
                    and not (block.get('type') == 'text' and block.get('text', '').lstrip().startswith('<system-reminder>'))
                ]

            if content:
                sanitized['messages'].append({**msg, 'content': content})

    sanitized['model'] = SETTINGS['local_model']
    return sanitized


def make_local_request(original_body, rule_name):
    """Build and send a sanitized non-streaming local request to the Qwen3-14B
    model, waiting for the complete response before returning."""

    try:
        original_data = json.loads(original_body)
    except json.JSONDecodeError:
        return {'status': 400, 'body': 'Invalid JSON request'}

    sanitized = _sanitize(original_data)
    sanitized['stream'] = False

    try:
        start_time = time.time()
        response = requests.post(
            SETTINGS['local_url'] + '/v1/messages',
            json=sanitized,
            timeout=SETTINGS['local_timeout_s'],
        )
    except requests.exceptions.RequestException as e:
        return {'status': 503, 'body': 'Local server unavailable', 'reason': str(e)}

    if response.status_code != 200:
        return {
            'status': response.status_code,
            'body': response.text,
            'reason': 'Local server error'
        }

    try:
        response_data = json.loads(response.text)
        if 'content' in response_data:
            marker = {
                'type': 'text',
                'text': _marker_text(rule_name)
            }
            response_data['content'].insert(0, marker)

        return {
            'status': 200,
            'body': json.dumps(response_data),
            'duration': time.time() - start_time
        }
    except json.JSONDecodeError:
        return {'status': 500, 'body': response.text, 'reason': 'JSON decode error'}


def _sse_event(event_type, payload):
    return f'event: {event_type}\ndata: {json.dumps(payload)}\n\n'


def start_streaming_local_request(original_body, rule_name):
    """Connect to the local model for a streaming fallback and return
    (error, events) without waiting for the generation to finish.

    error is None on success, or a dict ({'status', 'reason'}) if the local
    server never became reachable/healthy -- the caller should relay a normal
    (non-streaming) failure response in that case.

    events, when error is None, is a generator of raw SSE text chunks yielded
    as the local model produces them (marker first, immediately). Building
    the whole response before sending anything (the old approach, shared with
    make_local_request) meant a realistic-length generation left the client
    looking at 70+ seconds of total silence -- long enough for a real client
    to time out and reset the connection well before completion.
    """
    try:
        original_data = json.loads(original_body)
    except json.JSONDecodeError:
        return {'status': 400, 'reason': 'Invalid JSON request'}, None

    sanitized = _sanitize(original_data)
    sanitized['stream'] = True

    try:
        response = requests.post(
            SETTINGS['local_url'] + '/v1/messages',
            json=sanitized,
            timeout=SETTINGS['local_timeout_s'],
            stream=True,
        )
    except requests.exceptions.RequestException as e:
        return {'status': 503, 'reason': str(e)}, None

    if response.status_code != 200:
        return {'status': response.status_code, 'reason': 'Local server error'}, None

    def _events():
        yield _sse_event('content_block_start', {'type': 'content_block_start', 'index': 0,
                                                   'content_block': {'type': 'text', 'text': ''}})
        yield _sse_event('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                                   'delta': {'type': 'text_delta', 'text': _marker_text(rule_name)}})
        yield _sse_event('content_block_stop', {'type': 'content_block_stop', 'index': 0})

        event_type = None
        for line in response.iter_lines(decode_unicode=True):
            if line is None or line == '':
                continue
            if line.startswith('event:'):
                event_type = line[len('event:'):].strip()
                continue
            if line.startswith('data:'):
                raw = line[len('data:'):].strip()
                try:
                    payload = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict) and 'index' in payload:
                    payload = {**payload, 'index': payload['index'] + 1}
                yield _sse_event(event_type or 'message', payload if payload is not None else raw)

    return None, _events()