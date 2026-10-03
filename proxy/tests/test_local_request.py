import unittest
from unittest import mock
import local_request
import json
import tomllib

class _FakeResponse:
    """Minimal stand-in for a requests.Response from llama-server."""

    def __init__(self, payload, status_code=200):
        self.status_code = status_code
        self.text = json.dumps(payload)
        self.reason = 'OK'
        self.headers = {'Content-Type': 'application/json'}

    def json(self):
        return json.loads(self.text)


class TestLocalRequest(unittest.TestCase):
    def setUp(self):
        # Set up temporary rules.toml for testing
        self.test_rules = r"""
[settings]
listen_port = 8090
holdback_chars = 300
local_url = "http://127.0.0.1:9931"
local_model = "qwen3-14b-local"
local_max_tokens = 8192
local_timeout_s = 600
log_path = "test_logs/fallback.jsonl"

[[rules]]
name = "generic-decline"
pattern = '''^\s*(I\s+(won't|can't|cannot|am not able to)|I'm not able to|I must decline)'''
"""
        
        with open('test_rules.toml', 'w') as f:
            f.write(self.test_rules)
        
        # Load settings
        with open('test_rules.toml', 'rb') as f:
            self.settings = tomllib.load(f)['settings']

    # KNOWN CONTRADICTION -- needs a decision, see proxy/PROXY-NOTES.md.
    # This test asserts cache_control is stripped as a key and the text
    # block kept; _sanitize drops any block carrying cache_control
    # outright, which is the documented behaviour. One of the two is
    # wrong. Left failing-on-purpose rather than edited to match the code.
    @unittest.expectedFailure
    def test_sanitize_request(self):
        original_request = {
            'messages': [
                {
                    'content': [
                        {'type': 'text', 'text': 'Hello, world!', 'cache_control': 'no-cache'},
                        {'type': 'thinking', 'text': 'This is a thinking block'}
                    ]
                }
            ],
            'system': {
                'content': [
                    {'type': 'text', 'text': 'System prompt', 'cache_control': 'max-age=3600'}
                ]
            },
            'tool_choice': 'auto',
            'max_tokens': 10000,
            'stream': True,
            'temperature': 0.7
        }
        
        # Test sanitization
        # _sanitize is the pure part; calling make_local_request here would
        # require a live llama-server on :9931.
        data = local_request._sanitize(original_request)
        
        # Check field whitelisting
        self.assertIn('messages', data)
        self.assertIn('system', data)
        self.assertIn('tool_choice', data)
        self.assertIn('max_tokens', data)
        self.assertIn('stream', data)
        self.assertIn('temperature', data)
        self.assertNotIn('tool_use', data)
        
        # Check thinking blocks and cache_control removal
        self.assertEqual(len(data['messages'][0]['content']), 1)
        self.assertEqual(data['messages'][0]['content'][0]['text'], 'Hello, world!')
        self.assertNotIn('cache_control', data['messages'][0]['content'][0])
        
        self.assertEqual(len(data['system']['content']), 1)
        self.assertEqual(data['system']['content'][0]['text'], 'System prompt')
        self.assertNotIn('cache_control', data['system']['content'][0])
        
        # Check max_tokens clamping
        self.assertEqual(data['max_tokens'], self.settings['local_max_tokens'])
        
        # Check model setting
        self.assertEqual(data['model'], self.settings['local_model'])

    def test_marker_injection(self):
        original_request = {
            'messages': [{'content': [{'type': 'text', 'text': "I can't help with that"}]}],
            'stream': False
        }
        
        # Simulate local server response
        local_response = {
            'content': [{'type': 'text', 'text': 'Local response'}],
            'model': 'qwen3-14b-local'
        }
        
        # Test non-streaming marker injection
        with mock.patch('local_request.requests.post') as post:
            post.return_value = _FakeResponse(local_response)
            response = local_request.make_local_request(
                json.dumps(original_request), 'generic-decline')
        data = json.loads(response['body'])
        
        self.assertEqual(len(data['content']), 2)
        self.assertEqual(data['content'][0]['text'], '⚠ [local fallback: rule "generic-decline"]\n\n')
        self.assertEqual(data['content'][1]['text'], 'Local response')
        

    # KNOWN MISMATCH -- needs a decision, see proxy/PROXY-NOTES.md.
    # This exercises the STREAMING marker, but calls make_local_request,
    # which is the non-streaming path and emits no per-block 'index'.
    # Real streaming goes through start_streaming_local_request, which
    # yields SSE strings, so these assertions do not apply to it as
    # written. Left failing-on-purpose rather than quietly reshaped.
    @unittest.expectedFailure
    def test_marker_injection_streaming(self):
        original_request = {
            'messages': [{'content': [{'type': 'text', 'text': "I can't help with that"}]}],
            'stream': False,
        }
        local_response = {
            'content': [{'type': 'text', 'text': 'Local response'}],
            'model': 'qwen3-14b-local',
        }
        # Test streaming marker injection
        original_request['stream'] = True
        local_response['content'] = [{'type': 'text', 'text': 'Local response', 'index': 0}]
        
        with mock.patch('local_request.requests.post') as post:
            post.return_value = _FakeResponse(local_response)
            response = local_request.make_local_request(
                json.dumps(original_request), 'generic-decline')
        data = json.loads(response['body'])
        
        self.assertEqual(len(data['content']), 2)
        self.assertEqual(data['content'][0]['text'], '⚠ [local fallback: rule "generic-decline"]\n\n')
        self.assertEqual(data['content'][0]['index'], 0)
        self.assertEqual(data['content'][1]['text'], 'Local response')
        self.assertEqual(data['content'][1]['index'], 1)