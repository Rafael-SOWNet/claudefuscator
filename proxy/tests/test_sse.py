import unittest
from .. import sse

class TestSSE(unittest.TestCase):
    def test_parse_sse(self):
        test_data = """
event: message_start
data: {\"model\": \"claude-3-sonnet-20240229\"}

event: content_block_start
data: {\"type\": \"text\", \"text\": \"Hello,\"}

event: content_block_delta
data: {\"type\": \"text\", \"partial_text\": \" world!\"}

event: message_delta
data: {\"stop_reason\": \"end_turn\"}

"""
        
        events = sse.parse_sse(test_data)
        
        self.assertEqual(len(events), 4)
        self.assertEqual(events[0]['type'], 'message_start')
        self.assertEqual(events[1]['type'], 'content_block_start')
        self.assertEqual(events[2]['type'], 'content_block_delta')
        self.assertEqual(events[3]['type'], 'message_delta')

    def test_serialize_sse(self):
        events = [
            {'type': 'message_start', 'data': {'model': 'claude-3-sonnet-20240229'}},
            {'type': 'content_block_start', 'content': {'type': 'text', 'text': 'Hello,'}},
            {'type': 'content_block_delta', 'partial_text': ' world!'},
            {'type': 'message_delta', 'stop_reason': 'end_turn'}
        ]
        
        sse_stream = sse.serialize_sse(events)
        
        self.assertIn('event: message_start', sse_stream)
        self.assertIn('data: {"model": "claude-3-sonnet-20240229"}', sse_stream)
        self.assertIn('event: content_block_start', sse_stream)
        self.assertIn('data: {"type": "text", "text": "Hello,"}', sse_stream)
        self.assertIn('event: content_block_delta', sse_stream)
        self.assertIn('data: {"type": "text", "partial_text": " world!"}', sse_stream)
        self.assertIn('event: message_delta', sse_stream)
        self.assertIn('data: {"stop_reason": "end_turn"}', sse_stream)

    def test_parse_multi_line_data(self):
        test_data = """
event: content_block_start
data: First line\nSecond line\nThird line
"""
        
        events = sse.parse_sse(test_data)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['type'], 'content_block_start')
        self.assertEqual(events[0]['data'], 'First line\nSecond line\nThird line')

    def test_parse_partial_chunk(self):
        test_data = """
event: content_block_delta
data: Hello,
""" + """
data: world!\n"""
        
        events = sse.parse_sse(test_data)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['type'], 'content_block_delta')
        self.assertEqual(events[0]['data'], 'Hello,\nworld!\n')