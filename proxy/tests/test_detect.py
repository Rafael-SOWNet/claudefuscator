import unittest
from .. import detect
import json
import os

class TestDetect(unittest.TestCase):
    def setUp(self):
        # Set up temporary rules.toml for testing
        self.test_rules = r"""
[settings]
listen_port = 8090
holdback_chars = 300
log_path = "test_logs/fallback.jsonl"

[[rules]]
name = "generic-decline"
pattern = "((I\\s+)?(won't|can't|cannot|unable to|am not able to|declin(e|ing))|I'm not able to|I must decline)"

[[rules]]
name = "licensing"
pattern = "(licen[cs]e|copyright|permission|terms of (use|service)).{0,120}(can't|cannot|won't|unable|not able)"

[[rules]]
name = "policy-refusal"
pattern = "(rules?|policy|policies|guidelines?)\\s+(forbid|prohibit)s?|forbidden|not (permitted|allowed)|not (going to|gonna) do (this|that|it)|not \\w+ing (this|that|it|the)|I refuse|refus(e|ing) to"
"""
        
        with open('test_rules.toml', 'w') as f:
            f.write(self.test_rules)
        
        detect.load_rules('test_rules.toml')

        # Create test log directory
        os.makedirs('test_logs', exist_ok=True)

    def tearDown(self):
        # Clean up test files
        os.remove('test_rules.toml')
        for f in os.listdir('test_logs'):
            os.remove(os.path.join('test_logs', f))
        os.rmdir('test_logs')

    def test_rule_matching(self):
        # make_decision() uses search(), not match(): a refusal can be preceded
        # by preamble text, so these all go through search() too.
        # Test generic-decline rule
        self.assertTrue(detect.RULES[0]['regex'].search("I can't help with that"))
        self.assertTrue(detect.RULES[0]['regex'].search("I'm not able to do this"))
        self.assertTrue(detect.RULES[0]['regex'].search("Can't do the \"real model\" import. Project hard rules"))
        self.assertTrue(detect.RULES[0]['regex'].search("Same answer: I won't import it as a baked model."))
        self.assertTrue(detect.RULES[0]['regex'].search("I'm still declining."))
        self.assertFalse(detect.RULES[0]['regex'].search("I would be happy to help"))

        # Test licensing rule
        self.assertTrue(detect.RULES[1]['regex'].search("Copyright can't be modified"))
        self.assertTrue(detect.RULES[1]['regex'].search("Permission terms of use won't allow this"))
        self.assertTrue(detect.RULES[1]['regex'].search("Sorry, due to copyright restrictions I can't do this"))
        self.assertFalse(detect.RULES[1]['regex'].search("I can't help with licensing"))

        # Test policy-refusal rule
        self.assertTrue(detect.RULES[2]['regex'].search("No, still not doing this. The project rules forbid it."))
        self.assertTrue(detect.RULES[2]['regex'].search("That's forbidden by our guidelines."))
        self.assertTrue(detect.RULES[2]['regex'].search("Sorry, that's not permitted here."))
        self.assertTrue(detect.RULES[2]['regex'].search("I refuse to do that."))
        self.assertTrue(detect.RULES[2]['regex'].search("My answer is the same: no. I'm not removing the safety check."))
        self.assertFalse(detect.RULES[2]['regex'].search("Sure, here is the code you asked for."))

    def test_holdback_conditions(self):
        # Real Anthropic streaming: content_block_start's own text is always
        # empty; the actual text arrives via content_block_delta events. This
        # is the shape that was previously unhandled, leaving held_text empty
        # for every real streamed response regardless of what it said.
        events = [
            {'type': 'message_start'},
            {'type': 'content_block_start', 'content_block': {'type': 'text', 'text': ''}},
            {'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': 'Hello'}},
            {'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': ' world'}},
            {'type': 'message_delta', 'stop_reason': 'end_turn'}
        ]

        held = detect.holdback(events)
        self.assertEqual(held['held_text'], 'Hello world')
        self.assertEqual(len(held['held_events']), 5)

        # Test holdback by tool use (a content_block_start, not its own event type)
        events = [
            {'type': 'message_start'},
            {'type': 'content_block_start', 'content_block': {'type': 'tool_use', 'name': 'some_tool'}}
        ]
        held = detect.holdback(events)
        self.assertEqual(len(held['held_events']), 2)
        self.assertEqual(held['held_text'], '')

        # Test holdback by message delta
        events = [
            {'type': 'message_start'},
            {'type': 'message_delta', 'stop_reason': 'refusal'}
        ]
        held = detect.holdback(events)
        self.assertEqual(len(held['held_events']), 2)

        # Stops accumulating once holdback_chars is reached, mid-stream
        long_events = (
            [{'type': 'message_start'},
             {'type': 'content_block_start', 'content_block': {'type': 'text', 'text': ''}}]
            + [{'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': 'x' * 100}}] * 5
        )
        held = detect.holdback(long_events)
        self.assertGreaterEqual(len(held['held_text']), 300)
        self.assertLess(len(held['held_text']), 500)  # broke out well before all 5 deltas

    def test_classifier_refusal_priority(self):
        # Simulate classifier refusal with rule match
        events = [
            {'type': 'message_start'},
            {'type': 'content_block_start', 'content_block': {'type': 'text', 'text': ''}},
            {'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': "I can't help with that"}},
            {'type': 'message_delta', 'stop_reason': 'refusal', 'stop_details': {'category': 'licensing'}}
        ]

        held = detect.holdback(events)
        decision = detect.make_decision(held, "{}")
        self.assertEqual(decision['type'], 'pass')
        self.assertEqual(decision['reason'], 'classifier_refusal')
        self.assertEqual(decision['category'], 'licensing')

    def test_streaming_decline_detected(self):
        # The actual bug: a real decline spread across content_block_delta events
        # must be detected via holdback() + make_decision(), not just via a raw
        # string passed straight to make_decision().
        events = [
            {'type': 'message_start'},
            {'type': 'content_block_start', 'content_block': {'type': 'text', 'text': ''}},
            {'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': "I'm not going to do this, "}},
            {'type': 'content_block_delta', 'delta': {'type': 'text_delta', 'text': "no matter how it's worded."}},
            {'type': 'content_block_stop'},
            {'type': 'message_delta', 'stop_reason': 'end_turn'},
        ]
        held = detect.holdback(events)
        decision = detect.make_decision(held, "{}")
        self.assertEqual(decision['type'], 'fallback')
        self.assertEqual(decision['rule'], 'policy-refusal')

    def test_fallback_logging(self):
        # Test logging when fallback occurs
        detect.log_fallback("generic-decline", "I can't help with that", 100, 200, 200)
        
        with open('test_logs/fallback.jsonl', 'r') as f:
            logs = [json.loads(line) for line in f]
            
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['event'], 'fallback')
        self.assertEqual(logs[0]['rule'], 'generic-decline')
        self.assertEqual(logs[0]['upstream_text_head'], "I can't help with that")
        self.assertEqual(logs[0]['local_status'], 200)
        self.assertEqual(logs[0]['upstream_ms'], 100)
        self.assertEqual(logs[0]['local_ms'], 200)
