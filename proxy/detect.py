import tomllib
import re
import json
from datetime import datetime
import os

# Load rules from rules.toml
RULES = []
SETTINGS = {}

def load_rules(path='rules.toml'):
    """Load rules from a rules TOML file"""
    global RULES, SETTINGS

    with open(path, 'rb') as f:
        config = tomllib.load(f)
        
    SETTINGS['listen_port'] = config['settings']['listen_port']
    SETTINGS['holdback_chars'] = config['settings']['holdback_chars']
    SETTINGS['log_path'] = config['settings']['log_path']
    
    RULES = []
    for rule_config in config['rules']:
        name = rule_config['name']
        pattern = rule_config['pattern']
        
        # Compile regex pattern
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            raise ValueError(f"Invalid regex in rule '{name}': {pattern}")
        
        RULES.append({'name': name, 'regex': regex})

# Initialize rules at startup
load_rules()

def holdback(events):
    """Hold events until holdback condition is met"""
    held_events = []
    held_text = ''

    for event in events:
        etype = event['type']
        if etype == 'message_start':
            # Start holding
            held_events.append(event)
        elif etype == 'content_block_start' and event.get('content_block', {}).get('type') == 'tool_use':
            # A tool call, not text -- nothing to inspect for a refusal.
            held_events.append(event)
            break
        elif etype == 'content_block_start' and event.get('content_block', {}).get('type') == 'text':
            # content_block_start's own text is always empty in real Anthropic
            # streaming; kept for the (harmless) case it isn't.
            held_events.append(event)
            held_text += event['content_block'].get('text', '')
            if len(held_text) >= SETTINGS['holdback_chars']:
                break
        elif etype == 'content_block_delta' and event.get('delta', {}).get('type') == 'text_delta':
            # This is where the actual streamed text arrives -- previously
            # unhandled, so held_text stayed empty and nothing ever matched.
            held_events.append(event)
            held_text += event['delta'].get('text', '')
            if len(held_text) >= SETTINGS['holdback_chars']:
                break
        elif etype == 'message_delta' and 'stop_reason' in event:
            # Stop holding on message delta with stop reason
            held_events.append(event)
            break
        elif etype == 'message_stop':
            # Stop holding on message stop
            held_events.append(event)
            break
        else:
            # Continue relaying other events
            pass

    return {'held_events': held_events, 'held_text': held_text}

def make_decision(held, original_request):
    """Make decision to pass or fallback.

    `held` is either the dict returned by holdback() (streaming case) or a
    plain string of already-complete response text (non-streaming case).
    """
    if isinstance(held, dict):
        held_events = held.get('held_events', [])
        held_text = held.get('held_text', '')
    else:
        held_events = []
        held_text = held

    # Check for classifier refusal
    for event in held_events:
        if event['type'] == 'message_delta' and 'stop_reason' in event:
            if event['stop_reason'] == 'refusal':
                # Classifier refusal, pass through
                return {
                    'type': 'pass',
                    'reason': 'classifier_refusal',
                    'category': event.get('stop_details', {}).get('category')
                }

    # Check for rule matches. search(), not match(): a refusal is often preceded
    # by preamble text ("Same answer: I won't..."), not the literal first characters.
    for rule in RULES:
        if held_text and rule['regex'].search(held_text):
            return {
                'type': 'fallback',
                'rule': rule['name']
            }

    # No match, pass through
    return {'type': 'pass'}

def log_fallback(rule_name, held_text, upstream_time, local_time, status):
    """Log fallback event to JSONL file"""
    log_entry = {
        'ts': datetime.now().isoformat(),
        'request_id': 'proxy-generated-id',  # Placeholder for actual ID
        'event': 'fallback' if status == 200 else 'fallback_failed',
        'rule': rule_name,
        'upstream_text_head': held_text[:SETTINGS['holdback_chars']],
        'local_status': status,
        'upstream_ms': upstream_time,
        'local_ms': local_time
    }
    
    log_dir = os.path.dirname(SETTINGS['log_path'])
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    with open(SETTINGS['log_path'], 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry) + '\n')