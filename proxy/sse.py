import json

def parse_sse(sse_data):
    """Parse an Anthropic-compatible SSE stream into event list"""
    events = []
    lines = sse_data.split('\n')

    for line in lines:
        if line.startswith('event: '):
            event_type = line[7:].strip()
            events.append({'type': event_type})
        elif line.startswith('data: '):
            data = line[6:]
            if events:
                cur = events[-1]
                cur['data'] = cur.get('data', '') + data + '\n'
        elif line.startswith('id: '):
            # Handle ID if needed
            pass
        elif line.startswith('retry: '):
            # Handle retry if needed
            pass
        elif line == '':
            # Empty line, continue
            continue
        else:
            # Continuation of the current data value (no field prefix)
            if events:
                cur = events[-1]
                if 'data' in cur:
                    if cur['data'].endswith('\n'):
                        cur['data'] += line
                    else:
                        cur['data'] += '\n' + line
                else:
                    cur['data'] = line

    return events

def serialize_sse(events):
    """Serialize event list into SSE stream"""
    sse_stream = []

    for event in events:
        event_type = event['type']
        sse_stream.append(f'event: {event_type}')

        if event_type == 'message_start':
            if 'data' in event:
                sse_stream.append(f'data: {json.dumps(event["data"])}')
        elif event_type == 'content_block_start':
            sse_stream.append(f'data: {json.dumps(event.get("content", {}))}')
        elif event_type == 'content_block_delta':
            sse_stream.append(f'data: {json.dumps({"type": "text", "partial_text": event.get("partial_text")})}')
        elif event_type in ('content_block_stop', 'message_delta', 'message_stop'):
            payload = {k: v for k, v in event.items() if k != 'type'}
            sse_stream.append(f'data: {json.dumps(payload)}')
        elif event_type == 'ping':
            sse_stream.append('data: ') # Empty data
        else:
            # Unknown event type, skip
            pass

    return '\n'.join(sse_stream) + '\n\n'
