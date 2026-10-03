'use strict';
/*
 * MessageDisplay - tokens -> real values, on screen only.
 *
 * This is the restore side for the terminal. `displayContent` replaces the
 * text you see while it streams; the transcript and the model's own view keep
 * the token. That asymmetry is exactly what we want: you read real hostnames,
 * nothing real is written to the transcript on disk, and nothing real goes
 * back up on the next turn.
 *
 * INPUT SHAPE IS NOT DOCUMENTED. The hooks reference documents
 * `displayContent` on the way out but no input schema on the way in, so this
 * script probes a list of plausible field names rather than assuming one. Run
 * with CLAUDEFUSCATOR_DUMP=<path> to write the raw payload and confirm which field
 * your Claude Code version actually sends (see TESTING.md, check 5). The
 * payload here contains model output - tokens, not real values - so dumping
 * it is comparatively safe.
 */

const fs = require('node:fs');
const rt = require('../lib/runtime.js');

/* Ordered most- to least-likely. First string wins. */
const CANDIDATE_FIELDS = [
  'message',
  'content',
  'text',
  'display_content',
  'displayContent',
  'assistant_message',
];

function findTextField(payload) {
  for (const field of CANDIDATE_FIELDS) {
    const v = payload[field];
    if (typeof v === 'string' && v) return { field: field, text: v };
    /* e.g. { message: { content: "..." } } */
    if (v && typeof v === 'object' && typeof v.content === 'string' && v.content) {
      return { field: field + '.content', text: v.content };
    }
  }
  return null;
}

(async function main() {
  const payload = await rt.readPayload();

  if (process.env.CLAUDEFUSCATOR_DUMP) {
    try {
      fs.appendFileSync(process.env.CLAUDEFUSCATOR_DUMP, JSON.stringify(payload) + '\n');
    } catch (_) { /* debug aid only */ }
  }

  const state = await rt.setup(payload);
  if (!state.ok) return rt.noChange();

  const found = findTextField(payload);
  if (!found) return rt.noChange();

  try {
    const r = rt.core.restore(found.text, state.vault);
    if (!r.changed) return rt.noChange();

    return rt.respond({
      hookSpecificOutput: {
        hookEventName: 'MessageDisplay',
        displayContent: r.text,
      },
    });
  } catch (_) {
    /* Worst case you read a token instead of a hostname. Never break display. */
    return rt.noChange();
  }
})();
