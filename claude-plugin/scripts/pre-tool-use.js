'use strict';
/*
 * PreToolUse - tokens -> real values in tool arguments.
 *
 * Not optional. Once the model has seen HOST_cf7b891e it will ask to Read,
 * grep or ssh that token, and the local tool would fail. `updatedInput`
 * rewrites the arguments before the tool runs, so tools operate on real
 * values while the model only ever sees tokens.
 *
 * VERIFY BEFORE TRUSTING (see TESTING.md, check 4): it is not documented
 * whether Claude Code echoes `updatedInput` back to the model. If it does,
 * this hook would put real values into the conversation - the exact thing
 * Claudefuscator exists to prevent. TESTING.md check 4 greps the transcript to
 * settle it empirically. Set `"restoreToolInput": false` in the config to
 * disable this hook; tool calls on tokenized values will then simply fail,
 * which is inconvenient but leaks nothing.
 */

const rt = require('../lib/runtime.js');

(async function main() {
  const payload = await rt.readPayload();

  const state = await rt.setup(payload);
  if (!state.ok) return rt.noChange();
  if (state.config.restoreToolInput === false) return rt.noChange();

  const original = payload.tool_input;
  if (!original || typeof original !== 'object') return rt.noChange();

  try {
    let changed = false;
    const restored = await rt.core.mapStrings(original, async (s) => {
      const r = rt.core.restore(s, state.vault);
      if (r.changed) changed = true;
      return r.text;
    });

    if (!changed) return rt.noChange();

    return rt.respond({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        /* "allow" would skip the user's own permission rules for this tool.
         * "defer" keeps normal permission handling and just swaps the args. */
        permissionDecision: 'defer',
        updatedInput: restored,
      },
    });
  } catch (_) {
    /* Failing to restore only means the tool sees a token and errors. That is
     * visible and harmless, so never block on it. */
    return rt.noChange();
  }
})();
