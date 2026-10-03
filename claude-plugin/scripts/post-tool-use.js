'use strict';
/*
 * PostToolUse - THE scrub point. Real values -> tokens.
 *
 * This is the only hook that can stop a real identifier from reaching
 * Anthropic. `updatedToolOutput` replaces the tool's result before the model
 * sees it, so everything Claude Code ingests from the machine - file reads,
 * grep hits, bash output, MCP results - passes through here first.
 *
 * Fails closed by default: if we are configured but scrubbing throws, the
 * result is blocked rather than forwarded unscrubbed. Set
 * `"onError": "passthrough"` in the config to invert that.
 */

const rt = require('../lib/runtime.js');

(async function main() {
  const payload = await rt.readPayload();

  const state = await rt.setup(payload);
  if (!state.ok) {
    if (state.configError) {
      /* Broken config is loud: silence here is indistinguishable from
       * working, which is the worst possible failure mode for this tool. */
      return rt.respond({ systemMessage: 'Claudefuscator is NOT scrubbing: ' + state.reason });
    }
    return rt.noChange();
  }

  const original = payload.tool_response;
  if (original === undefined || original === null) return rt.noChange();

  try {
    const allHits = [];
    const scrubbed = await rt.core.mapStrings(original, async (s) => {
      const r = await rt.core.scrub(s, state.vault);
      for (const h of r.hits) allHits.push(h);
      return r.text;
    });

    if (allHits.length === 0) return rt.noChange();

    rt.saveDiscovered(state.vault, state.config, payload.session_id);

    return rt.respond({
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        updatedToolOutput: scrubbed,
      },
      /* Local UI only, and carries no real values. */
      systemMessage: 'Claudefuscator scrubbed ' + allHits.length + ' identifier(s) from '
        + (payload.tool_name || 'tool') + ' output: ' + rt.describeHits(allHits),
    });
  } catch (err) {
    if (rt.onError(state.config) === 'passthrough') {
      return rt.respond({ systemMessage: 'Claudefuscator scrub failed, output forwarded UNSCRUBBED: ' + err.message });
    }
    return rt.respond({
      decision: 'block',
      reason: 'Claudefuscator could not scrub this tool result, so it was withheld from the model: '
        + err.message + ' (set "onError": "passthrough" in your Claudefuscator config to forward it instead)',
    });
  }
})();
