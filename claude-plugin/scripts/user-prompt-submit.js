'use strict';
/*
 * UserPromptSubmit - DETECT AND WARN ONLY.
 *
 * The hooks reference is explicit that this event "can't replace the prompt;
 * it only injects additionalContext alongside it". There is no field that
 * rewrites what you typed. So the only two honest options are to block the
 * prompt outright or to let it through with a warning, and this build warns
 * (configured choice; a local proxy is the intended real fix later).
 *
 * CONSEQUENCE, STATED PLAINLY: in warn mode the real value you typed DOES
 * reach Anthropic. This hook is a smoke alarm, not a barrier. Set
 * `"promptPolicy": "block"` to fail closed instead - then the prompt is
 * rejected before the model sees it and you can paste back the tokenized
 * version from the warning.
 *
 * The warning names the matched values because in warn mode they are being
 * sent anyway, so withholding them from a local message protects nothing and
 * only makes the warning useless. In block mode nothing is sent, and the
 * values shown are yours on your own screen.
 */

const rt = require('../lib/runtime.js');

function promptField(payload) {
  for (const f of ['prompt', 'user_prompt', 'message', 'text']) {
    if (typeof payload[f] === 'string' && payload[f]) return payload[f];
  }
  return null;
}

(async function main() {
  const payload = await rt.readPayload();

  const state = await rt.setup(payload);
  if (!state.ok) return rt.noChange();

  const prompt = promptField(payload);
  if (!prompt) return rt.noChange();

  let result;
  try {
    result = await rt.core.scrub(prompt, state.vault);
  } catch (_) {
    return rt.noChange();
  }
  if (result.hits.length === 0) return rt.noChange();

  const policy = state.config.promptPolicy === 'block' ? 'block' : 'warn';

  /* Pair each token with the text that produced it, for a copy-pasteable fix.
   * Rebuilt by re-scanning rather than carried through core, because core
   * deliberately never puts real values in its hit records. */
  const lines = [];
  const seen = new Set();
  for (const hit of result.hits) {
    if (seen.has(hit.token)) continue;
    seen.add(hit.token);
    const real = state.vault.tokenToValue.get(hit.token)
      || state.vault.discovered.get(hit.token)
      || '(' + hit.source + ' match)';
    lines.push('  ' + real + '  ->  ' + hit.token);
  }

  if (policy === 'block') {
    return rt.respond({
      decision: 'block',
      reason: 'Claudefuscator blocked this prompt: it contains ' + result.hits.length
        + ' unscrubbed identifier(s). Tokenized version:\n\n' + result.text
        + '\n\nMapping:\n' + lines.join('\n'),
    });
  }

  return rt.respond({
    systemMessage: 'Claudefuscator WARNING - ' + result.hits.length
      + ' identifier(s) in your prompt were sent to Anthropic as typed '
      + '(prompts cannot be rewritten by a hook):\n' + lines.join('\n'),
  });
})();
