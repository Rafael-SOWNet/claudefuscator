'use strict';
/*
 * SessionStart - report status once per session.
 *
 * Exists because the dangerous failure mode for this plugin is silence: an
 * unconfigured or misconfigured Claudefuscator behaves exactly like a working one
 * from the outside, and you would not find out until after you had sent
 * something. So say out loud, at the top of every session, whether scrubbing
 * is actually on.
 *
 * Reports the key's SOURCE, never the key, and counts entries without listing
 * them.
 */

const rt = require('../lib/runtime.js');

(async function main() {
  const payload = await rt.readPayload();

  const { key, source } = rt.loadKey();
  if (!key) {
    return rt.respond({
      systemMessage: 'Claudefuscator: INACTIVE (no key configured). Nothing is being scrubbed. '
        + 'Set the plugin key via /config, or export CLAUDEFUSCATOR_KEY.',
    });
  }

  const state = await rt.setup(payload);
  if (!state.ok) {
    /* Off-project is a deliberate configuration, not a fault, but still say
     * so: the user must always be able to tell scrubbing is off. */
    const why = state.offProject
      ? 'INACTIVE here - ' + state.reason + ' (set "projects" in your config to change that)'
      : 'INACTIVE - ' + state.reason;
    return rt.respond({ systemMessage: 'Claudefuscator: ' + why + '. Nothing is being scrubbed.' });
  }

  const n = state.vault.tokenToValue.size;
  const patterns = state.vault.patterns.map((p) => p.name).join(', ') || 'none';
  const cache = state.config.cacheDiscovered ? 'on (real values cached at ' + rt.cacheFile(payload.session_id) + ')' : 'off';
  const prompt = state.config.promptPolicy === 'block' ? 'block' : 'warn only (typed identifiers ARE sent)';

  return rt.respond({
    systemMessage: 'Claudefuscator: ACTIVE. key from ' + source + '; ' + n + ' list entr' + (n === 1 ? 'y' : 'ies')
      + '; patterns: ' + patterns + '; prompt policy: ' + prompt + '; discovered-value cache: ' + cache + '.',
  });
})();
