'use strict';
/*
 * Claudefuscator options page.
 *
 * Reads and writes chrome.storage.local only. `storage.local` and not
 * `storage.sync` on purpose: sync would upload the key and your real
 * identifier values to your Google account, which defeats the point. If you
 * ever want that, it has to be an explicit decision, not a default.
 *
 * There is no fetch/XHR/WebSocket anywhere in this file, and the extension
 * holds no network permission.
 */

(function () {
  const core = globalThis.ClaudefuscatorCore;

  const el = {
    key: document.getElementById('key'),
    reveal: document.getElementById('reveal'),
    keyState: document.getElementById('keyState'),
    config: document.getElementById('config'),
    vaultToken: document.getElementById('vaultToken'),
    fetchRules: document.getElementById('fetchRules'),
    pair: document.getElementById('pair'),
    pairState: document.getElementById('pairState'),
    rulesState: document.getElementById('rulesState'),
    save: document.getElementById('save'),
    test: document.getElementById('test'),
    clear: document.getElementById('clear'),
    status: document.getElementById('status'),
    testOut: document.getElementById('testOut'),
    testTable: document.querySelector('#testTable tbody'),
    highlight: document.getElementById('highlight'),
  };

  function say(message, kind) {
    el.status.textContent = message;
    el.status.className = kind || '';
  }

  /* A fingerprint lets you confirm both sides hold the same key without ever
   * displaying or comparing the key itself. It is an HMAC over a fixed label,
   * truncated - it does not help anyone recover the key. */
  async function fingerprint(key) {
    if (!key) return null;
    const hex = await core.hmacHex(key, 'claudefuscator/keycheck');
    return hex.slice(0, 8);
  }

  async function showKeyState(key) {
    if (!key) {
      el.keyState.textContent = 'No key stored. Claudefuscator is inactive.';
      return;
    }
    const fp = await fingerprint(key);
    el.keyState.textContent = 'Key fingerprint ' + fp
      + ' — compare with the Claude Code side to confirm they match.';
  }

  function parseConfig(text) {
    if (!text.trim()) throw new Error('Config is empty.');
    let cfg;
    try {
      cfg = JSON.parse(text);
    } catch (err) {
      throw new Error('Not valid JSON: ' + err.message);
    }
    if (!cfg || typeof cfg !== 'object') throw new Error('Config must be a JSON object.');
    if (!Array.isArray(cfg.identifiers)) {
      throw new Error('Config needs an "identifiers" array (it may be empty).');
    }
    return cfg;
  }

  /* Collects the key and the shared list in one go, and says what came
   * back either way: a list that did not arrive and a list that arrived
   * empty look identical from here, and only one of them is fine. */
  async function collectFromVault() {
    el.rulesState.textContent = 'collecting…';

    /* Save the config too, not just the token.
     *
     * The worker reads what is STORED, so pasting a vault url and pressing
     * this button without pressing Save first had it judge the previous
     * config - and report "no vault configured" about a url sitting right
     * there on screen. A button that silently acts on different values
     * than the ones displayed is worse than one that refuses.
     */
    const toStore = { vaultToken: el.vaultToken.value.trim() };
    if (el.config.value.trim()) {
      try {
        toStore.config = parseConfig(el.config.value);
      } catch (err) {
        el.rulesState.textContent = 'Not collected: ' + err.message;
        return;
      }
    }
    await chrome.storage.local.set(toStore);

    try {
      const reply = await chrome.runtime.sendMessage(
        { type: 'claudefuscator-rules', force: true });

      if (!reply || reply.reason) {
        // Partial success is its own outcome. "Not collected" in front of a
        // run that did collect the key is simply untrue, and would send
        // somebody chasing a fault that is not there.
        const lead = (reply && reply.keyCollected)
          ? 'Key collected. '
          : 'Not collected: ';
        el.rulesState.textContent =
          lead + ((reply && reply.reason) || 'no answer from the worker');
        return;
      }

      const count = ((reply.rules && reply.rules.identifiers) || []).length;
      el.rulesState.textContent =
        'Collected version ' + reply.version + ': ' + count + ' identifier'
        + (count === 1 ? '' : 's') + ', held in memory for this browser session.';
    } catch (err) {
      el.rulesState.textContent = 'Not collected: ' + err.message;
    }
  }

  /* Pairing needs nothing from this page - not a key, not a token, not
   * even an agent url, since that defaults to the loopback origin the
   * manifest names. That is the point: a fresh browser can be set up
   * without anybody typing anything into it. */
  async function pairWithAgent() {
    el.pairState.textContent = 'pairing…';
    try {
      const reply = await chrome.runtime.sendMessage({ type: 'claudefuscator-pair' });
      if (!reply || reply.reason) {
        el.pairState.textContent =
          'Not paired: ' + ((reply && reply.reason) || 'no answer from the worker');
        return;
      }
      el.pairState.textContent =
        'Paired. The key is held for this browser session, with '
        + reply.identifiers + ' identifier' + (reply.identifiers === 1 ? '' : 's')
        + ' from the agent.';
      await showKeyState(null);
    } catch (err) {
      el.pairState.textContent = 'Not paired: ' + err.message;
    }
  }

  el.pair.addEventListener('click', pairWithAgent);
  el.fetchRules.addEventListener('click', collectFromVault);

  async function load() {
    const stored = await chrome.storage.local.get(
      ['key', 'config', 'highlight', 'vaultToken']);
    el.vaultToken.value = stored.vaultToken || '';
    el.highlight.checked = stored.highlight !== false;   // default on
    el.key.value = stored.key || '';
    el.config.value = typeof stored.config === 'string'
      ? stored.config
      : (stored.config ? JSON.stringify(stored.config, null, 2) : '');
    await showKeyState(stored.key);
  }

  /* Written on change rather than on Save: it is a display preference, it
   * takes effect in open tabs immediately, and nothing else on this page
   * depends on it. */
  el.highlight.addEventListener('change', async () => {
    await chrome.storage.local.set({ highlight: el.highlight.checked });
    say(el.highlight.checked ? 'Unveiled values are marked.' : 'Marking off.', 'ok');
  });

  el.reveal.addEventListener('change', () => {
    el.key.type = el.reveal.checked ? 'text' : 'password';
  });

  /* The key to work with: typed here, or collected from the vault.
   *
   * Returns '' and says why rather than throwing, because "no key" is the
   * ordinary state of a fresh install and must read as an instruction, not
   * an error. */
  async function workingKey() {
    const typed = el.key.value.trim();
    if (typed) return typed;

    if (!el.vaultToken.value.trim()) {
      say('Enter a key, or a vault token to collect one with.', 'err');
      return '';
    }

    // Save the token first: the worker reads it from storage, not from
    // this field, so collecting before saving would look mysteriously
    // broken the first time anyone tried it.
    await chrome.storage.local.set({ vaultToken: el.vaultToken.value.trim() });
    const held = await chrome.runtime.sendMessage({ type: 'claudefuscator-key' });
    if (!held || held.reason) {
      say('No key: ' + ((held && held.reason) || 'no answer from the worker'), 'err');
      return '';
    }
    return held.key;
  }

  el.save.addEventListener('click', async () => {
    /* Parse first, store second, THEN find a key.
     *
     * The old order deadlocked anyone setting up vault mode for the first
     * time: it asked for a key before storing anything, collecting a key
     * needs the vault url, and the vault url was sitting unsaved in the
     * textarea. Save could therefore never succeed, and said the config
     * had no vault section while the section was on screen.
     *
     * Storing before validating costs little - the config is this page's
     * own field, and a config that does not build is reported below and
     * can be corrected - whereas a config that cannot be saved until it
     * works, and cannot work until it is saved, cannot be corrected at
     * all.
     */
    let cfg;
    try {
      cfg = parseConfig(el.config.value);
    } catch (err) {
      return say(err.message, 'err');
    }

    /* Only a key that was TYPED here is stored. One collected from the
     * vault is deliberately left out: it belongs to this browser session
     * and writing it to disk would quietly undo the point of enrolment. */
    const stored = { config: cfg, highlight: el.highlight.checked,
                     vaultToken: el.vaultToken.value.trim() };
    if (el.key.value.trim()) stored.key = el.key.value.trim();
    await chrome.storage.local.set(stored);

    const key = await workingKey();
    if (!key) {
      // Saved, but inert. Say both halves: the settings are not lost, and
      // nothing is being scrubbed until a key turns up.
      return say('Settings saved, but there is no key yet, so nothing will '
        + 'be unveiled. See the message above.', 'err');
    }

    /* Build the vault now so a token collision or bad entry is caught
     * here rather than silently producing wrong restores later. */
    try {
      await core.buildVault(key, cfg);
    } catch (err) {
      return say(err.message, 'err');
    }

    await showKeyState(key);
    say('Saved locally. Open tabs pick this up without a reload.', 'ok');
  });

  el.test.addEventListener('click', async () => {
    const key = await workingKey();
    if (!key) return;

    let cfg;
    try {
      cfg = parseConfig(el.config.value);
    } catch (err) {
      return say(err.message, 'err');
    }

    let vault;
    try {
      vault = await core.buildVault(key, cfg);
    } catch (err) {
      return say(err.message, 'err');
    }

    el.testTable.replaceChildren();
    for (const [token, value] of vault.tokenToValue) {
      const row = document.createElement('tr');
      for (const cell of [token.split('_')[0], value, token]) {
        const td = document.createElement('td');
        td.textContent = cell;   // textContent, never innerHTML
        row.appendChild(td);
      }
      el.testTable.appendChild(row);
    }
    el.testOut.hidden = false;
    say(vault.tokenToValue.size + ' token(s) derived. Nothing was saved.', 'ok');
  });

  el.clear.addEventListener('click', async () => {
    await chrome.storage.local.clear();
    el.key.value = '';
    el.config.value = '';
    el.testTable.replaceChildren();
    el.testOut.hidden = true;
    await showKeyState(null);
    say('Stored key and identifier list erased from this profile.', 'ok');
  });

  load().catch((err) => say('Could not load stored settings: ' + err.message, 'err'));
})();
