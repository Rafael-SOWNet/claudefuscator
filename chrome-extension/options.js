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

  async function load() {
    const stored = await chrome.storage.local.get(['key', 'config', 'highlight']);
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

  el.save.addEventListener('click', async () => {
    const key = el.key.value.trim();
    if (!key) return say('Enter a key first.', 'err');

    let cfg;
    try {
      cfg = parseConfig(el.config.value);
    } catch (err) {
      return say(err.message, 'err');
    }

    /* Build the vault before saving so a token collision or bad entry is
     * caught here rather than silently producing wrong restores later. */
    try {
      await core.buildVault(key, cfg);
    } catch (err) {
      return say(err.message, 'err');
    }

    await chrome.storage.local.set({ key: key, config: cfg, highlight: el.highlight.checked });
    await showKeyState(key);
    say('Saved locally. Open tabs pick this up without a reload.', 'ok');
  });

  el.test.addEventListener('click', async () => {
    const key = el.key.value.trim();
    if (!key) return say('Enter a key first.', 'err');

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
