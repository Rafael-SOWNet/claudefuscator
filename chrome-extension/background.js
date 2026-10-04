/*
 * Claudefuscator background worker - the ONLY place this extension touches
 * the network, and it reaches exactly one host.
 *
 * WHY A WORKER AND NOT A FETCH IN content.js
 *
 * The content script runs on an https claude.ai page. A fetch from there to
 * http://127.0.0.1 is a cross-origin request made with the page's own
 * privileges: it is subject to the page's CORS, and browsers additionally
 * gate requests from a public page into the private network. A worker fetch
 * backed by `host_permissions` is neither - it is the extension's own
 * request, which is what makes this work at all without weakening anything
 * on the page side.
 *
 * WHAT THIS DELIBERATELY IS NOT
 *
 * It is a transport and nothing else. It does not hold a vault, does not
 * decide what a token means, and does not write to the page. The content
 * script verifies every value this returns against the key before showing
 * it - see verifyMappings in content.js - so a wrong or hostile answer
 * here cannot put a value on screen that the key does not vouch for.
 *
 * THE AGENT URL MUST BE LOOPBACK
 *
 * Enforced by the manifest's host_permissions, which this file reads rather
 * than restating - so the set of hosts this extension can reach is one
 * statement, in the file a reviewer checks first. The reason is the same as
 * in the mod: the request carries proof-of-key and asks for real identifier
 * values, so a config naming a remote host would hand it both. The shared
 * vault is reached BY the agent, never from this extension.
 *
 * Moving the agent to another port means editing host_permissions too. That
 * is deliberate friction: widening where real values may be sent should be
 * a change to the manifest, not a line in a config file.
 */

/* Classic service worker, so importScripts rather than import. The opener
 * needs real WebCrypto, which a worker has and the mod's sandbox does not -
 * see the header of vault-crypto.js. */
importScripts('vault-crypto.js');

const AUTH_LABEL = 'claudefuscator/mappings/v1';

/* Where the decrypted rules live between fetches.
 *
 * storage.session, not storage.local: in memory, never written to disk,
 * cleared when the browser closes. The rules name every value this
 * organisation treats as sensitive, which makes the decrypted copy worth
 * more than any single one of them - it should not outlive the session.
 *
 * It does survive the service worker being torn down, which plain module
 * state would not, so the list is fetched once per browser session rather
 * than once per wake-up.
 *
 * The KEY is deliberately in storage.local instead. It has to persist or
 * the extension is unusable, it is entered once per profile, and it is on
 * the endpoint either way - the same place the mod and the agent keep
 * theirs. */
const RULES_CACHE = 'cachedRules';

/* The key, for this browser session only.
 *
 * In vault mode nobody types it here: the agent enrols it once, wrapped
 * under that person's API token, and each browser collects it on first use
 * and holds it in memory until the browser closes. storage.session is what
 * makes "once per session" true rather than once per service-worker
 * wake-up, which MV3 does roughly whenever it feels like it.
 *
 * In local mode the key is typed into the options page and lives in
 * storage.local, because without a vault there is nowhere else it could
 * come from. That copy is on disk; the collected one never is. */
const KEY_CACHE = 'sessionKey';
const TIMEOUT_MS = 4000;

/* The origins we may contact, taken from the manifest rather than written
 * out again here. Chrome will refuse anything outside host_permissions
 * anyway, so a second hard-coded list could only ever drift from it and
 * turn a refusal into a confusing "no agent" - this way the manifest is
 * the single statement of where this extension can reach. */
function allowedOrigins() {
  const out = [];
  for (const pattern of chrome.runtime.getManifest().host_permissions || []) {
    const m = /^(https?:\/\/[^/]+)\/\*$/.exec(pattern);
    if (m) out.push(m[1]);
  }
  return out;
}

/* Returns { url } or { reason }. Same three-faults-one-message problem
 * vaultOrigin had: "no agent section" and "that origin is not permitted"
 * are different problems with different fixes, and reporting both as the
 * latter points at the manifest when the config is what is empty. */
function agentUrl(config) {
  const raw = config && config.agent;

  /* No agent section? Use the loopback origin the manifest already
   * names. There is exactly one sensible value, the manifest is what
   * bounds it either way, and making people write it out by hand turned
   * an empty config into a dead end - including for pairing, which is
   * how a fresh browser gets configured in the first place. */
  if (!raw) {
    /* Any loopback origin EXCEPT the vault's. A vault reached over
     * loopback - which is how it is exercised in tests, and how someone
     * would run one locally - would otherwise be mistaken for the agent
     * and sent /resolve calls it has no route for, without the bearer
     * token it would want. Defaulting is a convenience; guessing between
     * two different services is not. */
    const vaultUrl = typeof (config && config.vault && config.vault.url) === 'string'
      ? config.vault.url.trim().replace(/\/$/, '')
      : null;

    const loopback = allowedOrigins().find((o) =>
      /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|$)/.test(o) && o !== vaultUrl);

    return loopback
      ? { url: loopback, defaulted: true }
      : { reason: 'no "agent" section, and no loopback origin to assume one on. '
          + 'Add {"agent": {"url": "http://127.0.0.1:8091"}} and press Save.' };
  }

  if (typeof raw !== 'object') {
    return { reason: '"agent" in your identifier list is not an object.' };
  }
  if (raw.enabled === false) {
    return { reason: 'the agent is turned off in your config ("enabled": false).' };
  }

  const url = typeof raw.url === 'string' ? raw.url.trim().replace(/\/$/, '') : '';
  if (!url) return { reason: 'your "agent" section has no "url".' };

  if (!allowedOrigins().includes(url)) {
    return { reason: `this extension may not reach ${url}. It may reach: `
      + allowedOrigins().join(', ') + '.' };
  }

  return { url };
}

/* Same construction as the agent's, the proxy's and the mod's: proof that
 * we hold the key, without the key ever being sent. */
async function authHeader(secret) {
  const enc = new TextEncoder();
  const k = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', k, enc.encode(AUTH_LABEL));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

/* The key this session works with, collected from the vault if it is not
 * already to hand. Returns { key } or { reason }; never throws, because
 * every caller has to be able to say WHY it is not scrubbing. */
/* Take the key and the list from the local agent, during a window it
 * opened. The person runs `--pair` at the terminal and presses the
 * button here; nothing is typed into the browser.
 *
 * This exists because the vault's copy of the key is wrapped under the
 * credential that enrolled it, which belongs to the agent. No second
 * credential can open it, so handing browsers their own token could
 * never have worked - the AEAD simply fails. Over loopback the agent
 * already holds the key, and the person at the terminal is the person
 * at the browser.
 */
async function pairWithAgent() {
  const { config } = await chrome.storage.local.get(['config']);

  const where = agentUrl(config);
  if (where.reason) return { reason: where.reason };

  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(where.url + '/pair', {
      method: 'POST',
      signal: abort.signal,
      credentials: 'omit',
      cache: 'no-store',
    });

    if (res.status === 403) {
      return { reason: 'no pairing window is open. Run this first:\n'
        + '    python agent/claudefuscator_agent.py --pair' };
    }
    if (!res.ok) return { reason: 'the agent answered ' + res.status };

    const body = await res.json();
    if (!body || !body.key) return { reason: 'the agent sent no key' };

    /* The key goes to session storage and nowhere else - memory only,
     * gone when the browser closes. The LIST may be written to disk: it
     * is configuration, not a secret in the same sense, and a browser
     * that forgot it on every restart would scrub nothing until the
     * next pairing. */
    await chrome.storage.session.set({ [KEY_CACHE]: body.key });
    const toStore = { collectedAt: Date.now() };
    if (body.config) toStore.config = body.config;
    await chrome.storage.local.set(toStore);

    const count = ((body.config && body.config.identifiers) || []).length;
    return { paired: true, identifiers: count, defaulted: where.defaulted };
  } catch (err) {
    return {
      reason: err && err.name === 'AbortError'
        ? 'the agent did not answer in time'
        : 'could not reach the agent: ' + (err && err.message),
    };
  } finally {
    clearTimeout(timer);
  }
}

let collecting = null;

async function ensureKey() {
  const cached = await chrome.storage.session.get(KEY_CACHE);
  if (cached[KEY_CACHE]) return { key: cached[KEY_CACHE] };

  /* The content script, the options page and the rules fetch can all ask
   * at once on a cold start, and each would otherwise begin its own
   * collection: "once per browser session" has to mean once, not once per
   * caller that happened to be first. Shared promise, cleared when it
   * settles so a failure can be retried. */
  if (collecting) return collecting;
  collecting = collectKey().finally(() => { collecting = null; });
  return collecting;
}

async function collectKey() {

  const { key, config, vaultToken } = await chrome.storage.local.get(
    ['key', 'config', 'vaultToken']);

  // A typed key wins. Somebody who filled that field meant it, and
  // silently preferring a remote one would make the box they are looking
  // at a lie.
  if (key) return { key };
  if (!vaultToken) return { reason: 'no key configured, and no vault token to collect one with' };

  const where = vaultOrigin(config);
  if (where.reason) return { reason: where.reason };
  const origin = where.url;

  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(origin + '/api/vault/key', {
      headers: { 'Authorization': 'Bearer ' + vaultToken },
      signal: abort.signal,
      credentials: 'omit',
      cache: 'no-store',
    });

    if (res.status === 404) {
      return { reason: 'no key has been enrolled for this token yet - run the '
        + 'agent once with --enrol-key' };
    }
    if (!res.ok) return { reason: 'the vault answered ' + res.status };

    const body = await res.json();
    const collected = await ClaudefuscatorVaultCrypto.unwrapKey({
      v: body.envelopeVersion, n: body.nonce, ct: body.ciphertext,
    }, vaultToken);

    /* Nothing is taken on trust here. A wrong key does not produce wrong
     * values: every resolved value is re-derived against this key before
     * it is shown, so a vault serving a key that is not ours ends in
     * nothing being unveiled rather than something false being unveiled. */
    await chrome.storage.session.set({ [KEY_CACHE]: collected });
    /* A marker, not the key: storage.session is invisible to content
     * scripts by design, so without this a page open since before the
     * collection would sit inert until it was reloaded. It carries a
     * timestamp and nothing else. */
    await chrome.storage.local.set({ collectedAt: Date.now() });
    return { key: collected };
  } catch (err) {
    return {
      reason: err && err.name === 'AbortError'
        ? 'the vault timed out'
        : 'the enrolled key did not open: ' + (err && err.message),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function resolve(tokens) {
  const { config } = await chrome.storage.local.get(['config']);
  const held = await ensureKey();
  if (held.reason) return { mappings: {}, reason: held.reason };
  const key = held.key;
  if (!config) return { mappings: {}, reason: 'not configured' };
  const where = agentUrl(config);
  if (where.reason) return { mappings: {}, reason: where.reason };
  const url = where.url;
  if (!Array.isArray(tokens) || !tokens.length) return { mappings: {} };

  /* A wedged agent must not leave the page waiting for its unveiling. */
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url + '/resolve', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-claudefuscator-auth': await authHeader(key),
      },
      body: JSON.stringify({ tokens }),
      signal: abort.signal,
      /* No cookies, no cached credentials: the only thing that should ever
       * authenticate this request is the header above. */
      credentials: 'omit',
      cache: 'no-store',
    });
    if (!res.ok) return { mappings: {}, reason: 'agent answered ' + res.status };
    const body = await res.json();
    return { mappings: (body && body.mappings) || {} };
  } catch (err) {
    return { mappings: {}, reason: err && err.name === 'AbortError' ? 'agent timed out' : 'no agent' };
  } finally {
    clearTimeout(timer);
  }
}

/* ---- the shared identifier list --------------------------------------
 *
 * Fetched sealed and opened here, so every machine uses one list and
 * copies cannot drift. The server stores ciphertext and cannot read it;
 * this is the only side that can.
 */

/* Returns { url } or { reason }.
 *
 * A reason rather than null, because the three ways this fails need three
 * different actions and used to produce one message. "No vault in your
 * config" was reported as "that url is not one this extension may reach",
 * followed by a list of origins that included the very host the person
 * thought they had configured - which reads as a bug in the extension and
 * sends them to look in the wrong place entirely.
 */
function vaultOrigin(config) {
  const raw = config && config.vault;

  if (!raw || typeof raw !== 'object') {
    return { reason: 'your identifier list has no "vault" section. Add '
      + '{"vault": {"url": "https://…"}} and press Save.' };
  }
  if (raw.enabled === false) {
    return { reason: 'the vault is turned off in your config ("enabled": false).' };
  }

  const url = typeof raw.url === 'string' ? raw.url.trim().replace(/\/$/, '') : '';
  if (!url) return { reason: 'your "vault" section has no "url".' };

  // Same rule as resolve: only an origin the manifest already names.
  if (!allowedOrigins().includes(url)) {
    // Both sides of the comparison. Printing only the permitted list left
    // no way to see that the configured value was, say, carrying a path or
    // a port - the two strings look identical in a sentence that shows one.
    return { reason: `this extension may not reach ${url}. It may reach: `
      + allowedOrigins().join(', ')
      + '. Widening that is a manifest change, not a setting.' };
  }

  return { url };
}

async function fetchRules(force) {
  if (!force) {
    const cached = await chrome.storage.session.get(RULES_CACHE);
    if (cached[RULES_CACHE]) return { rules: cached[RULES_CACHE], cached: true };
  }

  const { config, vaultToken } = await chrome.storage.local.get(
    ['config', 'vaultToken']);

  if (!vaultToken) return { reason: 'no vault token configured' };
  const held = await ensureKey();
  if (held.reason) return { reason: held.reason };
  const key = held.key;

  const where = vaultOrigin(config);
  if (where.reason) return { reason: where.reason };
  const origin = where.url;

  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(origin + '/api/vault/identifiers', {
      headers: { 'Authorization': 'Bearer ' + vaultToken },
      signal: abort.signal,
      credentials: 'omit',
      cache: 'no-store',
    });

    /* The key was collected by now - ensureKey ran above and succeeded, or
     * we would not have got here. Say so, because these two are fetched
     * together but fail separately: reporting only "no list published"
     * reads as nothing having worked, when in fact the part that cannot
     * be done locally just did. */
    if (res.status === 404) {
      return { keyCollected: true,
        reason: 'no shared list has been published yet, so your local '
          + 'identifier list is still the one in force' };
    }
    if (!res.ok) {
      return { keyCollected: true, reason: 'the vault answered ' + res.status };
    }

    const body = await res.json();
    const text = await ClaudefuscatorVaultCrypto.openDocument(key, {
      v: body.envelopeVersion, version: body.version,
      n: body.nonce, ct: body.ciphertext,
    });

    const published = JSON.parse(text);
    const rules = published.config || published;

    await chrome.storage.session.set({ [RULES_CACHE]: rules });
    await chrome.storage.local.set({ collectedAt: Date.now() });
    return { rules, version: body.version };
  } catch (err) {
    /* Reported, never silently ignored: "my colleague's entries are
     * missing" must not look the same as "nobody published any". */
    return {
      reason: err && err.name === 'AbortError'
        ? 'the vault timed out'
        : 'the published list did not open: ' + (err && err.message),
    };
  } finally {
    clearTimeout(timer);
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg) return false;

  if (msg.type === 'claudefuscator-resolve') {
    resolve(msg.tokens).then(sendResponse);
    return true;   // keep the channel open for the async reply
  }

  if (msg.type === 'claudefuscator-pair') {
    pairWithAgent().then(sendResponse);
    return true;
  }

  if (msg.type === 'claudefuscator-key') {
    // For the options page, which needs the key to build a vault and show
    // what a test round-trip does. Same extension, same storage area it
    // could read anyway - this exists so the collecting logic has one home.
    ensureKey().then(sendResponse);
    return true;
  }

  if (msg.type === 'claudefuscator-rules') {
    fetchRules(msg.force === true).then(sendResponse);
    return true;
  }

  return false;
});
