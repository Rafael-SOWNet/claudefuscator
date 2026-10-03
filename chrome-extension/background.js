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

const AUTH_LABEL = 'claudefuscator/mappings/v1';
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

function agentUrl(config) {
  const raw = config && config.agent;
  if (!raw || typeof raw !== 'object' || raw.enabled === false) return null;
  const url = typeof raw.url === 'string' ? raw.url.trim().replace(/\/$/, '') : '';
  if (!url) return null;
  return allowedOrigins().includes(url) ? url : null;
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

async function resolve(tokens) {
  const { key, config } = await chrome.storage.local.get(['key', 'config']);
  if (!key || !config) return { mappings: {}, reason: 'not configured' };
  const url = agentUrl(config);
  if (!url) {
    return {
      mappings: {},
      reason: 'the configured agent url is not one this extension may reach: '
        + allowedOrigins().join(', '),
    };
  }
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

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== 'claudefuscator-resolve') return false;
  resolve(msg.tokens).then(sendResponse);
  return true;   // keep the channel open for the async reply
});
