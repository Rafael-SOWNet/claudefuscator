'use strict';
/*
 * Opening the vault's envelopes, in the browser.
 *
 * The Python side in agent/vault_crypto.py seals; this opens. Two
 * independent implementations of one format, which is why
 * shared/vault-vectors.json exists and why both sides assert against it.
 * The project has been bitten by exactly this before: a compound literal
 * swallowing a longer pattern shipped in two cores and passed every vector,
 * because no vector combined the features.
 *
 * WHY THIS IS NOT IN claudefuscator-core.js
 *
 * The core is copied verbatim into the mod's sandbox, which has a
 * crypto.subtle with no importKey - hence the pure-JS HMAC fallback living
 * there. An AEAD cannot have that treatment: hand-rolling AES-GCM for a
 * security boundary is not on, so this file needs real WebCrypto and
 * therefore cannot be part of what the mod loads. The mod never decrypts
 * anything; the extension and the agent do.
 */

const VAULT_VERSION = 'claudefuscator/vault/v1';
const DOCUMENT_LABEL = 'claudefuscator/identifiers/v1';
const ENVELOPE_VERSION = 1;
const TOKEN_VERSION = 'claudefuscator/v1';

function utf8(text) {
  return new TextEncoder().encode(text);
}

function fromBase64(value) {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/*
 * Length-prefixed, matching _aad and _document_aad on the Python side.
 * Prefixed rather than separator-joined so a product named `a|b` cannot
 * produce the same additional data as some other pairing.
 */
function lengthPrefixed(parts) {
  const encoded = parts.map(utf8);
  const total = encoded.reduce((n, p) => n + 4 + p.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let at = 0;
  for (const part of encoded) {
    view.setUint32(at, part.length, false);   // big-endian, as Python writes it
    out.set(part, at + 4);
    at += 4 + part.length;
  }
  return out;
}

/*
 * HKDF-SHA256 over the Claudefuscator key.
 *
 * The salt is THIRTY-TWO ZERO BYTES, not an empty array, and the difference
 * is not cosmetic. Python's HKDF(salt=None) substitutes a zero block of the
 * hash length, while WebCrypto takes the salt literally - so an empty
 * Uint8Array derives a different key and every row fails to open with no
 * hint as to why. The vectors catch it; this comment is so nobody has to
 * rediscover why they are failing.
 */
async function valueKey(secret) {
  const base = await crypto.subtle.importKey('raw', utf8(secret), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8(VAULT_VERSION) },
    base,
    256
  );
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['decrypt']);
}

async function openWithAad(secret, envelope, aad) {
  if (!envelope || typeof envelope !== 'object') throw new Error('not an envelope');
  if (envelope.v !== ENVELOPE_VERSION) {
    throw new Error('unsupported envelope version ' + envelope.v);
  }

  let nonce;
  let ciphertext;
  try {
    nonce = fromBase64(envelope.n);
    ciphertext = fromBase64(envelope.ct);
  } catch (e) {
    throw new Error('malformed envelope: ' + e.message);
  }

  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad },
      await valueKey(secret),
      ciphertext
    );
  } catch (_) {
    /* WebCrypto reports every AEAD failure identically and says nothing
     * about which part was wrong, which is correct of it. */
    throw new Error('does not authenticate under this key and context');
  }

  return new TextDecoder().decode(plain);
}

/* One mapping. Bound to its token, product and token version, so a row
 * cannot be lifted into another product or replayed under another token. */
async function openValue(secret, token, envelope, product) {
  return openWithAad(secret, envelope,
    lengthPrefixed([TOKEN_VERSION, product || '', token]));
}

/* A whole document - the shared identifier list. Bound to its version, so
 * an older one cannot be replayed as the current one. */
async function openDocument(secret, envelope, label) {
  if (typeof envelope.version !== 'number') throw new Error('malformed envelope: no version');
  return openWithAad(secret, envelope,
    lengthPrefixed([TOKEN_VERSION, label || DOCUMENT_LABEL, String(envelope.version)]));
}

const ENROLMENT_LABEL = 'claudefuscator/enrolment/v1';

/*
 * The Claudefuscator key, unwrapped from what the vault stores.
 *
 * Wrapped under a key derived from the caller's API token, so what sits in
 * the vault's database is useless on its own: the server keeps only a
 * SHA-256 of that token, never the token itself, so a dump or a backup
 * yields a blob nothing on the host can open.
 *
 * Be clear about what it does not cover. A token crosses the wire on every
 * request, so code execution on the running host can harvest one and
 * unwrap. That is inherent to a server distributing the key at all, and is
 * why the design resisted doing so for a long time - see UNVEIL-SERVER.md.
 *
 * Same salt caveat as valueKey: 32 zero bytes, matching Python's
 * HKDF(salt=None), not an empty array.
 */
async function unwrapKey(envelope, apiToken) {
  if (!envelope || typeof envelope !== 'object') throw new Error('not an envelope');
  if (envelope.v !== ENVELOPE_VERSION) {
    throw new Error('unsupported envelope version ' + envelope.v);
  }
  if (!apiToken) throw new Error('no API token');

  const base = await crypto.subtle.importKey('raw', utf8(apiToken), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8(ENROLMENT_LABEL) },
    base,
    256
  );
  const wrapping = await crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['decrypt']);

  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(envelope.n), additionalData: utf8(ENROLMENT_LABEL) },
      wrapping,
      fromBase64(envelope.ct)
    );
  } catch (_) {
    throw new Error('the wrapped key does not open under this API token - '
      + 'enrol again after rotating it');
  }

  return new TextDecoder().decode(plain);
}

const ClaudefuscatorVaultCrypto = {
  VAULT_VERSION,
  DOCUMENT_LABEL,
  ENVELOPE_VERSION,
  ENROLMENT_LABEL,
  openValue,
  openDocument,
  unwrapKey,
};

if (typeof globalThis !== 'undefined') {
  globalThis.ClaudefuscatorVaultCrypto = ClaudefuscatorVaultCrypto;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ClaudefuscatorVaultCrypto;
}
