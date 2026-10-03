'use strict';
/*
 * Claudefuscator core - shared tokenizer/detokenizer.
 *
 * CANONICAL COPY: shared/claudefuscator-core.js
 * Synced copies (do not edit directly):
 *   claude-plugin/lib/claudefuscator-core.js
 *   chrome-extension/claudefuscator-core.js
 * Run `node tools/sync-core.js` after editing; `npm test` fails if they drift.
 *
 * Dual-mode: sets globalThis.ClaudefuscatorCore (classic script, for the Chrome
 * content script) and module.exports (CommonJS, for the Node hook scripts).
 * Uses WebCrypto only, which is global in both Node >=18 and Chrome, so there
 * is exactly one implementation of token derivation on both sides.
 */

const TOKEN_VERSION = 'claudefuscator/v1';
const DEFAULT_TOKEN_LENGTH = 8;

/* Match boundaries. \b is unreliable at the edges of values containing . @ -
 * so use explicit lookarounds. Two separate concerns, hence two lookarounds
 * per side:
 *   1. not adjacent to another identifier character, so `host-01` does not
 *      match inside `host-010`;
 *   2. not adjacent to a dot that is itself followed/preceded by an
 *      alphanumeric, so `corp.example` does not match inside
 *      `host-01.corp.example` - while a trailing sentence period still ends
 *      the match, which is why `.` is NOT in the character class. Putting `.`
 *      in the class made `mail you@corp.example.` fail to match at all. */
const BOUNDARY = '[A-Za-z0-9_%+@-]';
const LEFT = '(?<!' + BOUNDARY + ')(?<![A-Za-z0-9]\\.)';
const RIGHT = '(?!' + BOUNDARY + ')(?!\\.[A-Za-z0-9])';

function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/* Normalisation is part of the token contract: both sides must agree, or the
 * same real value derives a different token on each side. Do not change this
 * without bumping TOKEN_VERSION. */
function normalise(value) {
  return String(value).normalize('NFKC').trim().toLowerCase();
}

/* ---- HMAC-SHA256 ------------------------------------------------------
 * Two implementations, same output, because the hosts differ.
 *
 * Node and Chrome have WebCrypto, which is what the proxy and the extension
 * use. A Claude Code MOD does not: its sandbox exposes a `crypto.subtle`
 * object with no `importKey`, so the WebCrypto path throws there and the mod
 * would silently derive nothing. The docs list `crypto.subtle` among the
 * environment's web APIs; that turned out not to hold for the methods this
 * needs, and only running the mod showed it.
 *
 * So: use WebCrypto where it works, and fall back to the pure one. Both are
 * asserted equal over every committed vector by test/vectors.test.js - a
 * second implementation of a wire format is only acceptable with that test
 * standing. */

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function sha256Bytes(bytes) {
  const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

  const bitLen = bytes.length * 8;
  const padded = new Uint8Array((((bytes.length + 9) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  /* Length as a 64-bit big-endian count of bits. Lengths here are far below
   * 2^32 bits, so the high word is whatever the float division gives. */
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);

  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = w[i - 15];
      const b = w[i - 2];
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e;
      e = (d + t1) >>> 0;
      d = c; c = b; b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i]);
  return out;
}

/* RFC 2104, block size 64 for SHA-256. */
function hmacHexPure(secret, message) {
  const enc = new TextEncoder();
  let key = enc.encode(secret);
  if (key.length > 64) key = sha256Bytes(key);

  const inner = new Uint8Array(64 + enc.encode(message).length);
  const outer = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    const kb = i < key.length ? key[i] : 0;
    inner[i] = kb ^ 0x36;
    outer[i] = kb ^ 0x5c;
  }
  inner.set(enc.encode(message), 64);
  outer.set(sha256Bytes(inner), 64);

  return Array.from(sha256Bytes(outer))
    .map(function (b) { return b.toString(16).padStart(2, '0'); })
    .join('');
}

function hasWebCrypto() {
  return typeof crypto !== 'undefined'
    && crypto.subtle
    && typeof crypto.subtle.importKey === 'function'
    && typeof crypto.subtle.sign === 'function';
}

async function hmacHex(secret, message) {
  if (!hasWebCrypto()) return hmacHexPure(secret, message);
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map(function (b) { return b.toString(16).padStart(2, '0'); })
    .join('');
}

/* token = TYPE_<n hex chars of HMAC-SHA256(key, "claudefuscator/v1/TYPE/value")>.
 * Stable for a given (key, type, value); reveals nothing about the value's
 * length or content; short enough that the model echoes it back intact. */
async function deriveToken(secret, type, value, tokenLength, caseSensitive) {
  const t = String(type || 'OTHER').toUpperCase().replace(/[^A-Z0-9]/g, '');
  /* Case-sensitive entries hash the EXACT spelling, so `Acme` and `ACME`
   * get different tokens and each restores to itself. Required for code: a
   * case-folding round trip turns ACME_TIMEOUT into Acme_TIMEOUT, which
   * is a different symbol and silently breaks the file. */
  const subject = caseSensitive ? 'cs:' + String(value).trim() : normalise(value);
  const hex = await hmacHex(secret, TOKEN_VERSION + '/' + t + '/' + subject);
  return t + '_' + hex.slice(0, tokenLength || DEFAULT_TOKEN_LENGTH);
}

/* ---- built-in patterns -------------------------------------------------
 * Deliberately high-precision only. `guard` receives the matched text and
 * returns false to leave it untouched, which is how public and loopback
 * addresses stay readable. No person-name heuristics by design: names come
 * from the explicit identifier list, because a name matcher that silently
 * misses a name is worse than one whose coverage you can enumerate.
 *
 * Every group inside a pattern MUST be non-capturing - compile() relies on
 * exactly one capture group per alternative to know which one matched. */
function builtinPatterns(config) {
  const on = Object.assign(
    { email: true, privateIp: true, mac: true, internalHost: true },
    config.patterns || {}
  );
  const out = [];

  if (on.email) {
    out.push({
      name: 'email',
      type: 'EMAIL',
      source: LEFT + '[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*\\.[A-Za-z]{2,}' + RIGHT,
    });
  }

  if (on.privateIp) {
    out.push({
      name: 'privateIp',
      type: 'IP',
      /* Trailing boundary must allow a sentence period (`... 10.42.7.19.`)
       * while rejecting a fifth octet (`10.42.7.19.5`). */
      source: '(?<![0-9.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![0-9])(?!\\.[0-9])',
      guard: isPrivateIpv4,
    });
  }

  if (on.mac) {
    out.push({
      name: 'mac',
      type: 'MAC',
      source: '(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])',
    });
  }

  const domains = (config.internalDomains || []).filter(Boolean);
  if (on.internalHost && domains.length) {
    const alt = domains.map(escapeRegex).join('|');
    const label = '[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?';
    out.push({
      name: 'internalHost',
      type: 'HOST',
      source: LEFT + label + '(?:\\.' + label + ')*\\.(?:' + alt + ')' + RIGHT,
    });
  }

  return out;
}

function isPrivateIpv4(text) {
  const parts = String(text).split('.').map(Number);
  if (parts.length !== 4) return false;
  for (const n of parts) {
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
  }
  const a = parts[0];
  const b = parts[1];
  if (a === 10) return true;                          // RFC1918
  if (a === 172 && b >= 16 && b <= 31) return true;   // RFC1918
  if (a === 192 && b === 168) return true;            // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true;  // RFC6598 CGNAT
  if (a === 169 && b === 254) return true;            // link-local
  return false;                                       // public, loopback, 0.0.0.0, broadcast
}

/* ---- vault ------------------------------------------------------------- */

/*
 * A vault is everything needed to scrub and restore, derived entirely from
 * (secret, config). Both sides build their own from those two inputs - the key
 * is never transmitted, and neither is the mapping.
 */
async function buildVault(secret, config) {
  if (!secret) throw new Error('Claudefuscator: no key supplied');
  const cfg = config || {};
  const tokenLength = cfg.tokenLength || DEFAULT_TOKEN_LENGTH;

  const tokenToValue = new Map();   // token   -> canonical real value
  const literalToToken = new Map(); // literal -> token (includes aliases)
  const compoundLiterals = new Set(); // literals allowed to match inside code identifiers
  const compoundTokens = new Set();   // their tokens, which need a looser restore boundary
  const caseSensitiveLiterals = new Set(); // spellings matched exactly, not case-folded
  const collisions = [];

  for (const item of cfg.identifiers || []) {
    if (!item || !item.value) continue;
    const type = String(item.type || 'OTHER').toUpperCase();
    const spellings = [item.value].concat(item.aliases || []).filter(Boolean);

    /* `compound` implies case-sensitive, and each spelling keeps its OWN
     * token rather than collapsing onto the canonical one. Aliases exist to
     * make several spellings mean one thing, which is right for a person's
     * name and wrong for a symbol: Acme, ACME and acme are three
     * different identifiers and each has to come back exactly as written. */
    const caseSensitive = item.compound === true || item.caseSensitive === true;

    for (const spelling of (caseSensitive ? spellings : [item.value])) {
      const token = await deriveToken(secret, type, spelling, tokenLength, caseSensitive);
      const existing = tokenToValue.get(token);
      if (existing !== undefined && existing !== spelling) {
        collisions.push({ token: token, values: [existing, spelling] });
        continue;
      }
      tokenToValue.set(token, spelling);
      literalToToken.set(String(spelling), token);
      if (caseSensitive) caseSensitiveLiterals.add(String(spelling));
      if (item.compound) { compoundLiterals.add(String(spelling)); compoundTokens.add(token); }
    }

    if (!caseSensitive) {
      const token = literalToToken.get(item.value);
      for (const alias of spellings.slice(1)) literalToToken.set(String(alias), token);
    }
  }

  /* A truncated-HMAC collision makes restore ambiguous, so it is a hard error
   * rather than a warning. Both sides detect it identically because both build
   * the full table. Fix by raising tokenLength on both sides. */
  if (collisions.length) {
    const detail = collisions
      .map(function (c) { return c.token + ' <- ' + c.values.join(' , '); })
      .join('; ');
    throw new Error(
      'Claudefuscator: token collision at tokenLength=' + tokenLength + ': ' + detail +
      '. Raise tokenLength in your config (both sides).'
    );
  }

  /* Allow-list: never tokenize these, whatever matched them. The safety
   * valve for an over-broad personal filter - a short acronym or a harvested
   * term that collides with an ordinary Dutch or English word. It wins over
   * both patterns AND explicit identifiers, because its whole purpose is to
   * be the thing you reach for when the filter is too eager. */
  const allow = new Set();
  for (const word of cfg.allowList || []) {
    if (word) allow.add(normalise(word));
  }

  const vault = {
    secret: secret,
    tokenLength: tokenLength,
    tokenToValue: tokenToValue,
    literalToToken: literalToToken,
    compoundLiterals: compoundLiterals,
    compoundTokens: compoundTokens,
    caseSensitiveLiterals: caseSensitiveLiterals,
    allow: allow,
    patterns: builtinPatterns(cfg),
    discovered: new Map(), // token -> real value, for pattern hits (in-memory)
  };
  compile(vault);
  return vault;
}

/*
 * One combined regex, one pass. Literals come first and are sorted
 * longest-first, so "Jane Example" wins over "Jane", and a configured
 * literal wins over the generic email pattern (giving it the list token, which
 * is the only kind the Chrome side can restore). A single pass also means text
 * we insert is never rescanned.
 */
function compile(vault) {
  const alternatives = [];

  const literals = Array.from(vault.literalToToken.keys())
    .sort(function (a, b) { return b.length - a.length || a.localeCompare(b); });
  for (const literal of literals) {
    /* `compound` entries also match inside a code identifier, so `Acme`
     * hits in `AcmeClient` / `acme_client` / `ACME_TIMEOUT`. Without
     * it the boundary lookarounds stop at the word edge, which is right for
     * prose and wrong for C#/TS symbol names that embed a company or product
     * name. The replacement stays a valid identifier because a token is
     * [A-Z0-9_]. This renames a LABEL inside code; it does not hide what the
     * code does - see CLAUDE.md. */
    const isCompound = vault.compoundLiterals.has(literal);
    alternatives.push({
      kind: 'literal',
      literal: literal,
      caseSensitive: vault.caseSensitiveLiterals.has(literal),
      source: isCompound ? escapeRegex(literal) : LEFT + escapeRegex(literal) + RIGHT,
    });
  }
  for (const p of vault.patterns) {
    alternatives.push({
      kind: 'pattern',
      type: p.type,
      name: p.name,
      guard: p.guard,
      source: p.source,
    });
  }

  vault.alternatives = alternatives;
  vault.scrubRe = alternatives.length
    ? new RegExp(alternatives.map(function (a) { return '(' + a.source + ')'; }).join('|'), 'gi')
    : null;

  /* The same patterns again, sticky, so one position can be probed without
   * rescanning. scrub uses these to find out whether a literal that won a
   * position is really just a FRAGMENT of a longer pattern match starting
   * at the same place - `Acme` inside `Acme@partner.example`. */
  vault.patternProbes = vault.patterns.map(function (p) {
    return { alt: { kind: 'pattern', type: p.type, name: p.name, guard: p.guard },
             re: new RegExp(p.source, 'iy') };
  });

  rebuildRestore(vault);
}

function rebuildRestore(vault) {
  const all = Array.from(vault.tokenToValue.keys())
    .concat(Array.from(vault.discovered.keys()))
    .sort(function (a, b) { return b.length - a.length; });

  /* Two boundary rules, because compound tokens sit INSIDE code identifiers.
   *
   * strict   - the normal case. A token must stand alone, so ordinary text
   *            that merely looks like a token (MAX_deadbeef) is never
   *            rewritten and nothing we did not generate is "restored".
   * compound - produced by a `compound` entry, so it legitimately appears
   *            glued to other identifier characters (ORG_81da0267Client).
   *            No left boundary and only a not-a-hex-digit right boundary,
   *            which still prevents matching a PREFIX of a longer token
   *            while allowing the rest of the symbol to follow. Slightly
   *            looser, hence opt-in per entry.
   *
   * Without the compound rule, `compound: true` would tokenize code
   * identifiers that could then never be turned back. */
  const compound = [];
  const strict = [];
  for (const token of all) {
    (vault.compoundTokens.has(token) ? compound : strict).push(escapeRegex(token));
  }

  const parts = [];
  if (strict.length) {
    parts.push('(?<![A-Za-z0-9_])(?:' + strict.join('|') + ')(?![A-Za-z0-9_])');
  }
  if (compound.length) {
    parts.push('(?:' + compound.join('|') + ')(?![0-9a-f])');
  }
  vault.restoreRe = parts.length ? new RegExp(parts.join('|'), 'g') : null;
}

/* ---- scrub / restore --------------------------------------------------- */

/*
 * Real values -> tokens. Returns the rewritten text plus a hit list carrying
 * types and tokens only, never the real value, so a caller can log it safely.
 */
async function scrub(text, vault) {
  const src = String(text == null ? '' : text);
  if (!vault.scrubRe || !src) return { text: src, hits: [], changed: false };

  const hits = [];
  const pieces = [];
  let cursor = 0;

  vault.scrubRe.lastIndex = 0;
  let m;
  while ((m = vault.scrubRe.exec(src)) !== null) {
    if (m[0] === '') { vault.scrubRe.lastIndex++; continue; }

    /* The alternation can report a match inside text an earlier, longer one
     * already consumed. Skip it rather than splicing backwards. */
    if (m.index < cursor) continue;

    let groupIndex = -1;
    for (let i = 1; i < m.length; i++) {
      if (m[i] !== undefined) { groupIndex = i; break; }
    }
    const alt = groupIndex > 0 ? vault.alternatives[groupIndex - 1] : null;
    if (!alt) continue;

    /* Every candidate starting HERE, longest first.
     *
     * Alternation order alone is not enough. Literals are listed first on
     * purpose, so a value on the list gets its list token - the only kind
     * the Chrome side can restore. But a `compound` literal drops the word
     * boundary so it can match inside a symbol name, and that lets a short
     * literal win a position where a much longer pattern also starts:
     * `Acme` beat the email pattern in `Acme@partner.example`, tokenizing
     * four characters and sending the domain upstream in clear. Worse, a
     * case-sensitive literal that then failed its exact-case check consumed
     * the position and left the whole address unscrubbed.
     *
     * So: collect what matches here, prefer the longest, and let a literal
     * win a tie - which preserves the list-token intent for a literal that
     * IS the match, and refuses it for one that is merely a fragment. */
    const candidates = [{ alt: alt, text: m[0] }];
    for (const probe of vault.patternProbes) {
      probe.re.lastIndex = m.index;
      const pm = probe.re.exec(src);
      if (pm && pm[0] && pm[0].length > m[0].length) {
        candidates.push({ alt: probe.alt, text: pm[0] });
      }
    }
    candidates.sort(function (a, b) {
      if (b.text.length !== a.text.length) return b.text.length - a.text.length;
      return (a.alt.kind === 'literal' ? 0 : 1) - (b.alt.kind === 'literal' ? 0 : 1);
    });

    let token = null;
    let type = null;
    let chosen = null;

    for (const candidate of candidates) {
      const resolved = await resolveCandidate(vault, candidate);
      if (resolved) { token = resolved.token; type = resolved.type; chosen = candidate; break; }
    }

    if (!token) {
      /* Nothing here resolved - an allow-listed word, the wrong casing, a
       * guard that said no. Resume one character along rather than past the
       * rejected text, or a value starting inside it is lost: that is how
       * a skipped `acme` used to swallow the address it was part of. */
      vault.scrubRe.lastIndex = m.index + 1;
      continue;
    }

    pieces.push(src.slice(cursor, m.index), token);
    cursor = m.index + chosen.text.length;
    vault.scrubRe.lastIndex = cursor;
    hits.push({
      token: token,
      type: type,
      source: chosen.alt.kind === 'literal' ? 'list' : chosen.alt.name,
    });
  }

  pieces.push(src.slice(cursor));
  const out = pieces.join('');
  return { text: out, hits: hits, changed: out !== src };
}

/* One candidate to a token, or null when it must not be tokenized. */
async function resolveCandidate(vault, candidate) {
  const alt = candidate.alt;
  const text = candidate.text;

  /* Allow-list wins over everything, pattern or literal. */
  if (vault.allow.has(normalise(text))) return null;

  if (alt.kind === 'literal') {
    /* One RegExp cannot mix case flags per alternative, so the regex stays
     * case-insensitive and exact case is resolved here, by the TEXT THAT
     * MATCHED rather than by the alternative that won the position.
     * Filtering on the alternative instead would drop the match entirely
     * whenever a sibling spelling happened to sort first - `acme` winning
     * the position would stop `Acme` and `ACME` ever being tokenized. */
    let token;
    if (alt.caseSensitive) {
      if (!vault.caseSensitiveLiterals.has(text)) return null;
      token = vault.literalToToken.get(text);
    } else {
      token = vault.literalToToken.get(alt.literal);
    }
    return token ? { token: token, type: token.split('_')[0] } : null;
  }

  if (alt.guard && !alt.guard(text)) return null;
  const token = await deriveToken(vault.secret, alt.type, text, vault.tokenLength);
  if (!vault.discovered.has(token)) {
    vault.discovered.set(token, text);
    rebuildRestore(vault);
  }
  return { token: token, type: alt.type };
}

/* Tokens -> real values. Pure substitution over the known token set. */
function restore(text, vault) {
  const src = String(text == null ? '' : text);
  if (!vault.restoreRe || !src) return { text: src, changed: false };
  vault.restoreRe.lastIndex = 0;
  const out = src.replace(vault.restoreRe, function (tok) {
    if (vault.tokenToValue.has(tok)) return vault.tokenToValue.get(tok);
    if (vault.discovered.has(tok)) return vault.discovered.get(tok);
    return tok;
  });
  return { text: out, changed: out !== src };
}

/*
 * Restore, but also report WHERE each replacement landed in the output.
 *
 * Display-only, and JS-only: the Chrome extension uses it to highlight what
 * it unveiled, and the proxy has no screen so the Python port does not need
 * it. `restore` above stays the plain path, so nothing that derives or
 * compares tokens changes shape.
 */
function restoreSpans(text, vault) {
  const src = String(text == null ? '' : text);
  if (!vault.restoreRe || !src) return { text: src, changed: false, spans: [] };

  vault.restoreRe.lastIndex = 0;
  const spans = [];
  const pieces = [];
  let cursor = 0;
  let out = 0;
  let m;

  while ((m = vault.restoreRe.exec(src)) !== null) {
    const token = m[0];
    const value = vault.tokenToValue.has(token)
      ? vault.tokenToValue.get(token)
      : (vault.discovered.has(token) ? vault.discovered.get(token) : null);
    if (value === null) continue;

    const lead = src.slice(cursor, m.index);
    pieces.push(lead, value);
    out += lead.length;
    spans.push({ start: out, end: out + value.length, token: token });
    out += value.length;
    cursor = m.index + token.length;
  }

  pieces.push(src.slice(cursor));
  const result = pieces.join('');
  return { text: result, changed: result !== src, spans: spans };
}

/* Walk a JSON-ish value, applying fn to every string. Tool results are often
 * structured; rewriting only the string leaves preserves the shape that both
 * the model and the tool expect. */
async function mapStrings(value, fn) {
  if (typeof value === 'string') return fn(value);
  if (Array.isArray(value)) {
    const out = [];
    for (const v of value) out.push(await mapStrings(v, fn));
    return out;
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) out[k] = await mapStrings(value[k], fn);
    return out;
  }
  return value;
}

const ClaudefuscatorCore = {
  TOKEN_VERSION: TOKEN_VERSION,
  DEFAULT_TOKEN_LENGTH: DEFAULT_TOKEN_LENGTH,
  normalise: normalise,
  escapeRegex: escapeRegex,
  hmacHex: hmacHex,
  hmacHexPure: hmacHexPure,
  hasWebCrypto: hasWebCrypto,
  deriveToken: deriveToken,
  buildVault: buildVault,
  scrub: scrub,
  restore: restore,
  restoreSpans: restoreSpans,
  mapStrings: mapStrings,
  isPrivateIpv4: isPrivateIpv4,
  rebuildRestore: rebuildRestore,
};

if (typeof globalThis !== 'undefined') globalThis.ClaudefuscatorCore = ClaudefuscatorCore;
if (typeof module !== 'undefined' && module.exports) module.exports = ClaudefuscatorCore;

export default ClaudefuscatorCore;
