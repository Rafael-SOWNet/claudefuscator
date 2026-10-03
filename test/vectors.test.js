'use strict';
/*
 * Asserts the JS core still reproduces shared/test-vectors.json.
 *
 * On this side that mostly guards against an accidental change to derivation
 * (the vectors were generated FROM this code). Its real value is as the twin
 * of proxy/tests/test_parity.py: both suites assert the same file, so the JS
 * and Python tokenizers cannot drift apart without one of them going red.
 */

const test = require('node:test');
const assert = require('node:assert');

const core = require('../shared/claudefuscator-core.js');
const vectors = require('../shared/test-vectors.json');

test('vector file targets the current token version', () => {
  assert.strictEqual(vectors.tokenVersion, core.TOKEN_VERSION,
    'TOKEN_VERSION changed; regenerate with: node tools/gen-vectors.js');
});

test('every vector token still derives identically', async () => {
  for (const t of vectors.tokens) {
    const got = await core.deriveToken(
      vectors.key, t.type, t.value, vectors.config.tokenLength, t.caseSensitive);
    assert.strictEqual(got, t.token, 'token changed for ' + JSON.stringify(t.value));
  }
});

test('every vector scrub case still produces the same output', async () => {
  for (const c of vectors.scrub) {
    const vault = await core.buildVault(vectors.key, vectors.config);
    const r = await core.scrub(c.input, vault);
    assert.strictEqual(r.text, c.output, 'scrub changed for case: ' + c.name);
    assert.deepStrictEqual(r.hits, c.hits, 'hits changed for case: ' + c.name);
    assert.strictEqual(core.restore(r.text, vault).text, c.restored,
      'restore changed for case: ' + c.name);
  }
});

test('no vector output leaks a value from the identifier list', () => {
  const allow = new Set((vectors.config.allowList || []).map((w) => w.toLowerCase()));
  const csLiterals = new Set(
    vectors.tokens.filter((t) => t.caseSensitive).map((t) => t.value)
  );

  for (const item of vectors.config.identifiers) {
    for (const real of [item.value].concat(item.aliases || [])) {
      if (allow.has(real.toLowerCase())) continue;   // deliberately not scrubbed
      for (const c of vectors.scrub) {
        /* A case-sensitive spelling is only scrubbed when it appears with
         * exactly that casing, so compare exactly for those. */
        const exact = csLiterals.has(real) || item.compound || item.caseSensitive;
        const inInput = exact ? c.input.includes(real) : c.input.toLowerCase().includes(real.toLowerCase());
        if (!inInput) continue;
        const inOutput = exact ? c.output.includes(real) : c.output.toLowerCase().includes(real.toLowerCase());
        assert.ok(!inOutput, 'case "' + c.name + '" leaked ' + real + ': ' + c.output);
      }
    }
  }
});

/* ---- the two HMAC implementations must agree ------------------------- */

test('the pure HMAC matches WebCrypto on a known RFC 4231 vector', () => {
  /* Anchors the pure implementation to something outside this repo, so a
   * bug in it cannot agree with a matching bug in the vectors. */
  assert.strictEqual(
    core.hmacHexPure(''.repeat(20), 'Hi There'),
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
});

test('the pure HMAC derives every vector token identically to WebCrypto', async () => {
  /* A Claude Code mod runs in a sandbox whose crypto.subtle has no
   * importKey, so the mod takes the pure path while the proxy and the
   * extension take the WebCrypto one. If these two ever disagree, the mod
   * and the extension derive different tokens and restore silently fails.
   * This is the test that makes a second implementation acceptable. */
  assert.ok(core.hasWebCrypto(), 'this host has no WebCrypto, so the comparison proves nothing');

  for (const t of vectors.tokens) {
    const viaWebCrypto = await core.hmacHex(
      vectors.key, core.TOKEN_VERSION + '/' + t.type + '/'
        + (t.caseSensitive ? 'cs:' + t.value.trim() : core.normalise(t.value)));
    const viaPure = core.hmacHexPure(
      vectors.key, core.TOKEN_VERSION + '/' + t.type + '/'
        + (t.caseSensitive ? 'cs:' + t.value.trim() : core.normalise(t.value)));
    assert.strictEqual(viaPure, viaWebCrypto, 'implementations diverged for ' + t.value);
    assert.ok(t.token.endsWith(viaPure.slice(0, vectors.config.tokenLength))
      || t.token === t.type + '_' + viaPure.slice(0, vectors.config.tokenLength),
      'the vector token does not match either implementation for ' + t.value);
  }
});
