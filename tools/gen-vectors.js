'use strict';
/*
 * Generates shared/test-vectors.json from the JS core, which is the reference
 * implementation.
 *
 * The vector file is the only thing stopping the JS and Python tokenizers
 * drifting apart. A byte-copy works for the two JS copies (tools/sync-core.js)
 * but cannot work across languages, so instead both suites assert the same
 * fixed key -> expected output mapping:
 *
 *   test/vectors.test.js        (JS)
 *   proxy/tests/test_parity.py  (Python)
 *
 *   node tools/gen-vectors.js           regenerate
 *   node tools/gen-vectors.js --check   exit 1 if the committed file is stale
 *
 * Vectors cover whole scrub/restore round trips, not just token derivation,
 * because the regex boundary rules are just as easy to get subtly wrong as
 * the HMAC and just as silently damaging.
 */

const fs = require('node:fs');
const path = require('node:path');
const core = require('../shared/claudefuscator-core.js');

const OUT = path.join(__dirname, '..', 'shared', 'test-vectors.json');

/* Fixed and arbitrary. Never use this key for anything real. */
const KEY = 'claudefuscator-test-vector-key-v1';

const CONFIG = {
  tokenLength: 8,
  internalDomains: ['corp.example', 'lan'],
  patterns: { email: true, privateIp: true, mac: true, internalHost: true },
  identifiers: [
    { type: 'PERSON', value: 'Jane Example', aliases: ['J. Example', 'jexample'] },
    { type: 'HOST', value: 'build-01.corp.example' },
    { type: 'ORG', value: 'Example Customer B.V.', aliases: ['Example Customer'] },
    { type: 'SERIAL', value: 'DEV-100-000123' },
    { type: 'OTHER', value: 'C++ (Acme)' },
    { type: 'PERSON', value: 'Renée Müller' },
    /* Personal/org filter: product + process vocabulary. */
    { type: 'ORG', value: 'ExampleCorp', aliases: ['Example Corp'] },
    { type: 'PRODUCT', value: 'WIDGET-800' },
    /* Code identifier: compound => case-sensitive, one token per spelling. */
    { type: 'SYMBOL', value: 'Acme', aliases: ['ACME', 'acme'], compound: true },
    /* Exact case without compound matching. */
    { type: 'PROCESS', value: 'ABC', caseSensitive: true },
  ],
  /* Allow-list beats both patterns and identifiers. */
  allowList: ['kern', 'bank', 'post'],
};

/* Each case targets a specific behaviour that must agree across languages. */
const CASES = [
  ['plain literal', 'Jane Example filed it'],
  ['alias collapses to canonical token', 'J. Example filed it'],
  ['case-insensitive match', 'JANE EXAMPLE filed it'],
  ['sentence-final value', 'Mail nobody@corp.example.'],
  ['sentence-final host', 'Host is build-01.corp.example.'],
  ['sentence-final ip', 'Address 10.42.7.19.'],
  ['longer hostname must not match the shorter literal', 'build-010.corp.example is separate'],
  ['ipv4 prefix of longer dotted number untouched', 'version 10.42.7.19.5 here'],
  ['public and loopback addresses untouched', '8.8.8.8 127.0.0.1 0.0.0.0 255.255.255.255'],
  ['private ranges caught', '10.0.0.1 172.16.0.1 192.168.0.1 100.64.0.1 169.254.1.1'],
  ['mac colon and dash forms', 'aa:bb:cc:dd:ee:ff and AA-BB-CC-DD-EE-FF'],
  ['regex metacharacters in a literal', 'built with C++ (Acme) today'],
  ['non-ascii literal', 'ask Renée Müller about it'],
  ['token-shaped text is not a token', 'const MAX_deadbeef = 1; HOST_zzzzzzzz'],
  ['mixed line', 'Jane Example rebooted build-01.corp.example at 10.42.7.19 (aa:bb:cc:dd:ee:ff)'],
  ['internal host under second domain', 'see printer.lan for details'],
  ['nested fqdn under internal domain', 'a.b.corp.example resolves'],
  ['serial number', 'unit DEV-100-000123 failed'],
  ['org alias', 'Example Customer signed off'],
  ['empty string', ''],
  ['org vocabulary and alias', 'ExampleCorp and Example Corp shipped it'],
  ['product code', 'unit WIDGET-800 failed'],
  ['compound matches inside a code identifier', 'new AcmeClient(); ACME_TIMEOUT; acme_x; Acme'],
  ['compound leaves an unlisted spelling alone', 'AcMe stays as written'],
  ['caseSensitive without compound', 'ABC runs; abc does not match'],
  ['allow-list beats an identifier', 'kern and bank and post are ordinary words'],
  ['allow-list does not block unrelated hits', 'kern at 10.0.0.5'],
];

async function main() {
  const vault = await core.buildVault(KEY, CONFIG);

  const tokens = [];
  for (const [token, value] of vault.tokenToValue) {
    tokens.push({
      type: token.split('_')[0],
      value: value,
      token: token,
      /* Needed to re-derive: a case-sensitive entry hashes the exact
       * spelling, so the flag is part of the token's identity. */
      caseSensitive: vault.caseSensitiveLiterals.has(value),
    });
  }
  tokens.sort((a, b) => a.token.localeCompare(b.token));

  const scrub = [];
  for (const [name, input] of CASES) {
    /* A fresh vault per case so `discovered` from one case cannot change the
     * next one's restore result. Order independence is part of the contract. */
    const v = await core.buildVault(KEY, CONFIG);
    const r = await core.scrub(input, v);
    scrub.push({
      name: name,
      input: input,
      output: r.text,
      hits: r.hits,
      restored: core.restore(r.text, v).text,
    });
  }

  const payload = {
    _comment: 'Generated by tools/gen-vectors.js. Asserted by test/vectors.test.js and proxy/tests/test_parity.py. Do not hand-edit.',
    tokenVersion: core.TOKEN_VERSION,
    key: KEY,
    config: CONFIG,
    tokens: tokens,
    scrub: scrub,
  };

  const body = JSON.stringify(payload, null, 2) + '\n';

  if (process.argv.includes('--check')) {
    const current = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
    if (current !== body) {
      console.error('shared/test-vectors.json is stale. Run: node tools/gen-vectors.js');
      process.exit(1);
    }
    console.log('ok       shared/test-vectors.json');
    return;
  }

  fs.writeFileSync(OUT, body);
  console.log('wrote    shared/test-vectors.json (' + tokens.length + ' tokens, ' + scrub.length + ' scrub cases)');
}

main().catch((err) => { console.error(err); process.exit(1); });
