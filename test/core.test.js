'use strict';
/*
 * Tests for the shared tokenizer core. Run with `npm test` (node --test).
 * No dependencies - node's built-in test runner only.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const core = require('../shared/claudefuscator-core.js');

const KEY = 'test-key-do-not-use-for-real';
const CONFIG = {
  tokenLength: 8,
  internalDomains: ['corp.example', 'lan'],
  identifiers: [
    { type: 'PERSON', value: 'Jane Example', aliases: ['J. Example', 'jexample'] },
    { type: 'HOST', value: 'host-01.corp.example' },
    { type: 'ORG', value: 'Acme Equipment' },
  ],
};

function vault(cfg, key) {
  return core.buildVault(key || KEY, cfg || CONFIG);
}

test('same value always derives the same token', async () => {
  const v = await vault();
  const a = await core.scrub('Jane Example', v);
  const b = await core.scrub('Jane Example said so', v);
  assert.match(a.text, /^PERSON_[0-9a-f]{8}$/);
  assert.ok(b.text.startsWith(a.text));
});

test('all aliases of an entry map to one token', async () => {
  const v = await vault();
  const canonical = (await core.scrub('Jane Example', v)).text;
  assert.strictEqual((await core.scrub('J. Example', v)).text, canonical);
  assert.strictEqual((await core.scrub('jexample', v)).text, canonical);
});

test('matching is case-insensitive but the token is stable', async () => {
  const v = await vault();
  const canonical = (await core.scrub('Jane Example', v)).text;
  assert.strictEqual((await core.scrub('JANE EXAMPLE', v)).text, canonical);
  assert.strictEqual((await core.scrub('jane example', v)).text, canonical);
});

test('a different key produces different tokens for the same value', async () => {
  const v1 = await vault(CONFIG, 'key-one');
  const v2 = await vault(CONFIG, 'key-two');
  const a = (await core.scrub('Jane Example', v1)).text;
  const b = (await core.scrub('Jane Example', v2)).text;
  assert.notStrictEqual(a, b);
});

test('round-trips: restore(scrub(x)) === x', async () => {
  const v = await vault();
  const input = [
    'Jane Example rebooted host-01.corp.example at 10.42.7.19.',
    'Contact you@corp.example about it.',
    'NIC aa:bb:cc:dd:ee:ff on host build-01.lan.',
    'Acme Equipment owns 192.168.1.1 and 172.20.5.5.',
  ].join('\n');
  const s = await core.scrub(input, v);
  assert.ok(s.changed);
  assert.strictEqual(core.restore(s.text, v).text, input);
});

test('an alias restores to the canonical spelling, not the alias', async () => {
  /* Intended, and worth pinning: aliases collapse onto one token, so the
   * token cannot know which spelling produced it. Round-tripping is
   * value-preserving, not byte-preserving, wherever aliases are involved. */
  const v = await vault();
  const s = await core.scrub('Ask J. Example about it', v);
  assert.strictEqual(core.restore(s.text, v).text, 'Ask Jane Example about it');
});

test('no real value survives in the scrubbed text', async () => {
  const v = await vault();
  const input = 'Jane Example / host-01.corp.example / 10.42.7.19 / you@corp.example';
  const s = await core.scrub(input, v);
  for (const secret of ['Jane', 'Example', 'host-01', 'corp.example', '10.42.7.19', 'you']) {
    assert.ok(!s.text.includes(secret), 'leaked ' + secret + ' in: ' + s.text);
  }
});

test('hit records never carry the real value', async () => {
  const v = await vault();
  const s = await core.scrub('Jane Example at 10.42.7.19', v);
  const blob = JSON.stringify(s.hits);
  assert.ok(!blob.includes('Jane'));
  assert.ok(!blob.includes('10.42.7.19'));
  assert.ok(s.hits.length >= 2);
});

/* --- boundary regressions: each of these was a real bug ---------------- */

test('a value at the end of a sentence is still matched', async () => {
  const v = await vault();
  for (const input of [
    'Mail you@corp.example.',
    'Host is host-01.corp.example.',
    'Address 10.42.7.19.',
    'Name is Jane Example.',
  ]) {
    const s = await core.scrub(input, v);
    assert.ok(s.changed, 'not matched at sentence end: ' + input);
    assert.strictEqual(core.restore(s.text, v).text, input);
  }
});

test('a configured host does not match inside a longer hostname', async () => {
  const v = await vault();
  const listToken = (await core.scrub('host-01.corp.example', v)).text;
  const s = await core.scrub('host-010.corp.example', v);
  assert.notStrictEqual(s.text, listToken, 'host-01 matched inside host-010');
  assert.strictEqual(core.restore(s.text, v).text, 'host-010.corp.example');
});

test('a domain suffix does not match inside a longer FQDN', async () => {
  const v = await vault({ internalDomains: ['corp.example'], identifiers: [] });
  const s = await core.scrub('a.b.corp.example', v);
  /* One token for the whole FQDN, not a token for a trailing fragment. */
  assert.match(s.text, /^HOST_[0-9a-f]{8}$/);
  assert.strictEqual(core.restore(s.text, v).text, 'a.b.corp.example');
});

test('an IPv4 prefix of a longer dotted number is not tokenized', async () => {
  const v = await vault();
  const s = await core.scrub('version 10.42.7.19.5 here', v);
  assert.strictEqual(s.text, 'version 10.42.7.19.5 here');
});

/* --- precision: things that must NOT be touched ----------------------- */

test('public, loopback and broadcast addresses are left alone', async () => {
  const v = await vault();
  const input = '8.8.8.8 1.1.1.1 127.0.0.1 0.0.0.0 255.255.255.255 203.0.113.9';
  const s = await core.scrub(input, v);
  assert.strictEqual(s.text, input);
});

test('every RFC1918 / CGNAT / link-local range is caught', async () => {
  for (const ip of ['10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.0.1',
                    '100.64.0.1', '100.127.0.1', '169.254.1.1']) {
    assert.ok(core.isPrivateIpv4(ip), 'missed private range: ' + ip);
  }
  for (const ip of ['172.15.0.1', '172.32.0.1', '100.63.0.1', '100.128.0.1',
                    '11.0.0.1', '192.167.0.1', '9.9.9.9']) {
    assert.ok(!core.isPrivateIpv4(ip), 'false positive: ' + ip);
  }
  assert.ok(!core.isPrivateIpv4('10.0.0.256'));
  assert.ok(!core.isPrivateIpv4('10.0.0'));
});

test('text that merely looks like a token is never restored', async () => {
  const v = await vault();
  const input = 'const MAX_deadbeef = 1; PERSON_00000000 HOST_zzzzzzzz';
  assert.strictEqual(core.restore(input, v).text, input);
});

test('restore only substitutes tokens this vault generated', async () => {
  const v1 = await vault(CONFIG, 'key-one');
  const v2 = await vault(CONFIG, 'key-two');
  const scrubbed = (await core.scrub('Jane Example', v1)).text;
  /* Wrong key: the token is unknown, so it is left as-is rather than mapped
   * to some other value. */
  assert.strictEqual(core.restore(scrubbed, v2).text, scrubbed);
});

test('scrubbing is idempotent', async () => {
  const v = await vault();
  const once = await core.scrub('Jane Example on host-01.corp.example', v);
  const twice = await core.scrub(once.text, v);
  assert.strictEqual(twice.text, once.text);
});

test('longest literal wins over a shorter overlapping one', async () => {
  const v = await vault({
    identifiers: [
      { type: 'PERSON', value: 'Jane' },
      { type: 'PERSON', value: 'Jane Example' },
    ],
  });
  const long = (await core.scrub('Jane Example', v)).text;
  const short = (await core.scrub('Jane', v)).text;
  assert.notStrictEqual(long, short);
  assert.strictEqual(long.split('_').length, 2, 'expected a single token: ' + long);
});

test('a configured literal beats the generic email pattern', async () => {
  const v = await vault({
    internalDomains: ['corp.example'],
    identifiers: [{ type: 'PERSON', value: 'you@corp.example' }],
  });
  const s = await core.scrub('you@corp.example', v);
  /* PERSON, not EMAIL - list entries are the only tokens the Chrome side can
   * restore, so they must take priority. */
  assert.match(s.text, /^PERSON_[0-9a-f]{8}$/);
});

test('empty and null input are handled', async () => {
  const v = await vault();
  assert.strictEqual((await core.scrub('', v)).text, '');
  assert.strictEqual((await core.scrub(null, v)).text, '');
  assert.strictEqual(core.restore(null, v).text, '');
});

test('an empty config scrubs nothing and throws nothing', async () => {
  const v = await vault({ identifiers: [] });
  assert.strictEqual((await core.scrub('anything at all', v)).text, 'anything at all');
});

test('regex metacharacters in a configured value are matched literally', async () => {
  const v = await vault({ identifiers: [{ type: 'OTHER', value: 'C++ (Acme)' }] });
  const s = await core.scrub('built with C++ (Acme) today', v);
  assert.ok(s.changed);
  assert.strictEqual(core.restore(s.text, v).text, 'built with C++ (Acme) today');
});

test('a token collision is a hard error, not a silent mismap', async () => {
  /* tokenLength 1 gives 16 buckets, so a handful of entries collide. */
  await assert.rejects(
    () => core.buildVault(KEY, {
      tokenLength: 1,
      identifiers: Array.from({ length: 40 }, (_, i) => ({ type: 'HOST', value: 'h' + i })),
    }),
    /token collision/
  );
});

test('building a vault without a key throws', async () => {
  await assert.rejects(() => core.buildVault('', CONFIG), /no key supplied/);
});

test('mapStrings rewrites only string leaves and keeps the shape', async () => {
  const input = { a: 'Jane Example', b: [1, 'host-01.corp.example', null], c: { d: true } };
  const v = await vault();
  const out = await core.mapStrings(input, async (s) => (await core.scrub(s, v)).text);
  assert.match(out.a, /^PERSON_/);
  assert.strictEqual(out.b[0], 1);
  assert.match(out.b[1], /^HOST_/);
  assert.strictEqual(out.b[2], null);
  assert.strictEqual(out.c.d, true);
});

/* --- the synced copies must not drift --------------------------------- */

test('synced copies of the core are byte-identical to the canonical one', () => {
  const root = path.join(__dirname, '..');
  const canonical = fs.readFileSync(path.join(root, 'shared/claudefuscator-core.js'));
  const digest = (b) => crypto.createHash('sha256').update(b).digest('hex');
  for (const copy of ['claude-plugin/lib/claudefuscator-core.js', 'chrome-extension/claudefuscator-core.js']) {
    const p = path.join(root, copy);
    assert.ok(fs.existsSync(p), copy + ' is missing - run: node tools/sync-core.js');
    assert.strictEqual(
      digest(fs.readFileSync(p)), digest(canonical),
      copy + ' has drifted - run: node tools/sync-core.js'
    );
  }
});
