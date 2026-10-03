'use strict';
/*
 * Layered-config merge, JS side. The twin of proxy/tests/test_merge_parity.py:
 * both run the same fixtures in test/fixtures/merge/ and must agree, because
 * if the proxy and the Chrome extension resolve packs differently they end up
 * with different flat lists, derive different tokens, and restore silently
 * stops working.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { mergeConfig } = require('../shared/config-merge.js');

const DIR = path.join(__dirname, 'fixtures', 'merge');

function loader(baseDir) {
  const roots = new Map();
  return function loadPack(ref, origin) {
    const root = roots.get(origin) || (origin && path.dirname(origin)) || baseDir;
    const file = path.isAbsolute(ref) ? ref : path.join(root, ref);
    if (!fs.existsSync(file)) return null;
    roots.set(file, path.dirname(file));
    return { config: JSON.parse(fs.readFileSync(file, 'utf8')), source: file };
  };
}

function merge(name) {
  const file = path.join(DIR, name);
  const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
  return mergeConfig(cfg, loader(DIR), { source: file });
}

test('packs resolve, including nested ones', () => {
  const r = merge('config.json');
  const values = r.config.identifiers.map((i) => i.value);
  assert.ok(values.includes('WIDGET-800'), 'base pack entry missing');
  assert.ok(values.includes('Plant One'), 'nested pack entry missing');
  assert.ok(values.includes('Jane Example'), 'project entry missing');
  assert.strictEqual(r.packs.length, 2);
});

test('the project list wins over a pack, and says so', () => {
  const r = merge('config.json');
  const entry = r.config.identifiers.find((i) => i.value === 'ExampleCorp');
  assert.strictEqual(entry.type, 'CUSTOMER', 'project entry did not override the pack');
  assert.ok(r.warnings.some((w) => w.includes('ExampleCorp') && w.includes('later wins')),
    'override happened silently');
});

test('an overridden entry appears once, in its original position', () => {
  const r = merge('config.json');
  const hits = r.config.identifiers.filter((i) => i.value === 'ExampleCorp');
  assert.strictEqual(hits.length, 1);
});

test('match flags survive the merge', () => {
  /* Dropping these silently disables compound/exact-case behaviour, which
   * would make code round-trips case-fold and corrupt source files. */
  const r = merge('config.json');
  const sym = r.config.identifiers.find((i) => i.value === 'Acme');
  const proc = r.config.identifiers.find((i) => i.value === 'XYZ');
  assert.strictEqual(sym.compound, true);
  assert.deepStrictEqual(sym.aliases, ['ACME']);
  assert.strictEqual(proc.caseSensitive, true);
});

test('packs key is removed from the resolved config', () => {
  const r = merge('config.json');
  assert.ok(!('packs' in r.config), 'packs survived into the flat config');
});

test('non-identifier config is carried through untouched', () => {
  const r = merge('config.json');
  assert.strictEqual(r.config.tokenLength, 8);
  assert.deepStrictEqual(r.config.internalDomains, ['corp.example']);
  assert.deepStrictEqual(r.config.allowList, ['kern', 'post']);
});

test('a missing pack warns instead of throwing', () => {
  const r = merge('missing-pack.json');
  assert.ok(r.warnings.some((w) => w.includes('pack not found')));
  assert.strictEqual(r.config.identifiers.length, 1);
});

test('short terms are flagged, unless already made caseSensitive', () => {
  const r = merge('config.json');
  /* ABC is a bare 3-character term - warn. */
  assert.ok(r.warnings.some((w) => w.includes('"ABC"') && w.includes('3-character')),
    'bare short term was not flagged');
  /* XYZ is the same length but caseSensitive, which is the remedy the
   * warning recommends, so warning again would be noise. */
  assert.ok(!r.warnings.some((w) => w.includes('"XYZ"')),
    'warned about a term that had already applied the fix');
});

test('merging is idempotent', () => {
  const once = merge('config.json').config;
  const twice = mergeConfig(once, loader(DIR), { source: path.join(DIR, 'config.json') }).config;
  assert.deepStrictEqual(twice.identifiers, once.identifiers);
});

test('pack recursion is bounded', () => {
  /* A pack that references itself must fail loudly, not hang. */
  const selfRef = { packs: ['self'], identifiers: [] };
  const selfLoader = () => ({ config: selfRef, source: 'self' });
  assert.throws(() => mergeConfig(selfRef, selfLoader, { source: 'self' }), /nesting deeper/);
});

/* ---- project gate ----------------------------------------------------- */

const { matchesProject, expandHome } = require('../shared/config-merge.js');

const WIN = { home: 'C:/Users/me', platform: 'win32' };
const NIX = { home: '/home/me', platform: 'linux' };
const PROJECTS = ['~/git/acme', '~/git/widget'];

test('no project list means active everywhere', () => {
  /* Absent must not mean "silently off" - that is the failure mode this
   * whole project is built to avoid. */
  assert.ok(matchesProject('/anywhere', undefined, NIX));
  assert.ok(matchesProject('/anywhere', [], NIX));
});

test('a listed project matches, and so does anything inside it', () => {
  assert.ok(matchesProject('/home/me/git/acme', PROJECTS, NIX));
  assert.ok(matchesProject('/home/me/git/acme/backend/src', PROJECTS, NIX));
  assert.ok(matchesProject('/home/me/git/widget', PROJECTS, NIX));
});

test('an unlisted project does not match', () => {
  assert.ok(!matchesProject('/home/me/git/something-else', PROJECTS, NIX));
  assert.ok(!matchesProject('/home/me', PROJECTS, NIX));
  assert.ok(!matchesProject('/tmp', PROJECTS, NIX));
});

test('a sibling whose name merely starts the same does NOT match', () => {
  /* `~/git/acme` must not match `~/git/acme-old`. A bare startsWith would say
   * it does - the same boundary bug the tokenizer had with hostnames. */
  assert.ok(!matchesProject('/home/me/git/acme-old', PROJECTS, NIX));
  assert.ok(!matchesProject('/home/me/git/acmex', PROJECTS, NIX));
  assert.ok(!matchesProject('/home/me/git/widgetsnapshot', PROJECTS, NIX));
});

test('Windows paths, separators and case are handled', () => {
  /* String.raw so the backslashes are real separators and not JS escapes. */
  assert.ok(matchesProject(String.raw`C:\Users\me\git\acme`, PROJECTS, WIN));
  assert.ok(matchesProject(String.raw`C:\Users\me\git\acme\backend`, PROJECTS, WIN));
  assert.ok(matchesProject('C:/Users/me/git/ACME', PROJECTS, WIN), 'Windows paths are case-insensitive');
  assert.ok(!matchesProject(String.raw`C:\Users\me\git\acme-old`, PROJECTS, WIN));
});

test('POSIX matching stays case-sensitive', () => {
  assert.ok(!matchesProject('/home/me/git/ACME', PROJECTS, NIX));
});

test('an absolute project entry works without ~', () => {
  assert.ok(matchesProject('/srv/work/thing', ['/srv/work'], NIX));
  assert.ok(!matchesProject('/srv/workshop', ['/srv/work'], NIX));
});

test('a trailing slash on the entry makes no difference', () => {
  assert.ok(matchesProject('/home/me/git/acme/x', ['~/git/acme/'], NIX));
});

test('an unknown cwd fails closed when a list is set', () => {
  /* If we cannot tell where we are, do not assume we are allowed. */
  assert.ok(!matchesProject('', PROJECTS, NIX));
  assert.ok(!matchesProject(null, PROJECTS, NIX));
});

test('expandHome leaves non-~ paths alone', () => {
  assert.strictEqual(expandHome('/srv/x', '/home/me'), '/srv/x');
  assert.strictEqual(expandHome('~/git', '/home/me'), '/home/me/git');
  assert.strictEqual(expandHome('~', '/home/me'), '/home/me');
});
