'use strict';
/*
 * Tests for the vocabulary harvester.
 *
 * The most important one is "counts only": the harvester exists because the
 * list of terms you want hidden from Claude is itself sensitive, so printing
 * it into an agent's context defeats the purpose. That property is a
 * behaviour, so it gets a test rather than a comment.
 *
 * Everything here runs against a synthetic corpus of invented words written
 * into a temp dir - no real repositories and no real vocabulary.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const harvest = require('../tools/harvest-vocab.js');

const SCRIPT = path.join(__dirname, '..', 'tools', 'harvest-vocab.js');

/* Invented vocabulary. ZORBEX/QUVIAN are the "org" terms that should be
 * found; the rest is ordinary programming English that should not be. */
const CORPUS = {
  'a.cs': `
    // ZORBEX controller for the QUVIAN-200 unit.
    public class DataReader { }
    const int MAX_BUFFER = 1024;
    var client = new ZorbexClient();
    // FROBNIC is generic: it also appears in the baseline corpus.
    FROBNIC.init();
  `,
  'b.cs': `
    // ZORBEX again, in a second file, plus QUVIAN-200 and QUVIAN-400.
    public class FileSystem { }
    var other = new ZorbexClient();   // second file, clears the 2-file floor
    FROBNIC.start();
  `,
  'c.md': `
    # ZORBEX notes
    The QUVIAN-200 replaces the QUVIAN-400.
    FROBNIC is used throughout.
  `,
  'only-once.cs': `
    // GLORP appears in exactly one file, so it must not be proposed.
    var glorp = 1; // GLORP GLORP GLORP GLORP
  `,
};

/* A control corpus: code "you did not write". FROBNIC lives here too, so
 * the baseline filter should drop it from the proposals.
 * Note the generic term must NOT already be in config/allowlist-nl-en.json,
 * or it is removed as a stopword and never reaches the baseline check -
 * which is why this is FROBNIC and not something like "PLAIN". */
const BASELINE = {
  'vendor.cs': `
    class Thing { void go() { FROBNIC.run(); FROBNIC.stop(); } }
  `,
};

function writeCorpus(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-harvest-'));
  for (const [name, body] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), body);
  }
  return dir;
}

function run(args) {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-harvest-out-'));
  const outFile = path.join(out, 'pack.json');
  const stdout = execFileSync('node', [SCRIPT, ...args, '--out', outFile], { encoding: 'utf8' });
  const pack = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  return { stdout, pack, values: pack.identifiers.map((i) => i.value), outFile };
}

/* ---- the privacy property -------------------------------------------- */

test('stdout contains counts but never the harvested terms', () => {
  const dir = writeCorpus(CORPUS);
  const { stdout, values } = run([dir, '--min', '2']);

  assert.ok(values.length > 0, 'nothing was proposed, so the test proves nothing');
  for (const term of values) {
    assert.ok(!stdout.includes(term),
      `term "${term}" leaked into stdout:\n${stdout}`);
  }
  assert.match(stdout, /candidates \d+ seen/);
  assert.match(stdout, /Terms were NOT printed/);
});

test('--print does print them, for a human terminal', () => {
  const dir = writeCorpus(CORPUS);
  const { stdout, values } = run([dir, '--min', '2', '--print']);
  assert.ok(values.length > 0);
  assert.ok(stdout.includes(values[0]), 'the opt-in flag did not print anything');
});

/* ---- shape heuristics ------------------------------------------------- */

test('acronyms are proposed (they were silently dropped once)', () => {
  const dir = writeCorpus(CORPUS);
  const { values } = run([dir, '--min', '2']);
  assert.ok(values.includes('ZORBEX'), 'acronym shape missed: ' + values.join(', '));
});

test('part codes are proposed', () => {
  const dir = writeCorpus(CORPUS);
  const { values } = run([dir, '--min', '2']);
  assert.ok(values.includes('QUVIAN-200'), 'part code missed: ' + values.join(', '));
});

test('a hyphenated term with no digit is not a part code', () => {
  /* Without the digit requirement this shape matches hyphenated prose and
   * floods the output. */
  assert.ok(!harvest.isInteresting('READ-ONLY', { needsDigit: true }, new Set()));
  assert.ok(harvest.isInteresting('QUVIAN-200', { needsDigit: true }, new Set()));
});

test('PascalCase is off unless --symbols', () => {
  const dir = writeCorpus(CORPUS);
  const without = run([dir, '--min', '2']).values;
  const withSym = run([dir, '--min', '2', '--symbols']).values;
  assert.ok(!without.includes('ZorbexClient'), 'symbols leaked in by default');
  assert.ok(withSym.includes('ZorbexClient'), '--symbols did not enable the shape');
});

test('PascalCase made only of ordinary words is rejected', () => {
  const stop = new Set(['data', 'reader', 'file', 'system']);
  assert.ok(!harvest.isInteresting('DataReader', {}, stop));
  assert.ok(!harvest.isInteresting('FileSystem', {}, stop));
  assert.ok(harvest.isInteresting('ZorbexReader', {}, stop), 'an org prefix should survive');
});

/* ---- stopwords and dictionaries --------------------------------------- */

test('the shipped allow-list is used as stopwords', () => {
  const stop = harvest.loadStopwords({ dict: [] });
  assert.ok(stop.has('json'), 'allowlist not loaded');
  assert.ok(stop.has('kern'), 'Dutch words not loaded');
  assert.ok(!stop.has('zorbex'));
});

test('--dict adds an external wordlist', () => {
  const dir = writeCorpus(CORPUS);
  const dictFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cf-dict-')), 'words');
  fs.writeFileSync(dictFile, 'zorbex\nsomethingelse\n');
  const { values } = run([dir, '--min', '2', '--dict', dictFile]);
  assert.ok(!values.includes('ZORBEX'), 'dict entry was not treated as a stopword');
});

/* ---- corpus heuristics ------------------------------------------------ */

test('a term in only one file is not proposed', () => {
  const dir = writeCorpus(CORPUS);
  const { values } = run([dir, '--min', '2']);
  assert.ok(!values.includes('GLORP'), 'single-file term was proposed');
});

test('--baseline drops terms that also occur in code you did not write', () => {
  const dir = writeCorpus(CORPUS);
  const base = writeCorpus(BASELINE);

  const without = run([dir, '--min', '2']).values;
  const withBase = run([dir, '--min', '2', '--baseline', base]).values;

  assert.ok(without.includes('FROBNIC'), 'fixture assumption wrong: FROBNIC not proposed without a baseline');
  assert.ok(!withBase.includes('FROBNIC'), 'baseline did not exclude a generic term');
  assert.ok(withBase.includes('ZORBEX'), 'baseline wrongly excluded an org term');
});

test('baseline exclusions are reported in the counts', () => {
  const dir = writeCorpus(CORPUS);
  const base = writeCorpus(BASELINE);
  const { stdout } = run([dir, '--min', '2', '--baseline', base]);
  assert.match(stdout, /baseline\s+\d+ files, \d+ generic terms excluded/);
  assert.match(stdout, /in baseline/);
});

test('--max-doc-freq drops ubiquitous boilerplate in a large corpus', () => {
  const files = (n) => new Set(Array.from({ length: n }, (_, i) => 'f' + i));
  const counts = new Map([
    ['EVERYWHERE', { n: 500, type: 'TERM', files: files(90) }],   // 90% of files
    ['FOCUSED', { n: 20, type: 'TERM', files: files(10) }],       // 10%
  ]);
  const { ranked, rejected } = harvest.select(counts, 100, new Set(),
    { min: 3, minFiles: 2, maxDocFreq: 0.5, max: 100, symbols: false });
  const values = ranked.map(([v]) => v);
  assert.ok(!values.includes('EVERYWHERE'), 'ubiquity ceiling had no effect');
  assert.ok(values.includes('FOCUSED'));
  assert.strictEqual(rejected.ubiquitous, 1);
});

test('the ubiquity rule is skipped on a small corpus', () => {
  /* In a handful of files every real term is in "most" of them, so applying
   * the ratio there returns nothing at all. */
  const counts = new Map([['ZORBEX', { n: 9, type: 'TERM', files: new Set(['a', 'b', 'c']) }]]);
  const { ranked } = harvest.select(counts, 4, new Set(),
    { min: 3, minFiles: 2, maxDocFreq: 0.5, max: 100, symbols: false });
  assert.strictEqual(ranked.length, 1, 'small-corpus guard did not apply');
});

/* ---- ranking ---------------------------------------------------------- */

test('select caps each shape separately', () => {
  const counts = new Map();
  for (let i = 0; i < 50; i++) {
    counts.set('AAA' + i, { n: 10, type: 'TERM', files: new Set(['f1', 'f2']) });
    counts.set('BB-' + i + '0', { n: 10, type: 'PRODUCT', files: new Set(['f1', 'f2']) });
  }
  const { ranked } = harvest.select(counts, 100, new Set(),
    { min: 1, minFiles: 2, maxDocFreq: 1, max: 40, symbols: false });

  const byType = new Map();
  for (const [, r] of ranked) byType.set(r.type, (byType.get(r.type) || 0) + 1);
  assert.ok(byType.get('TERM') > 0 && byType.get('PRODUCT') > 0,
    'one shape took the whole budget: ' + JSON.stringify([...byType]));
});

test('select reports why things were rejected', () => {
  const counts = new Map([
    ['RARE', { n: 1, type: 'TERM', files: new Set(['f1', 'f2']) }],
    ['LONELY', { n: 9, type: 'TERM', files: new Set(['f1']) }],
    ['GENERIC', { n: 9, type: 'TERM', files: new Set(['f1', 'f2']) }],
  ]);
  const { ranked, rejected } = harvest.select(counts, 10, new Set(['GENERIC']),
    { min: 3, minFiles: 2, maxDocFreq: 1, max: 100, symbols: false });
  assert.strictEqual(ranked.length, 0);
  assert.strictEqual(rejected.rare, 1);
  assert.strictEqual(rejected.spread, 1);
  assert.strictEqual(rejected.baseline, 1);
});

/* ---- output ----------------------------------------------------------- */

test('the written pack is a usable config layer', async () => {
  const core = require('../shared/claudefuscator-core.js');
  const dir = writeCorpus(CORPUS);
  const { pack } = run([dir, '--min', '2']);

  /* It must load straight into a vault without hand-editing. */
  const vault = await core.buildVault('harvest-test-key', pack);
  const out = await core.scrub('the ZORBEX QUVIAN-200 shipped', vault);
  assert.ok(!out.text.includes('ZORBEX'));
  assert.strictEqual(core.restore(out.text, vault).text, 'the ZORBEX QUVIAN-200 shipped');
});

test('symbol entries are marked compound so code round-trips', () => {
  const dir = writeCorpus(CORPUS);
  const { pack } = run([dir, '--min', '2', '--symbols']);
  const sym = pack.identifiers.find((i) => i.type === 'SYMBOL');
  assert.ok(sym, 'no SYMBOL entry produced');
  assert.strictEqual(sym.compound, true);
});

test('the pack carries a review warning', () => {
  const dir = writeCorpus(CORPUS);
  const { pack } = run([dir, '--min', '2']);
  assert.ok(JSON.stringify(pack['//']).includes('REVIEW BEFORE USE'));
});
