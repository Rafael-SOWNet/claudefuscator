'use strict';
/*
 * Proposes a personal/org vocabulary pack by scanning local sources.
 *
 *   node tools/harvest-vocab.js <dir> [<dir> ...] [options]
 *
 * THE POINT OF THIS SCRIPT IS THAT CLAUDE NEVER SEES ITS OUTPUT.
 * ---------------------------------------------------------------
 * There is a bootstrapping problem: the list of terms you want hidden from
 * Claude is itself sensitive, so asking Claude to read your repos and
 * SharePoint to build that list sends the whole list to Anthropic in the
 * process. So by default this prints COUNTS ONLY - never the terms - and
 * writes them to a gitignored file for you to review in your own editor.
 *
 * Pass --print only when you are NOT running under an agent.
 *
 * HEURISTICS (all local, no model involved)
 * -----------------------------------------
 * Telling "our vocabulary" apart from "ordinary programming English" without
 * an LLM comes down to five cheap signals, applied in this order:
 *
 *   1. SHAPE      - only acronyms, part codes and (opt-in) PascalCase are
 *                   considered. Plain lowercase words are never harvested;
 *                   that way lies tokenizing the language itself.
 *   2. STOPWORDS  - config/allowlist-nl-en.json, plus any --dict wordlist.
 *                   Applied per PascalCase part too, so `DataReader` dies
 *                   while `AcmeReader` survives.
 *   3. BASELINE   - terms that also occur in a control corpus you did not
 *                   write (--baseline node_modules, a vendored SDK, ...)
 *                   are generic by definition. The strongest signal
 *                   available locally, for the cost of one extra scan.
 *   4. SPREAD     - a term must appear in >= --min-files files. Something
 *                   repeated inside one file is usually a local variable.
 *   5. UBIQUITY   - a term in more than --max-doc-freq of all files is
 *                   boilerplate (licence headers, framework names), not
 *                   distinguishing vocabulary. Only applied once the
 *                   corpus has at least 20 files; below that every real
 *                   term is in 'most' of them.
 *
 * Everything surviving is still a CANDIDATE. Review the file before using
 * it: over-tokenizing costs answer quality, and no heuristic can tell a
 * product name from a word you happen to use a lot.
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

const DEFAULT_EXT = [
  '.cs', '.ts', '.tsx', '.js', '.jsx', '.py', '.c', '.h', '.cpp', '.hpp',
  '.java', '.go', '.rs', '.rb', '.php', '.sql', '.sh', '.ps1', '.psm1',
  '.md', '.txt', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg',
  '.xml', '.csproj', '.razor', '.cshtml', '.html', '.css', '.scss',
];

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'bin', 'obj', 'dist', 'build', 'out', 'target',
  '.vs', '.vscode', '.idea', '__pycache__', 'venv', '.venv', 'vendor',
  'packages', 'wwwroot', '.next', 'coverage', '.pytest_cache', 'ms-playwright',
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024;

const SHAPES = [
  /* ALLCAPS acronym: XYZ, ABC, QRS. */
  { name: 'acronym', re: /\b[A-Z]{2,8}\b/g, type: 'TERM' },
  /* Part / model code. Must contain a digit: without that this shape just
   * matches hyphenated ALLCAPS prose and floods the output. */
  { name: 'partcode', re: /\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,3}\b/g, type: 'PRODUCT', needsDigit: true },
  /* PascalCase. OFF by default (--symbols): a codebase is overwhelmingly
   * ordinary class names, which drown out real vocabulary and push toward
   * tokenizing code wholesale - which costs answer quality and does not hide
   * what the code does anyway. */
  { name: 'pascal', re: /\b[A-Z][a-z]{2,}(?:[A-Z][a-z0-9]+){1,3}\b/g, type: 'SYMBOL', optIn: true },
];

function parseArgs(argv) {
  const opts = {
    dirs: [], baseline: [], dict: [],
    out: path.join(ROOT, 'config', 'packs', 'harvested.local.json'),
    min: 3, max: 400, minFiles: 2, maxDocFreq: 0.5,
    print: false, symbols: false, ext: DEFAULT_EXT,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--print') opts.print = true;
    else if (a === '--symbols') opts.symbols = true;
    else if (a === '--out') opts.out = path.resolve(argv[++i]);
    else if (a === '--baseline') opts.baseline.push(path.resolve(argv[++i]));
    else if (a === '--dict') opts.dict.push(path.resolve(argv[++i]));
    else if (a === '--min') opts.min = parseInt(argv[++i], 10);
    else if (a === '--max') opts.max = parseInt(argv[++i], 10);
    else if (a === '--min-files') opts.minFiles = parseInt(argv[++i], 10);
    else if (a === '--max-doc-freq') opts.maxDocFreq = parseFloat(argv[++i]);
    else if (a === '--ext') opts.ext = argv[++i].split(',').map((e) => (e.startsWith('.') ? e : '.' + e));
    else if (a.startsWith('--')) throw new Error('unknown option: ' + a);
    else opts.dirs.push(path.resolve(a));
  }
  return opts;
}

function loadStopwords(opts) {
  const stop = new Set();
  const allowFile = path.join(ROOT, 'config', 'allowlist-nl-en.json');
  if (fs.existsSync(allowFile)) {
    for (const w of JSON.parse(fs.readFileSync(allowFile, 'utf8')).allowList || []) {
      stop.add(String(w).toLowerCase());
    }
  }
  /* A system wordlist (/usr/share/dict/words, or any newline-separated file)
   * removes far more ordinary language than a hand-written list can. */
  for (const file of opts.dict || []) {
    if (!fs.existsSync(file)) { console.error('skipping missing dict: ' + file); continue; }
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      const w = line.trim().toLowerCase();
      if (w) stop.add(w);
    }
  }
  return stop;
}

function isInteresting(term, shape, stop) {
  const lower = term.toLowerCase();
  if (stop.has(lower)) return false;
  if (term.length < 3 || term.length > 40) return false;
  if (/^\d+$/.test(term)) return false;
  if (shape && shape.needsDigit && !/\d/.test(term)) return false;

  /* Split only BEFORE a capital that starts a lowercase run. Splitting on
   * every capital shattered ALLCAPS acronyms into single letters, and the
   * length check below then rejected every one of them - XYZ, ABC and QRS
   * were silently never proposed. */
  const parts = term.split(/(?=[A-Z][a-z])|[-_]/).filter(Boolean).map((p) => p.toLowerCase());
  if (parts.length > 1 && parts.every((p) => stop.has(p) || p.length < 2)) return false;
  return true;
}

function* walk(dir, ext, depth) {
  if (depth > 12) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
  for (const e of entries) {
    if (e.name.startsWith('.') && e.name !== '.github') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(full, ext, depth + 1);
    } else if (ext.includes(path.extname(e.name).toLowerCase())) {
      yield full;
    }
  }
}

/* Collect term -> {n, type, files} over a set of directories. */
function scan(dirs, opts, stop, collectOnlyTerms) {
  const counts = new Map();
  let filesScanned = 0;
  let bytes = 0;

  for (const dir of dirs) {
    if (!fs.existsSync(dir)) { console.error('skipping missing dir: ' + dir); continue; }
    for (const file of walk(dir, opts.ext, 0)) {
      let text;
      try {
        if (fs.statSync(file).size > MAX_FILE_BYTES) continue;
        text = fs.readFileSync(file, 'utf8');
      } catch (_) { continue; }
      filesScanned++;
      bytes += text.length;

      for (const shape of SHAPES) {
        if (shape.optIn && !opts.symbols) continue;
        shape.re.lastIndex = 0;
        let m;
        while ((m = shape.re.exec(text)) !== null) {
          const term = m[0];
          if (!isInteresting(term, shape, stop)) continue;
          if (collectOnlyTerms) { counts.set(term, true); continue; }
          let rec = counts.get(term);
          if (!rec) { rec = { n: 0, type: shape.type, files: new Set() }; counts.set(term, rec); }
          rec.n++;
          rec.files.add(file);
        }
      }
    }
  }
  return { counts, filesScanned, bytes };
}

/* Document frequency is only meaningful once there are enough documents.
 * Below this, every genuine term appears in "most" files and the ubiquity
 * rule throws away exactly what you were looking for - scanning a small docs
 * folder returned nothing at all. */
const MIN_FILES_FOR_DOC_FREQ = 20;

/* Pure ranking step, separated so it can be tested without touching disk. */
function select(counts, filesScanned, baselineTerms, opts) {
  const rejected = { baseline: 0, spread: 0, ubiquitous: 0, rare: 0 };
  const eligible = [];

  for (const [term, r] of counts) {
    if (baselineTerms.has(term)) { rejected.baseline++; continue; }
    if (r.n < opts.min) { rejected.rare++; continue; }
    if (r.files.size < opts.minFiles) { rejected.spread++; continue; }
    if (filesScanned >= MIN_FILES_FOR_DOC_FREQ
        && r.files.size / filesScanned > opts.maxDocFreq) { rejected.ubiquitous++; continue; }
    eligible.push([term, r]);
  }

  eligible.sort((a, b) =>
    (b[1].files.size - a[1].files.size) || (b[1].n - a[1].n) || a[0].localeCompare(b[0]));

  /* Cap each shape separately, or the most common shape takes the whole
   * budget and the rarer, more telling terms never surface. */
  const shapeTypes = new Set(SHAPES.filter((s) => !s.optIn || opts.symbols).map((s) => s.type));
  const perType = Math.max(20, Math.floor(opts.max / Math.max(1, shapeTypes.size)));
  const taken = new Map();
  const ranked = [];
  for (const entry of eligible) {
    const t = entry[1].type;
    const n = taken.get(t) || 0;
    if (n >= perType || ranked.length >= opts.max) continue;
    taken.set(t, n + 1);
    ranked.push(entry);
  }

  return { ranked, rejected };
}

function usage() {
  console.error('usage: node tools/harvest-vocab.js <dir> [<dir> ...] [options]');
  console.error('');
  console.error('  --baseline <dir>     control corpus; terms also seen there are dropped');
  console.error('  --dict <file>        extra stopword list (e.g. /usr/share/dict/words)');
  console.error('  --min <n>            minimum occurrences        (default 3)');
  console.error('  --min-files <n>      minimum distinct files     (default 2)');
  console.error('  --max-doc-freq <f>   drop terms in >f of files  (default 0.5)');
  console.error('  --max <n>            cap proposals, per shape   (default 400)');
  console.error('  --symbols            also propose PascalCase identifiers');
  console.error('  --out <file>         output pack');
  console.error('  --print              ALSO print terms - never under an agent');
  console.error('');
  console.error('Prints counts only unless --print.');
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.dirs.length) { usage(); process.exit(2); }

  const stop = loadStopwords(opts);

  /* Baseline first: a term that also appears in code you did not write is
   * generic, whatever its shape. */
  let baselineTerms = new Set();
  let baselineFiles = 0;
  if (opts.baseline.length) {
    const b = scan(opts.baseline, opts, stop, true);
    baselineTerms = new Set(b.counts.keys());
    baselineFiles = b.filesScanned;
  }

  const { counts, filesScanned, bytes } = scan(opts.dirs, opts, stop, false);
  const { ranked, rejected } = select(counts, filesScanned, baselineTerms, opts);

  const pack = {
    '//': [
      'CANDIDATES proposed by tools/harvest-vocab.js. REVIEW BEFORE USE.',
      'Nothing here is verified to be sensitive, and over-tokenizing costs',
      'you answer quality. Delete what does not belong; set "compound": true',
      'only on entries you want matched inside code identifiers.',
      'This file contains real vocabulary and is gitignored.',
    ],
    identifiers: ranked.map(([term, r]) => ({
      type: r.type,
      value: term,
      ...(r.type === 'SYMBOL' ? { compound: true } : {}),
    })),
  };

  fs.mkdirSync(path.dirname(opts.out), { recursive: true });
  fs.writeFileSync(opts.out, JSON.stringify(pack, null, 2) + '\n');

  /* Counts only. The terms themselves stay in the file. */
  const byType = new Map();
  for (const [, r] of ranked) byType.set(r.type, (byType.get(r.type) || 0) + 1);

  console.log(`scanned    ${filesScanned} files, ${(bytes / 1e6).toFixed(1)} MB`);
  if (opts.baseline.length) {
    console.log(`baseline   ${baselineFiles} files, ${baselineTerms.size} generic terms excluded`);
  }
  console.log(`candidates ${counts.size} seen, ${ranked.length} proposed`);
  console.log(`rejected   ${rejected.rare} too rare, ${rejected.spread} single-file, ` +
    `${rejected.ubiquitous} ubiquitous, ${rejected.baseline} in baseline`);
  for (const [type, n] of [...byType].sort()) console.log(`  ${type.padEnd(10)} ${n}`);
  console.log(`written    ${path.relative(ROOT, opts.out)}`);
  console.log('\nTerms were NOT printed. Open the file in your editor and prune it.');

  if (opts.print) {
    console.log('\n--print given; proposed terms follow:');
    for (const [term, r] of ranked) {
      console.log(`  ${r.type.padEnd(10)} ${term}  (${r.n}x, ${r.files.size} files)`);
    }
  }
}

if (require.main === module) main();

module.exports = { parseArgs, isInteresting, loadStopwords, scan, select, SHAPES,
                   MIN_FILES_FOR_DOC_FREQ };
