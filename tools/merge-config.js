'use strict';
/*
 * Flattens a layered config (packs -> project identifiers) into the single
 * JSON object the Chrome extension's options page expects.
 *
 *   node tools/merge-config.js [config] [--out f] [--stats] [--quiet]
 *
 * The proxy and the plugin resolve packs themselves, but the extension is
 * handed its config by hand through a textarea, so it needs the flat form.
 * Every side must end up with the SAME flat list or tokens diverge and
 * restore silently stops working.
 *
 * Prints warnings (short terms, redefinitions) but NOT the vocabulary, so it
 * is safe to run under an agent. `--stats` adds per-type counts, still
 * without naming anything. There is deliberately no flag that prints the
 * terms: open the output file in your own editor.
 */

const fs = require('node:fs');
const path = require('node:path');

const { mergeConfig } = require('../shared/config-merge.js');

const ROOT = path.join(__dirname, '..');

function parseArgs(argv) {
  const opts = { input: null, out: null, stats: false, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--out') opts.out = path.resolve(argv[++i]);
    else if (a === '--stats') opts.stats = true;
    else if (a === '--quiet') opts.quiet = true;
    else if (a.startsWith('--')) throw new Error('unknown option: ' + a);
    else opts.input = path.resolve(a);
  }
  if (!opts.input) {
    for (const guess of ['claudefuscator.local.json', 'config/claudefuscator.example.json']) {
      const p = path.join(ROOT, guess);
      if (fs.existsSync(p)) { opts.input = p; break; }
    }
  }
  return opts;
}

function makePackLoader(baseDir) {
  const roots = new Map();
  return function loadPack(ref, origin) {
    const root = roots.get(origin) || (origin && path.dirname(origin)) || baseDir;
    const file = path.isAbsolute(ref) ? ref : path.join(root, ref);
    if (!fs.existsSync(file)) return null;
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    roots.set(file, path.dirname(file));
    return { config: cfg, source: file };
  };
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.input || !fs.existsSync(opts.input)) {
    console.error('no config found. usage: node tools/merge-config.js <config.json> [--out f]');
    process.exit(2);
  }

  const raw = JSON.parse(fs.readFileSync(opts.input, 'utf8'));
  const result = mergeConfig(raw, makePackLoader(path.dirname(opts.input)), { source: opts.input });

  /* Strip the "//" comment keys - they are notes to you, not config, and
   * pasting them into the extension just adds noise. */
  const flat = {};
  for (const [k, v] of Object.entries(result.config)) {
    if (k === '//' || k.startsWith('//')) continue;
    flat[k] = v;
  }

  const body = JSON.stringify(flat, null, 2) + '\n';
  const out = opts.out || path.join(ROOT, 'claudefuscator.merged.local.json');
  fs.writeFileSync(out, body);

  if (!opts.quiet) {
    console.log(`source    ${path.relative(ROOT, opts.input)}`);
    console.log(`packs     ${result.packs.length}` +
      (result.packs.length ? ' (' + result.packs.map((p) => path.relative(ROOT, p)).join(', ') + ')' : ''));
    console.log(`entries   ${flat.identifiers.length}`);
    console.log(`allowList ${(flat.allowList || []).length}`);
    console.log(`written   ${path.relative(ROOT, out)}`);

    if (opts.stats) {
      const byType = new Map();
      for (const e of flat.identifiers) byType.set(e.type, (byType.get(e.type) || 0) + 1);
      for (const [t, n] of [...byType].sort()) console.log(`  ${t.padEnd(10)} ${n}`);
    }

    if (result.warnings.length) {
      console.log(`\n${result.warnings.length} warning(s):`);
      for (const w of result.warnings.slice(0, 40)) console.log('  ! ' + w);
      if (result.warnings.length > 40) console.log(`  ... ${result.warnings.length - 40} more`);
    }

    console.log('\nPaste this file into the extension options page so every side' +
      '\nderives the same tokens. Terms were not printed here.');
  }
}

main();
