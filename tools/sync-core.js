'use strict';
/*
 * Copies the canonical tokenizer core into the two places that must ship it
 * standalone: the plugin (component paths cannot escape the plugin root) and
 * the extension (Chrome only loads files inside the extension directory).
 *
 *   node tools/sync-core.js          copy, report what changed
 *   node tools/sync-core.js --check  exit 1 if a copy is stale (for CI)
 *
 * `npm test` also asserts the copies match, so drift cannot land unnoticed.
 */

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const COPIES = [
  {
    source: path.join(ROOT, 'shared', 'claudefuscator-core.js'),
    targets: [
      path.join(ROOT, 'claude-plugin', 'lib', 'claudefuscator-core.js'),
      path.join(ROOT, 'chrome-extension', 'claudefuscator-core.js'),
    ],
  },
  {
    /* The extension does not need this one: it is handed an already-flat
     * config through its options page. */
    source: path.join(ROOT, 'shared', 'config-merge.js'),
    targets: [path.join(ROOT, 'claude-plugin', 'lib', 'config-merge.js')],
  },
  /* The mod runs in an ES-module-only sandbox: no `require`, no Node
   * built-ins. The canonical core is dual-mode CommonJS with no `export`,
   * so the mod's copies get an ESM footer appended. Keeping the footer here
   * rather than forking the core means there is still exactly one copy of
   * the derivation logic, and the drift check below still covers it. */
  {
    source: path.join(ROOT, 'shared', 'claudefuscator-core.js'),
    targets: [path.join(ROOT, 'claude-mod', 'hooks', 'claudefuscator-core.mjs')],
    footer: `
export default ClaudefuscatorCore;
`,
  },
  {
    source: path.join(ROOT, 'shared', 'config-merge.js'),
    targets: [path.join(ROOT, 'claude-mod', 'hooks', 'config-merge.mjs')],
    footer: `
export default ConfigMerge;
`,
  },
];

const check = process.argv.includes('--check');
let stale = 0;

for (const { source: sourcePath, targets, footer } of COPIES) {
  const base = fs.readFileSync(sourcePath);
  const source = footer ? Buffer.concat([base, Buffer.from(footer, 'utf8')]) : base;
  for (const target of targets) {
    const rel = path.relative(ROOT, target);
    const current = fs.existsSync(target) ? fs.readFileSync(target) : null;
    if (current && current.equals(source)) {
      console.log('ok       ' + rel);
      continue;
    }
    stale++;
    if (check) {
      console.error('STALE    ' + rel);
      continue;
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, source);
    console.log((current ? 'updated  ' : 'created  ') + rel);
  }
}

if (check && stale) {
  console.error('\n' + stale + ' copy/copies out of date. Run: node tools/sync-core.js');
  process.exit(1);
}
