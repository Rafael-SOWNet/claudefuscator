'use strict';
/*
 * Resolves a layered Claudefuscator config into one flat identifier list.
 *
 * CANONICAL COPY: shared/config-merge.js
 * Synced copy (do not edit): claude-plugin/lib/config-merge.js
 * Mirrored in Python at proxy/config_merge.py, with parity asserted by
 * test/merge.test.js and proxy/tests/test_merge_parity.py.
 *
 * THREE LAYERS, LOWEST PRECEDENCE FIRST:
 *
 *   1. generic  - the built-in patterns (email, privateIp, mac, internalHost).
 *                 Regex, no vocabulary, applies anywhere. Lives in `patterns`
 *                 and is handled by the core, not here.
 *   2. packs    - reusable vocabulary files: company names, product and part
 *                 names, process acronyms. The stuff that is the same across
 *                 every project at one employer.
 *   3. identifiers - this project's own list. Last, so it wins.
 *
 * Merge order is part of the contract. Every side has to produce the SAME
 * flat list or tokens diverge and restore silently stops working, so the rule
 * is deliberately boring: concatenate in layer order, then for a repeated
 * normalised value the LAST entry wins (your local file can correct a pack).
 */

const MAX_PACK_DEPTH = 5;

/*
 * `loadPack(ref)` is injected so this file needs no filesystem and stays
 * usable anywhere. It takes a pack reference and returns the parsed object.
 */
function mergeConfig(config, loadPack, options) {
  const opts = options || {};
  const warnings = [];
  const seen = new Map();   // normalised value -> index in `merged`
  const merged = [];
  const loadedPacks = [];

  function addAll(identifiers, origin) {
    for (const item of identifiers || []) {
      if (!item || !item.value) continue;
      const entry = {
        type: String(item.type || 'OTHER').toUpperCase(),
        value: item.value,
      };
      if (item.aliases && item.aliases.length) entry.aliases = item.aliases.slice();
      /* These change how the entry is MATCHED and TOKENIZED, so dropping
       * them here would silently disable compound/exact-case behaviour and
       * make the merged list behave differently from the pack that declared
       * it - and differently on each side. */
      if (item.compound === true) entry.compound = true;
      if (item.caseSensitive === true) entry.caseSensitive = true;

      const key = String(item.value).normalize('NFKC').trim().toLowerCase();
      if (seen.has(key)) {
        const at = seen.get(key);
        const prev = merged[at];
        if (prev.type !== entry.type || JSON.stringify(prev.aliases || []) !== JSON.stringify(entry.aliases || [])) {
          warnings.push(
            `"${item.value}" redefined by ${origin} (was ${prev.type} from ${prev._origin}, now ${entry.type}); later wins`
          );
        }
        entry._origin = origin;
        merged[at] = entry;
        continue;
      }
      entry._origin = origin;
      seen.set(key, merged.length);
      merged.push(entry);
    }
  }

  function expand(cfg, origin, depth) {
    if (depth > MAX_PACK_DEPTH) {
      throw new Error(`Claudefuscator: pack nesting deeper than ${MAX_PACK_DEPTH} at ${origin}`);
    }
    for (const ref of cfg.packs || []) {
      const pack = loadPack(ref, origin);
      if (!pack) {
        warnings.push(`pack not found: ${ref} (referenced by ${origin})`);
        continue;
      }
      loadedPacks.push(pack.source || ref);
      expand(pack.config || {}, pack.source || ref, depth + 1);
      addAll((pack.config || {}).identifiers, pack.source || ref);
    }
  }

  expand(config, opts.source || 'config', 0);
  addAll(config.identifiers, opts.source || 'config');

  /* Short vocabulary terms are the main way a personal filter goes wrong.
   * "XYZ" is bounded so it will not match inside "AcmeTest", but it will still
   * fire on any standalone occurrence, including ones that have nothing to do
   * with you. Warn rather than refuse - it may well be what you want. */
  for (const entry of merged) {
    /* caseSensitive is the recommended remedy, so do not then warn about it:
     * a warning you have already acted on is noise, and noise is how real
     * warnings get ignored. */
    if (entry.caseSensitive || entry.compound) continue;
    for (const literal of [entry.value].concat(entry.aliases || [])) {
      const s = String(literal);
      if (s.length <= 3 && /^[A-Za-z0-9]+$/.test(s)) {
        warnings.push(
          `"${s}" (${entry._origin}) is a ${s.length}-character term; it will match any standalone occurrence. ` +
          'Consider caseSensitive, a longer form, or dropping it.'
        );
      }
    }
  }

  const flat = merged.map((e) => {
    const out = { type: e.type, value: e.value };
    if (e.aliases) out.aliases = e.aliases;
    if (e.compound) out.compound = true;
    if (e.caseSensitive) out.caseSensitive = true;
    return out;
  });

  const resolved = Object.assign({}, config);
  delete resolved.packs;
  resolved.identifiers = flat;

  return { config: resolved, warnings: warnings, packs: loadedPacks };
}


/* ---- project gate ------------------------------------------------------
 *
 * `projects` restricts where Claudefuscator is active: a list of directory
 * paths, and the session must be inside one of them. Absent or empty means
 * every project, which is stated out loud in the status line rather than
 * left to be inferred.
 *
 * This lives in the tool rather than in per-project settings on purpose. A
 * mod can be loaded globally by CLAUDE_CODE_PLUGIN_DIRS or by installing it,
 * and config hygiene is exactly the kind of thing that slips. Gating here
 * means that even when it IS loaded everywhere, it only acts where you said.
 */

function normalisePath(p, platform) {
  if (!p) return '';
  let out = String(p).replace(/\\/g, '/').replace(/\/+$/, '');
  if ((platform || (typeof process !== 'undefined' && process.platform)) === 'win32') {
    out = out.toLowerCase();
  }
  return out;
}

function expandHome(p, home) {
  if (!p) return p;
  if (p === '~') return home || p;
  if (p.startsWith('~/') || p.startsWith('~\\')) return (home || '~') + '/' + p.slice(2);
  return p;
}

/*
 * True when `cwd` is one of `projects` or inside one.
 *
 * The boundary matters: `~/git/acme` must not match `~/git/acme-old`, which a
 * bare startsWith would. Same class of bug as the hostname boundaries in the
 * tokenizer, so it is tested the same way.
 */
function matchesProject(cwd, projects, options) {
  const opts = options || {};
  if (!Array.isArray(projects) || projects.length === 0) return true;
  const here = normalisePath(cwd, opts.platform);
  if (!here) return false;

  for (const entry of projects) {
    if (!entry) continue;
    const root = normalisePath(expandHome(String(entry), opts.home), opts.platform);
    if (!root) continue;
    if (here === root || here.startsWith(root + '/')) return true;
  }
  return false;
}

const ConfigMerge = {
  mergeConfig: mergeConfig,
  MAX_PACK_DEPTH: MAX_PACK_DEPTH,
  matchesProject: matchesProject,
  normalisePath: normalisePath,
  expandHome: expandHome,
};

if (typeof globalThis !== 'undefined') globalThis.ClaudefuscatorConfigMerge = ConfigMerge;
if (typeof module !== 'undefined' && module.exports) module.exports = ConfigMerge;
