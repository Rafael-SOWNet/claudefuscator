'use strict';
/*
 * Shared plumbing for the Claudefuscator hook scripts: read the hook payload from
 * stdin, load the key and identifier list, emit a hook response.
 *
 * Two rules this file exists to enforce:
 *   1. The key is never written anywhere, never logged, never put into any
 *      field that reaches the model.
 *   2. If Claudefuscator is not configured it is completely inert - a privacy tool
 *      that breaks every tool call when unconfigured would just get disabled.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const core = require('./claudefuscator-core.js');
const { mergeConfig, matchesProject } = require('./config-merge.js');

/* ---- hook I/O ---------------------------------------------------------- */

function readStdin() {
  return new Promise((resolve) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { buf += c; });
    process.stdin.on('end', () => resolve(buf));
    process.stdin.on('error', () => resolve(buf));
  });
}

async function readPayload() {
  const raw = await readStdin();
  if (!raw.trim()) return {};
  try {
    return JSON.parse(raw);
  } catch (_) {
    return {};
  }
}

/* Emit a response and exit 0. Exit code 0 with no body means "no change",
 * which is the safe default for every hook except the fail-closed path in
 * post-tool-use.js. */
function respond(body) {
  if (body) process.stdout.write(JSON.stringify(body));
  process.exit(0);
}

function noChange() {
  respond(null);
}

/* ---- key ---------------------------------------------------------------
 * Preference order is deliberate. The plugin's own userConfig option is
 * declared `sensitive: true`, so Claude Code keeps it in the OS credential
 * store (Credential Manager / Keychain / libsecret) and never writes it to
 * settings.json. It reaches us as an environment variable on this process
 * only. That is the only source with no plaintext key on disk. */
function loadKey() {
  const fromOption = process.env.CLAUDE_PLUGIN_OPTION_SECRET_KEY;
  if (fromOption && fromOption.trim()) return { key: fromOption.trim(), source: 'plugin userConfig (OS credential store)' };

  const fromEnv = process.env.CLAUDEFUSCATOR_KEY;
  if (fromEnv && fromEnv.trim()) return { key: fromEnv.trim(), source: 'CLAUDEFUSCATOR_KEY env var' };

  const keyFile = process.env.CLAUDEFUSCATOR_KEY_FILE;
  if (keyFile && fs.existsSync(keyFile)) {
    const key = fs.readFileSync(keyFile, 'utf8').trim();
    if (key) return { key: key, source: 'CLAUDEFUSCATOR_KEY_FILE (plaintext on disk)' };
  }

  return { key: null, source: null };
}

/* ---- config ------------------------------------------------------------ */

function configCandidates() {
  const out = [];
  if (process.env.CLAUDE_PLUGIN_OPTION_CONFIG_PATH) out.push(process.env.CLAUDE_PLUGIN_OPTION_CONFIG_PATH);
  if (process.env.CLAUDEFUSCATOR_CONFIG) out.push(process.env.CLAUDEFUSCATOR_CONFIG);
  if (process.env.CLAUDE_PROJECT_DIR) out.push(path.join(process.env.CLAUDE_PROJECT_DIR, 'claudefuscator.local.json'));
  out.push(path.join(process.cwd(), 'claudefuscator.local.json'));
  out.push(path.join(os.homedir(), '.claudefuscator', 'identifiers.json'));
  return out;
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

function loadConfig() {
  for (const candidate of configCandidates()) {
    if (!candidate || !fs.existsSync(candidate)) continue;
    try {
      const cfg = JSON.parse(fs.readFileSync(candidate, 'utf8'));
      /* Resolve the layered config (packs -> project list) into one flat
       * identifier list. Must match proxy/config_merge.py exactly or the
       * proxy and this side derive different tokens. */
      const merged = mergeConfig(cfg, makePackLoader(path.dirname(candidate)), { source: candidate });
      return { config: merged.config, source: candidate, warnings: merged.warnings };
    } catch (err) {
      return { config: null, source: candidate, error: 'not valid JSON: ' + err.message };
    }
  }
  return { config: null, source: null };
}

/* ---- discovered-value cache -------------------------------------------
 * Pattern matches (an IP, a MAC, an address not on your list) produce a token
 * derived from a value nothing has recorded. Restoring those in a LATER hook
 * invocation - a different process - requires persisting the mapping.
 *
 * That file contains real identifier values in plaintext, which is exactly
 * what this tool exists to avoid, so it is OFF by default. With it off,
 * pattern matches are one-way redaction: consistent and correlatable, but not
 * reversible. Turn it on only if you want pattern hits restored too.
 */
function cacheFile(sessionId) {
  const base = process.env.CLAUDE_PLUGIN_DATA
    || path.join(os.homedir(), '.claudefuscator', 'data');
  const safe = String(sessionId || 'no-session').replace(/[^A-Za-z0-9_-]/g, '-');
  return path.join(base, 'sessions', safe + '.json');
}

function loadDiscovered(vault, cfg, sessionId) {
  if (!cfg || !cfg.cacheDiscovered) return;
  const file = cacheFile(sessionId);
  if (!fs.existsSync(file)) return;
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const [token, value] of Object.entries(data.discovered || {})) {
      vault.discovered.set(token, value);
    }
    core.rebuildRestore(vault);
  } catch (_) {
    /* A corrupt cache must not break the session; treat it as empty. */
  }
}

function saveDiscovered(vault, cfg, sessionId) {
  if (!cfg || !cfg.cacheDiscovered || vault.discovered.size === 0) return;
  const file = cacheFile(sessionId);
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const body = JSON.stringify(
      { warning: 'Contains real identifier values in plaintext.', discovered: Object.fromEntries(vault.discovered) },
      null, 2
    );
    /* 0600: owner-only. Honoured on POSIX; on Windows the file inherits the
     * profile ACL, which already restricts it to this user. */
    fs.writeFileSync(file, body, { mode: 0o600 });
  } catch (_) {
    /* Losing the cache degrades restore; it must not break the session. */
  }
}

/* ---- setup ------------------------------------------------------------- */

/*
 * Resolve key + config + vault. Returns { ok: false, reason } when Claudefuscator
 * should stay inert, so each hook can fall straight through to noChange().
 */
async function setup(payload) {
  const { key } = loadKey();
  if (!key) return { ok: false, reason: 'no key configured' };

  const { config, source, error } = loadConfig();
  if (error) return { ok: false, reason: 'config at ' + source + ' is ' + error, configError: true };
  if (!config) return { ok: false, reason: 'no identifier config found' };

  /* Project gate: same rule as the mod. An installed plugin is loaded in
   * every session, so without this it would scrub in projects you never
   * meant it to touch. Absent list means every project. */
  if (Array.isArray(config.projects) && config.projects.length) {
    const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
    if (!matchesProject(cwd, config.projects, { home: os.homedir() })) {
      return { ok: false, reason: 'this project is not on the configured list', offProject: true };
    }
  }

  let vault;
  try {
    vault = await core.buildVault(key, config);
  } catch (err) {
    /* Collision or bad config. Surface it - silently doing nothing here would
     * look identical to working correctly. */
    return { ok: false, reason: err.message, configError: true };
  }

  loadDiscovered(vault, config, payload && payload.session_id);
  return { ok: true, vault: vault, config: config, configSource: source };
}

/*
 * How to behave when we are configured but something threw mid-scrub.
 * "block" (default) fails closed: the content does not reach the model.
 * "passthrough" fails open: it does, unscrubbed. Fail closed is the right
 * default for a tool whose entire job is to not leak.
 */
function onError(cfg) {
  return (cfg && cfg.onError === 'passthrough') ? 'passthrough' : 'block';
}

/* Only ever describes hits by type/token/pattern - never the real value. */
function describeHits(hits) {
  const byType = new Map();
  for (const h of hits) {
    const k = h.type + ' (' + h.source + ')';
    byType.set(k, (byType.get(k) || 0) + 1);
  }
  return Array.from(byType.entries())
    .map(([k, n]) => (n > 1 ? n + ' x ' + k : k))
    .join(', ');
}

module.exports = {
  core,
  readPayload,
  respond,
  noChange,
  setup,
  loadKey,
  loadConfig,
  onError,
  describeHits,
  saveDiscovered,
  cacheFile,
};
