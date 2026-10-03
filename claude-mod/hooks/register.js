/*
 * Claudefuscator mod - event wiring.
 *
 * NOT YET RUN IN CLAUDE CODE. Mods need v2.1.287+ and this machine has
 * 2.1.211, so everything here is written against the documented API and the
 * published type declarations, and the pure logic in veil.js is unit-tested.
 * The event wiring itself is unverified until the version is in place. See
 * claude-mod/TESTING.md for exactly what has and has not been checked.
 *
 * WHY A MOD AND NOT A HOOK: a settings hook cannot rewrite a prompt - the
 * hooks reference states it "can't replace the prompt; it only injects
 * additionalContext alongside it". A mod's prompt.submit can, and
 * prompt.section / prompt.compose / prompt.context / skill.prompt reach the
 * system prompt and project instructions that no settings hook sees.
 *
 * WHY THE PROXY STILL EXISTS: this rewrites at a dozen specific points; the
 * proxy rewrites one request body. The proxy's coverage is structural, this
 * one's is enumerated. They are kept as alternatives, not run together.
 */

import core from './claudefuscator-core.mjs';
import configMerge from './config-merge.mjs';
import {
  makeVault, scrubText, restoreText, restoreDeep, scrubContextResult, scrubSections,
  restoreToolEvent, scrubToolResult, readText, writeText, describeHits,
  readAgentConfig, pendingMappings, agentAuthHeader,
} from './veil.js';

/* Shared by every hook in this module, which is how a mod keeps state. */
let vault = null;
let status = 'INACTIVE (not initialised)';
let warnings = [];
let scrubbed = 0;

/* Loading is lazy and memoised rather than done only at session.start.
 * session.start fires once per load and NOT after /clear, /resume or
 * /branch, and some hosts (the test harness among them) never raise it at
 * all - so a hook that depended on it would silently scrub nothing. Every
 * scrubbing hook calls ensureLoaded first; the promise is shared, so the
 * config is read once however many hooks race for it.
 *
 * These are declared at the top of the file on purpose: the engine lets `$`
 * be passed only into a function declared here, never across an import and
 * never into one nested inside register(), because claude plugin validate
 * enumerates a mod's capabilities statically and has to be able to follow
 * every `$` call. That is also why the config reading lives here and
 * veil.js stays pure. */
let loading = null;
let options = null;

/* The local agent. `sentTokens` is what it has already been told, so a long
 * session re-sends nothing; `flushing` is a single-flight guard, because
 * every scrubbing hook can trigger a flush and they overlap freely. */
let agent = { enabled: false, url: null, reason: 'not initialised' };
let agentAuth = null;
let sentTokens = new Set();
let flushing = false;
let agentFailures = 0;

function ensureLoaded($) {
  if (!loading) loading = load($);
  return loading;
}

/* Hand newly discovered token -> value pairs to the local agent, so the
 * Chrome extension can unveil values it has no way to derive. Declared up
 * here with the other `$`-taking functions, for the reason given above.
 *
 * FIRE AND FORGET, DELIBERATELY. $.http.fetch has no timeout, so awaiting
 * this would let a wedged agent hang your prompt. A mapping that arrives
 * late costs a red highlight in the browser until the next flush; a prompt
 * that never returns costs the session. Nothing here is on the critical
 * path, so nothing here is allowed to block it or to throw.
 *
 * It only ever speaks to loopback - readAgentConfig refuses any other URL. */
function scheduleFlush($) {
  if (!agent.enabled || !agentAuth || flushing) return;
  const pending = pendingMappings(vault, sentTokens);
  if (!pending.length) return;

  flushing = true;
  /* Mark as sent BEFORE the request. A retry loop that re-sends on every
   * failure would hammer a down agent once per prompt for the whole
   * session; one attempt per value is enough for a best-effort cache, and
   * the proxy covers the same ground when it is running. */
  for (const m of pending) sentTokens.add(m.token);

  $.http.fetch(agent.url + '/mappings', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-claudefuscator-auth': agentAuth,
    },
    body: JSON.stringify({ mappings: pending }),
  }).then((res) => {
    flushing = false;
    if (res && res.ok) return;
    /* Say it once. An agent that is simply not running is the normal case
     * for anyone in mod-only mode without one, and a line per prompt would
     * train people to ignore Claudefuscator's output - which is exactly
     * what this tool cannot afford. */
    if (agentFailures++ === 0) {
      $.ui.log(`Claudefuscator: the local agent answered ${res && res.status} - `
        + 'discovered values are not being shared. The browser will mark them red.');
    }
  }).catch(() => {
    flushing = false;
    if (agentFailures++ === 0) {
      $.ui.log(`Claudefuscator: no local agent at ${agent.url} - discovered values `
        + 'stay in this process. The browser will mark them red.');
    }
  });
}

async function load($) {
  let key = (options && options.secret_key) || null;
  if (!key) {
    try { key = await $.env.get('CLAUDEFUSCATOR_KEY'); } catch (_) { key = null; }
  }

  /* For ~ in project paths. Each name is spelled out literally because
   * $.env.get takes a literal, so the variables a mod reads can be listed
   * by `claude plugin validate` without running it. */
  let homeDir = null;
  try { homeDir = await $.env.get('HOME'); } catch (_) { homeDir = null; }
  if (!homeDir) {
    try { homeDir = await $.env.get('USERPROFILE'); } catch (_) { homeDir = null; }
  }

  const candidates = [];
  if (options && options.config_path) candidates.push(options.config_path);
  try {
    const fromEnv = await $.env.get('CLAUDEFUSCATOR_CONFIG');
    if (fromEnv) candidates.push(fromEnv);
  } catch (_) { /* no env access; fall through to the default path */ }
  candidates.push('claudefuscator.local.json');

  let rawConfig = null;
  for (const candidate of candidates) {
    let text = null;
    try { text = await $.fs.read(candidate); } catch (_) { continue; }
    if (!text) continue;
    try {
      rawConfig = { config: JSON.parse(text), source: candidate };
    } catch (err) {
      vault = null;
      status = `INACTIVE (config at ${candidate} is not valid JSON)`;
      return;
    }
    break;
  }

  const packs = new Map();
  for (const ref of (rawConfig && rawConfig.config.packs) || []) {
    let text = null;
    try { text = await $.fs.read(ref); } catch (_) { continue; }
    if (!text) continue;
    try { packs.set(ref, JSON.parse(text)); } catch (_) { /* merge warns */ }
  }

  /* Project gate. Read the session's directory and stop here when it is not
   * one of the configured projects, BEFORE building a vault - so a mod that
   * has been loaded globally still does nothing outside the projects you
   * named. $.session.cwd is spelled out here because `$` cannot cross an
   * import, and it shows up in `claude plugin validate` output, which is
   * where someone auditing the mod should be able to see it. */
  const projects = (rawConfig && rawConfig.config.projects) || null;
  if (Array.isArray(projects) && projects.length) {
    let cwd = null;
    try { cwd = await $.session.cwd(); } catch (_) { cwd = null; }
    if (!configMerge.matchesProject(cwd, projects, { home: homeDir })) {
      vault = null;
      status = `INACTIVE (this project is not on the configured list of ${projects.length})`;
      $.ui.log('Claudefuscator: ' + status);
      return;
    }
  }

  const built = await makeVault(key, rawConfig, packs, core, configMerge);
  vault = built.vault;
  status = built.status;
  if (vault && !(Array.isArray(projects) && projects.length)) {
    status += ' [all projects - set "projects" in your config to limit it]';
  }
  warnings = built.warnings || [];

  /* The agent is opt-in: no `agent.url` in the config means no agent, and
   * the mod behaves exactly as it did before. Say which it is, because a
   * mod that silently stopped sharing discovered values looks identical to
   * one that is sharing them, and the difference only shows up later as
   * unexplained red marks in the browser. */
  agent = readAgentConfig(rawConfig);
  sentTokens = new Set();
  agentFailures = 0;
  if (vault && agent.enabled) {
    try {
      agentAuth = await agentAuthHeader(key, core);
    } catch (_) {
      agentAuth = null;
      agent = { enabled: false, url: null, reason: 'could not derive the agent auth header' };
    }
  } else {
    agentAuth = null;
  }
  if (vault) {
    status += agent.enabled
      ? ` | agent: ${agent.url}`
      : ` | agent: off (${agent.reason})`;
  }

  /* Report here rather than only from session.start, which does not fire
   * after /clear, /resume or /branch and is absent in some hosts. An
   * unconfigured Claudefuscator behaves exactly like a working one from the
   * outside, so this line is the difference between a tool you can trust
   * and one you merely hope is on. */
  $.ui.log('Claudefuscator: ' + status);
  for (const w of warnings) $.ui.log('Claudefuscator: ' + w);
}

export function register(on, pluginOptions) {
  /* A reload re-runs register, and the config may have changed since, so
   * clear what the last load cached rather than serving a stale vault. */
  options = pluginOptions;
  loading = null;
  vault = null;
  status = 'INACTIVE (not initialised)';
  warnings = [];
  agent = { enabled: false, url: null, reason: 'not initialised' };
  agentAuth = null;
  sentTokens = new Set();
  flushing = false;
  agentFailures = 0;

  /* ---- startup ------------------------------------------------------
   * Say out loud whether scrubbing is on. An unconfigured Claudefuscator
   * behaves exactly like a working one from the outside, so silence here is
   * the dangerous failure mode. */
  /* Say out loud whether scrubbing is on. An unconfigured Claudefuscator
   * behaves exactly like a working one from the outside, so silence here is
   * the dangerous failure mode. */
  on('session.start', async ($, e, next) => {
    await ensureLoaded($);
    return next(e);
  });

  /* ---- outbound: real -> tokens -------------------------------------- */

  /* The prompt you typed. This is the gap a settings hook cannot close. */
  on('prompt.submit', async ($, e, next) => {
    await ensureLoaded($);
    if (!vault || typeof e.text !== 'string') return next(e);
    const r = await scrubText(e.text, vault, core);
    if (!r.hits.length) return next(e);
    scrubbed += r.hits.length;
    $.ui.log(`Claudefuscator scrubbed ${r.hits.length} identifier(s) from your prompt: ${describeHits(r.hits)}`);
    scheduleFlush($);
    return next({ ...e, text: r.text });
  });

  /* Each named section of the system prompt. */
  on('prompt.section', async ($, e, next) => {
    await ensureLoaded($);
    const result = await next(e);
    if (!vault) return result;
    const shape = readText(result, e);
    if (shape.text === null) return result;
    const r = await scrubText(shape.text, vault, core);
    if (!r.hits.length) return result;
    scrubbed += r.hits.length;
    return writeText(shape, result, r.text);
  });

  /* NOTE: prompt.compose appears in the type map but the engine's loader
   * refuses a hook on it ("prompt.compose" is not an event), so it is not
   * registered. prompt.section and prompt.context cover the same ground. */

  /* The context sent with the first message. This is how project
   * instructions reach Claude - the built-in agents-md mod injects
   * AGENTS.md here - so it is where CLAUDE.md content gets scrubbed. */
  on('prompt.context', async ($, e, next) => {
    await ensureLoaded($);
    const result = await next(e);
    if (!vault) return result;
    /* Covers both the `claudeMd` block's text and the instructionFiles list
     * that backs it; see scrubContextResult for why only `text`/`content`
     * and never `name`/`path`. */
    return scrubContextResult(result, vault, core);
  });

  /* A skill's expanded text. */
  on('skill.prompt', async ($, e, next) => {
    await ensureLoaded($);
    const result = await next(e);
    if (!vault) return result;
    const shape = readText(result, e);
    if (shape.text === null) return result;
    const r = await scrubText(shape.text, vault, core);
    return r.hits.length ? writeText(shape, result, r.text) : result;
  });

  /* Messages Claude Code writes for Claude itself, such as reminders. */
  on('prompt.attachment', async ($, e, next) => {
    await ensureLoaded($);
    const result = await next(e);
    if (!vault) return result;
    const shape = readText(result, e);
    if (shape.text === null) return result;
    const r = await scrubText(shape.text, vault, core);
    return r.hits.length ? writeText(shape, result, r.text) : result;
  });

  /* Tool descriptions are prose written by whoever defined the tool and can
   * carry a hostname. The tool's NAME is API surface and is left alone. */
  on('tool.describe', async ($, e, next) => {
    await ensureLoaded($);
    const result = await next(e);
    if (!vault) return result;
    const shape = readText(result, e, 'description');
    if (shape.text === null) return result;
    const r = await scrubText(shape.text, vault, core);
    return r.hits.length ? writeText(shape, result, r.text, 'description') : result;
  });

  /* ---- both directions, in one place --------------------------------
   * Arguments inbound (tokens -> real) so the tool acts on real values and
   * anything it writes to disk is deobfuscated; result outbound
   * (real -> tokens) before Claude reads it. */
  on('tool.call', async ($, e, next) => {
    await ensureLoaded($);
    if (!vault) return next(e);
    const restored = await restoreToolEvent(e, vault, core);
    const result = await next(restored);
    const { result: clean, hits } = await scrubToolResult(result, vault, core);
    if (hits.length) {
      scrubbed += hits.length;
      $.ui.log(`Claudefuscator scrubbed ${hits.length} identifier(s) from ${e.tool}: ${describeHits(hits)}`);
      /* Tool output is where most pattern hits come from - a log full of
       * hostnames, a config dump - so this is the flush that matters. */
      scheduleFlush($);
    }
    return clean;
  });

  /* ---- inbound: tokens -> real, on screen ----------------------------
   * Display only. The transcript keeps tokens, which is the one behavioural
   * difference from proxy mode, where the transcript keeps real values.
   * Both are fine: tokens on disk are not the threat.
   *
   * UserMessage matters as much as AssistantMessage here: prompt.submit
   * rewrote the stored prompt, and without this you would read your own
   * message back as tokens.
   *
   * The pattern is the one the Spinner example uses - rewrite props and
   * call next - so Claude Code still draws the component itself and only
   * the text changes. */
  for (const component of ['AssistantMessage', 'UserMessage', 'ToolResult', 'ToolUse']) {
    on('ui.render', { component }, async ($, e, next) => {
      await ensureLoaded($);
      if (!vault || !e.props) return next(e);
      const props = restoreProps(e.props);
      return props === e.props ? next(e) : next({ ...e, props });
    });
  }
}

/* Which prop carries displayed content depends on the component, and the
 * build's types pin it: UserMessage and AssistantMessage have `text: string`;
 * ToolUse has `input: unknown` and ToolResult `output: unknown`, which are
 * usually objects, so those need a deep walk rather than a string check.
 * Everything else on those components is read-only (`origin`, `isExpanded`,
 * `onScreen`, `tool`, `isErrored`) and a rewrite of it is refused, so it is
 * left strictly alone. */
function restoreProps(props) {
  let changed = false;
  const out = { ...props };

  if (typeof props.text === 'string') {
    const restored = restoreText(props.text, vault, core);
    if (restored !== props.text) { out.text = restored; changed = true; }
  }
  for (const key of ['input', 'output']) {
    if (!(key in props) || props[key] == null) continue;
    const restored = restoreDeep(props[key], vault, core);
    if (JSON.stringify(restored) !== JSON.stringify(props[key])) { out[key] = restored; changed = true; }
  }

  return changed ? out : props;
}
