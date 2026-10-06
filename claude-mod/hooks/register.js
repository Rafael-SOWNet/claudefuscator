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

/* How long to wait for the local agent to hand over a key and a list.
 *
 * Short on purpose. This runs before the first prompt is scrubbed, so
 * every millisecond is one the person is waiting; and the fallback -
 * running inert and saying so loudly - is a far better outcome than a
 * prompt that never returns. $.http.fetch has no timeout of its own,
 * which is the whole reason this constant exists.
 */
const AGENT_TIMEOUT_MS = 2000;

/* Shared by every hook in this module, which is how a mod keeps state. */
let vault = null;
/* 'warn' (default) or 'block'. Warn, not block, because a matcher that
 * stops work is one people route around, and this one is new enough
 * that its false-positive rate is unmeasured here. */
let secretPolicy = 'warn';
/* True when this mod's key and the agent's disagree. Carried into the
 * status line, because a warning logged once at load scrolls away and
 * this state lasts the whole session. */
let keyMismatch = false;
/* Where this session's key came from. Named in the status line so the
 * question "which key is the mod using" has an answer that does not
 * require reading the source. */
let keySource = 'unknown';
/* True when secret_key is set but deliberately disabled. Reported, so
 * that "ignored" never looks the same as "never configured". */
let disabledSecretKey = false;
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

/* Collect the key and the identifier list from the local agent.
 *
 * This is what lets a machine configure nothing: the agent connects to
 * the vault, unwraps the enrolled key, and hands both over loopback.
 *
 * WHY A HANDSHAKE FILE RATHER THAN A FIXED PORT
 *
 * /bootstrap cannot use the proof-of-key header every other agent route
 * uses, because the caller is asking for the key that header is built
 * from. The guard is a token the agent wrote to a file only this user can
 * read - which keeps the bar where it already was, since whoever can read
 * that file can read the vault credential beside it and collect the key
 * themselves. An unauthenticated loopback route would have lowered it to
 * "any local process".
 *
 * BOUNDED, BECAUSE THIS IS ON THE CRITICAL PATH
 *
 * $.http.fetch has no timeout and every hook awaits loading. A wedged or
 * dead agent would otherwise hang the prompt for ever - and a stale
 * handshake file naming a port nothing is listening on is an ordinary
 * occurrence, since an agent that is killed cannot clean up after itself.
 * So the fetch races a clock and loses after two seconds. Failing here
 * costs the scrubbing, which is loud; hanging costs the session.
 */
async function collectFromAgent($, homeDir) {
  if (!homeDir) return null;

  let handshake = null;
  try {
    const text = await $.fs.read(homeDir + '/.claudefuscator/agent.json');
    if (!text) return null;
    handshake = JSON.parse(text);
  } catch (_) {
    return null;
  }

  if (!handshake || !handshake.port || !handshake.token) return null;

  const url = 'http://127.0.0.1:' + handshake.port + '/bootstrap';

  try {
    /* The timeout arm swallows its own rejection. If the clock refuses,
     * this resolves null and the collection is abandoned - which is the
     * safe direction: without a working clock there is nothing bounding
     * the fetch, and an unbounded fetch on the critical path can hang the
     * prompt. Letting the rejection propagate instead would abandon the
     * attempt too, but by way of an exception that reads like a failure
     * of the agent. */
    const answer = await Promise.race([
      $.http.fetch(url, { headers: { 'x-claudefuscator-bootstrap': handshake.token } }),
      $.clock.sleep(AGENT_TIMEOUT_MS).then(() => null, () => null),
    ]);

    if (!answer || !answer.ok) return null;

    /* $.http.fetch resolves a plain { status, ok, headers, text } - not a
     * Response, and with no json(). Calling one threw, and the catch
     * below turned that into a silent "no agent", which is exactly the
     * shape of bug this project cannot afford: it scrubbed nothing and
     * said nothing was wrong. */
    const body = JSON.parse(answer.text);
    if (!body || !body.key) return null;

    return { key: body.key, config: body.config || null };
  } catch (_) {
    return null;
  }
}

async function load($) {
  keyMismatch = false;
  keySource = 'unknown';
  disabledSecretKey = false;

  /* `-` means "ignore this field", and it exists because there is no
   * other way out of it.
   *
   * secret_key is a sensitive userConfig field, so the plugin UI stores
   * it in Claude Code's credentials file and offers no way to empty it:
   * leaving the box blank means UNCHANGED, not cleared. Anyone who sets
   * a key and later moves to central mode is then stuck with it - and
   * stuck silently, because the mod goes on scrubbing with a key the
   * agent does not have, and nothing resolves for anybody else.
   *
   * Finding that out cost an afternoon and ended with editing a
   * credentials file by hand, which is not something to ask of anyone.
   * One typed character undoes it instead.
   */
  const configured = (options && options.secret_key) || null;
  const disabled = typeof configured === 'string'
    && ['-', 'none', 'agent'].includes(configured.trim().toLowerCase());

  disabledSecretKey = disabled;
  let key = disabled ? null : configured;
  keySource = key ? 'plugin config secret_key' : 'unknown';
  if (!key) {
    try { key = await $.env.get('CLAUDEFUSCATOR_KEY'); } catch (_) { key = null; }
    if (key) keySource = 'CLAUDEFUSCATOR_KEY in the environment';
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

  /* Nothing configured here? Ask the agent, which may have both.
   *
   * Last, not first, so an explicit local setting always wins. Someone
   * who put a key in the plugin config or a list on disk meant it, and
   * silently preferring what a service handed over would make the
   * setting they are looking at a lie.
   *
   * Asked for only when something is actually missing, so the ordinary
   * fully-configured case costs no round trip at all.
   */
  if (!key || !rawConfig) {
    const collected = await collectFromAgent($, homeDir);
    if (collected) {
      /* Two keys is the worst state this tool has, and until now it was
       * invisible. Everything keeps working: the mod scrubs, the status
       * line says ACTIVE, and the only symptoms are tokens the agent
       * cannot resolve and a 403 in a log nobody reads. Colleagues then
       * see red marks and conclude the vault lost their data.
       *
       * The two values are both in hand right here, so say it. */
      if (key && collected.key && key !== collected.key) {
        keyMismatch = true;
        $.ui.log('Claudefuscator: the key configured here is NOT the one the '
          + 'local agent holds. Tokens made here cannot be resolved by the '
          + 'agent or by the browser, and discovered values will be refused. '
          + 'Unset CLAUDEFUSCATOR_KEY (or clear secret_key) to use the '
          + 'enrolled key, or enrol this one.');
      }

      if (!key) { key = collected.key; keySource = 'the local agent'; }
      if (!rawConfig && collected.config) {
        rawConfig = { config: collected.config, source: 'the local agent' };
      }
    }
  }

  secretPolicy = (rawConfig && rawConfig.config
    && rawConfig.config.secretPolicy === 'block') ? 'block' : 'warn';

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

    /* In the status line as well as the one-off warning. The warning
     * scrolls away; this state lasts the session, and "ACTIVE" on its
     * own is exactly the reassurance that made this take an afternoon
     * to find. */
    if (keyMismatch) status += ' | KEY MISMATCH: the agent holds a different key';

    /* Which key, and where it came from.
     *
     * Eight characters of an HMAC over a fixed label: derived from the
     * key so it changes if one character does, one-way so it discloses
     * nothing, and stable so it can be read aloud. The agent prints the
     * same eight for the same key.
     *
     * Here because "ACTIVE" told us nothing for an entire afternoon
     * while the mod and the agent quietly used different keys. The
     * status line is where somebody looks first, so it should answer
     * the first question: WHICH key is this, and who gave it to me. */
    try {
      const fp = (await core.hmacHex(key, 'claudefuscator/fingerprint/v1')).slice(0, 8);
      status += ` | key: ${fp} (${keySource})`;
      if (disabledSecretKey) {
        status += ' | secret_key ignored by request';
      }
    } catch (_) {
      status += ' | key: fingerprint unavailable';
    }
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

    /* Credentials are checked BEFORE scrubbing and independently of it:
     * a prompt with no identifiers still gets this, and a machine with
     * no key or no list still gets it, because a pasted secret is a
     * problem whatever else is configured.
     *
     * Reported, never substituted. See the note on SECRET_PATTERNS -
     * a token round-trips, and a credential coming back is a new way to
     * spill it rather than a way to protect it. */
    if (typeof e.text === 'string') {
      const secrets = core.findSecrets(e.text);
      if (secrets.length) {
        const what = core.describeSecrets(secrets);
        if (secretPolicy === 'block') {
          $.ui.log(`Claudefuscator BLOCKED your prompt: it contains ${what}. `
            + 'Nothing was sent. Remove it, or set "secretPolicy": "warn" to '
            + 'send anyway.');
          /* Returning without next() is what stops it. The prompt is not
           * rewritten, because a credential silently removed from what
           * you typed is its own surprise. */
          return { text: '' };
        }
        $.ui.log(`Claudefuscator WARNING: your prompt contains ${what}, and it `
          + 'is being sent. Credentials are not tokenized - revoke it if this '
          + 'was not deliberate. Set "secretPolicy": "block" to stop instead.');
      }
    }

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
