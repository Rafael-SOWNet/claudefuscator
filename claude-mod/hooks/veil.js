/*
 * Claudefuscator mod - the pure part.
 *
 * Everything here is a plain function over plain data, deliberately separate
 * from register.js, so it can be tested with `node --test` on any machine
 * without Claude Code v2.1.287+ present. register.js is the thin wiring that
 * maps these onto events.
 *
 * DIRECTION OF TRAVEL, which is the thing to keep straight:
 *
 *   outbound (toward the model)   real -> tokens
 *       the prompt you typed, system-prompt sections, first-message context,
 *       skill text, Claude Code's own reminders, tool descriptions,
 *       and tool RESULTS.
 *
 *   inbound (back onto your machine)   tokens -> real
 *       tool ARGUMENTS, so a Write/Edit/Bash acts on real values and local
 *       disk gets deobfuscated content, and the rendered interface, so you
 *       read real values on screen.
 *
 * A mod rewrites at a dozen specific points rather than at one request body.
 * That is more precise than the proxy but has more places to miss, so each
 * hook is listed in claude-mod/TESTING.md with what it covers.
 */

/* Event result shapes are not uniform: some events resolve to a string, some
 * to { text }, some to undefined when nothing downstream changed it. Rather
 * than assume, read defensively and put the value back the same shape it
 * came in. Guessing wrong here fails silently, which is the one failure mode
 * this project cannot tolerate. */
export function readText(result, event, field = 'text') {
  if (typeof result === 'string') return { kind: 'string', text: result };
  if (result && typeof result[field] === 'string') return { kind: 'field', text: result[field] };
  if (event && typeof event[field] === 'string') return { kind: 'event', text: event[field] };
  return { kind: 'none', text: null };
}

export function writeText(shape, result, text, field = 'text') {
  if (shape.kind === 'string') return text;
  if (shape.kind === 'field') return { ...result, [field]: text };
  if (shape.kind === 'event') return { [field]: text };
  return result;
}

/* Walk any JSON-ish value, applying an async fn to every string leaf. Shared
 * by the tool-argument and tool-result paths, which both see arbitrary
 * structures. Mirrors core.mapStrings; kept here so veil.js stands alone. */
export async function mapStrings(value, fn) {
  if (typeof value === 'string') return fn(value);
  if (Array.isArray(value)) {
    const out = [];
    for (const v of value) out.push(await mapStrings(v, fn));
    return out;
  }
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) out[k] = await mapStrings(value[k], fn);
    return out;
  }
  return value;
}

/* Fields of a tool.call event that are structure, not content. `tool` names
 * the tool and rewriting it would break the call outright. */
const TOOL_META = new Set(['tool', 'toolUseId', 'tool_use_id', 'id', 'agentId', 'agent_id']);

/*
 * Tool arguments, inbound: tokens -> real.
 * Without this the model asks to grep HOST_cf7b891e and the tool finds
 * nothing. With it, the tool acts on the real value and anything written to
 * disk is deobfuscated, which is the point: tokens are a wire format, not a
 * storage format.
 */
export async function restoreToolEvent(event, vault, core) {
  if (!vault) return event;
  const out = { ...event };
  let changed = false;
  for (const key of Object.keys(event)) {
    if (TOOL_META.has(key)) continue;
    const mapped = await mapStrings(event[key], (s) => {
      const r = core.restore(s, vault);
      if (r.changed) changed = true;
      return r.text;
    });
    out[key] = mapped;
  }
  return changed ? out : event;
}

/*
 * Tool results, outbound: real -> tokens, before Claude reads them.
 * A refusal ({ deny }) is the mod's own text and carries nothing of yours,
 * so it is passed through untouched.
 */
export async function scrubToolResult(result, vault, core) {
  if (!vault || result == null) return { result, hits: [] };
  /* A refusal is the mod's own text and carries nothing of yours. */
  if (typeof result === 'object' && typeof result.deny === 'string') return { result, hits: [] };
  if (typeof result !== 'object') {
    const r = await core.scrub(result, vault);
    return { result: r.text, hits: r.hits };
  }

  const hits = [];
  const scrub = async (s) => {
    const r = await core.scrub(s, vault);
    for (const h of r.hits) hits.push(h);
    return r.text;
  };

  const out = { ...result };
  /* `result` is the tool's typed record and `text` is "the result as the
   * model reads it" - the one that actually reaches Claude. Scrub both, plus
   * `context`, which the model also reads. */
  if ('result' in result) out.result = await mapStrings(result.result, scrub);
  if (typeof result.text === 'string') out.text = await scrub(result.text);
  if (Array.isArray(result.context)) out.context = await mapStrings(result.context, scrub);

  if (!hits.length) return { result, hits };

  /* `ref` names the messages core already produced for this call, which stay
   * on the host side, and "a hook that returns the object it got makes core
   * use them verbatim". Those messages are the UNSCRUBBED ones. Dropping the
   * ref is what forces core to use the result we are returning instead -
   * without this the scrub could be silently discarded. */
  delete out.ref;

  return { result: out, hits };
}

/* Outbound text scrub, for the prompt and every system-prompt surface. */
export async function scrubText(text, vault, core) {
  if (!vault || typeof text !== 'string' || !text) return { text, hits: [] };
  const r = await core.scrub(text, vault);
  return { text: r.text, hits: r.hits };
}

/* Deep restore for a display prop whose type is `unknown` - a ToolUse's
 * `input` and a ToolResult's `output` are usually objects, so a top-level
 * string check would skip them entirely. */
export function restoreDeep(value, vault, core) {
  if (!vault) return value;
  if (typeof value === 'string') return core.restore(value, vault).text;
  if (Array.isArray(value)) return value.map((v) => restoreDeep(v, vault, core));
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) out[k] = restoreDeep(value[k], vault, core);
    return out;
  }
  return value;
}

/* Inbound text restore, for what is drawn on screen. */
export function restoreText(text, vault, core) {
  if (!vault || typeof text !== 'string' || !text) return text;
  return core.restore(text, vault).text;
}

/*
 * prompt.context resolves to { blocks, instructionFiles? }.
 *
 * A block is { name, text }: `name` is the key it renders under (`claudeMd`,
 * `userEmail`, ...) and is what a matcher narrows on, so only `text` may be
 * rewritten - a blanket string walk would mangle the name and detach the
 * block.
 *
 * `instructionFiles` is the separate list of loaded instruction files, each
 * { path, kind, content }. `content` is the CLAUDE.md text itself. Scrubbing
 * only `blocks` would leave it untouched if the engine reframes from this
 * list, so both are covered; scrubbing is idempotent, so covering both is
 * free. `path` is left alone: rewriting it would point at a file that does
 * not exist.
 */
export async function scrubContextResult(result, vault, core) {
  if (!vault || !result) return result;
  const out = { ...result };
  let changed = false;

  if (Array.isArray(result.blocks)) {
    const blocks = [];
    for (const b of result.blocks) {
      if (!b || typeof b.text !== 'string') { blocks.push(b); continue; }
      const r = await core.scrub(b.text, vault);
      if (r.hits.length) changed = true;
      blocks.push(r.hits.length ? { ...b, text: r.text } : b);
    }
    out.blocks = blocks;
  }

  if (Array.isArray(result.instructionFiles)) {
    const files = [];
    for (const f of result.instructionFiles) {
      if (!f || typeof f.content !== 'string') { files.push(f); continue; }
      const r = await core.scrub(f.content, vault);
      if (r.hits.length) changed = true;
      files.push(r.hits.length ? { ...f, content: r.text } : f);
    }
    out.instructionFiles = files;
  }

  return changed ? out : result;
}

/*
 * prompt.compose resolves to { sections }, a list of { id, text, scope }.
 * Scrub each section's text and leave ids and scopes alone - they are
 * structure, and rewriting an id would detach the section.
 */
export async function scrubSections(sections, vault, core) {
  if (!vault || !Array.isArray(sections)) return sections;
  const out = [];
  for (const section of sections) {
    if (!section || typeof section.text !== 'string') { out.push(section); continue; }
    out.push({ ...section, text: (await core.scrub(section.text, vault)).text });
  }
  return out;
}

/*
 * Build the vault from an already-loaded key and config.
 *
 * Takes plain data, never `$`. The engine refuses a module that passes `$`
 * across an import - every `$.noun.method()` has to be spelled literally in
 * the hook's own file so `claude plugin validate` can enumerate what the mod
 * does without running it. So all reading happens in register.js and this
 * stays pure, which is also what makes it testable without Claude Code.
 */
export async function makeVault(key, rawConfig, packs, core, configMerge) {
  if (!key) return { vault: null, status: 'INACTIVE (no key configured)' };
  if (!rawConfig) return { vault: null, status: 'INACTIVE (no identifier config found)' };

  /* packs: Map of ref -> parsed pack object, read by the caller. */
  const loadPack = (ref) => {
    const cfg = packs && packs.get(ref);
    return cfg ? { config: cfg, source: ref } : null;
  };

  let merged;
  try {
    merged = configMerge.mergeConfig(rawConfig.config, loadPack, { source: rawConfig.source });
  } catch (err) {
    return { vault: null, status: `INACTIVE (${err.message})` };
  }

  let vault;
  try {
    vault = await core.buildVault(key, merged.config);
  } catch (err) {
    /* Collision or bad config. Surface it: silence here looks exactly like
     * working correctly, which is this tool's worst failure mode. */
    return { vault: null, status: `INACTIVE (${err.message})`, warnings: merged.warnings };
  }

  const n = vault.tokenToValue.size;
  const patterns = vault.patterns.map((p) => p.name).join(', ') || 'none';
  return {
    vault,
    status: `ACTIVE (${n} list entr${n === 1 ? 'y' : 'ies'}; patterns: ${patterns}; config: ${rawConfig.source})`,
    warnings: merged.warnings,
  };
}

/* Hit records carry types and tokens only, never the real value, so a
 * caller can log them safely. */
export function describeHits(hits) {
  const byType = new Map();
  for (const h of hits) {
    const k = `${h.type} (${h.source})`;
    byType.set(k, (byType.get(k) || 0) + 1);
  }
  return Array.from(byType.entries())
    .map(([k, n]) => (n > 1 ? `${n} x ${k}` : k))
    .join(', ');
}

/* ---- the local agent ---------------------------------------------------
 *
 * The mod discovers token -> value pairs that nothing else holds: pattern
 * hits, where the matched value was never on anybody's list. The Chrome
 * extension cannot derive those for itself - it only knows what its own
 * config gives it - so without a path off this process they reach the
 * browser as unresolvable and get marked red.
 *
 * The agent is that path. This is the pure half of the client: which
 * mappings are still owed, and how the agent is addressed. The fetch itself
 * has to live in register.js, because `$` cannot cross an import and
 * `claude plugin validate` has to be able to see every call statically.
 *
 * Submitting sends REAL VALUES to a loopback service. That is consistent
 * with the threat model rather than a hole in it: the threat is Anthropic
 * seeing the values, and local plaintext is not the threat. What would be a
 * hole is sending them anywhere else, which is why the URL is validated
 * against loopback below rather than taken on trust from a config file.
 */

/* Only these. A config that points the agent at a remote host is a config
 * that ships your identifier list off the machine, so it is refused rather
 * than honoured - this is the one place where "do what the config says"
 * is the wrong instinct. The shared vault is reached BY the agent, over
 * TLS and behind Entra; it is never reached from here. */
const LOOPBACK = /^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?\/?$/;

export function readAgentConfig(rawConfig) {
  const raw = rawConfig && rawConfig.config && rawConfig.config.agent;
  if (!raw || typeof raw !== 'object') {
    return { enabled: false, url: null, reason: 'not configured' };
  }
  if (raw.enabled === false) {
    return { enabled: false, url: null, reason: 'disabled in config' };
  }
  const url = typeof raw.url === 'string' && raw.url ? raw.url.trim() : null;
  if (!url) {
    return { enabled: false, url: null, reason: 'no agent.url set' };
  }
  if (!LOOPBACK.test(url)) {
    /* Loud, not silent: a non-loopback agent URL is very likely a mistake
     * and possibly an attempt to exfiltrate, and either way the user needs
     * to know their mappings are NOT being submitted. */
    return {
      enabled: false,
      url: null,
      reason: `agent.url must be loopback, refusing ${url}`,
    };
  }
  return { enabled: true, url: url.replace(/\/$/, ''), reason: null };
}

/* token -> value pairs the agent has not been told about yet.
 *
 * `sent` is the caller's record of what has already gone, so a long session
 * re-sends nothing. List entries are deliberately excluded: anyone holding
 * the key and the same list derives those independently, so sending them
 * would put real values on the wire to no purpose. */
export function pendingMappings(vault, sent) {
  if (!vault || !vault.discovered || !vault.discovered.size) return [];
  const out = [];
  for (const [token, value] of vault.discovered) {
    if (sent && sent.has(token)) continue;
    if (typeof token !== 'string' || typeof value !== 'string') continue;
    out.push({ token, value });
  }
  return out;
}

/* The proof-of-key header. Same construction as the proxy's and the
 * agent's own, so all three agree without any of them sending the key. */
export async function agentAuthHeader(secret, core) {
  const hex = await core.hmacHex(secret, 'claudefuscator/mappings/v1');
  return hex.slice(0, 32);
}
