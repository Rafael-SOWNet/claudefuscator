/*
 * Tests for the Claude Code mod.
 *
 * WHAT THESE DO AND DO NOT PROVE
 * ------------------------------
 * Mods need Claude Code v2.1.287+ and this machine has 2.1.211, so the mod
 * has never been loaded by Claude Code. These tests drive register() with a
 * fake `on` and a fake mods API (`$`), which proves:
 *
 *   - the module graph loads in an ES-module-only context
 *   - the expected events are registered, with the expected matchers
 *   - each hook transforms its event the way it is supposed to, in the
 *     right direction, given the documented event shapes
 *
 * They CANNOT prove that the documented event shapes match the shapes a
 * real Claude Code sends, because nothing here has met a real one. That is
 * the gap claude-mod/TESTING.md describes and the version bump closes.
 */

import test from 'node:test';
import assert from 'node:assert';

import { register } from '../claude-mod/hooks/register.js';
import core from '../claude-mod/hooks/claudefuscator-core.mjs';
import {
  readText, writeText, restoreToolEvent, scrubToolResult, scrubSections,
  scrubContextResult, restoreDeep, readAgentConfig, pendingMappings,
} from '../claude-mod/hooks/veil.js';

const KEY = 'mod-test-key';
const CONFIG = {
  tokenLength: 8,
  internalDomains: ['corp.example'],
  identifiers: [
    { type: 'PERSON', value: 'Jane Example' },
    { type: 'HOST', value: 'build-01.corp.example' },
  ],
};
const REAL_HOST = 'build-01.corp.example';
const REAL_PERSON = 'Jane Example';

/* A fake mods API. $.fs.read serves the config from memory, $.env.get is
 * empty, and $.ui.log collects lines so a test can assert on them. */
function fakeApi({ config = CONFIG, env = {}, httpResponse = { status: 200, ok: true, headers: {}, text: '{"added":1}' } } = {}) {
  const logs = [];
  const requests = [];
  return {
    logs,
    requests,
    $: {
      ui: { log: (m) => logs.push(m) },
      env: { get: (k) => env[k] ?? null },
      fs: {
        read: async (p) => {
          if (p === 'claudefuscator.local.json') return JSON.stringify(config);
          throw new Error('ENOENT ' + p);
        },
      },
      http: {
        fetch: async (url, init) => {
          requests.push({ url, init });
          if (httpResponse instanceof Error) throw httpResponse;
          return httpResponse;
        },
      },
    },
  };
}

/* Collects what register() registers, so a test can fire one event. */
function harness(options = { secret_key: KEY }) {
  const hooks = [];
  const on = (event, a, b) => {
    const matcher = typeof a === 'function' ? null : a;
    const hook = typeof a === 'function' ? a : b;
    hooks.push({ event, matcher, hook });
    return { catch: () => {} };
  };
  register(on, options);

  const find = (event, matcher) => {
    const got = hooks.filter((h) => h.event === event
      && (!matcher || JSON.stringify(h.matcher) === JSON.stringify(matcher)));
    assert.ok(got.length, `no hook registered for ${event} ${JSON.stringify(matcher || '')}`);
    return got[0].hook;
  };

  /* next() returns what Claude Code would have produced. */
  const fire = (event, e, nextResult, matcher) => {
    const api = fakeApi();
    const next = async (passed) => {
      next.received = passed;
      return typeof nextResult === 'function' ? nextResult(passed) : nextResult;
    };
    return find(event, matcher)(api.$, e, next)
      .then((result) => ({ result, passed: next.received, logs: api.logs }));
  };

  return { hooks, find, fire, events: hooks.map((h) => h.event) };
}

async function started(options = { secret_key: KEY }) {
  const h = harness(options);
  const api = fakeApi();
  await h.find('session.start')(api.$, {}, async (e) => e);
  return { ...h, logs: api.logs };
}

/* One API instance shared across every fire, so a test can watch what the
 * mod sent to the local agent over a whole session rather than per call. */
function agentHarness({ config, httpResponse } = {}) {
  const hooks = [];
  const on = (event, a, b) => {
    const matcher = typeof a === 'function' ? null : a;
    const hook = typeof a === 'function' ? a : b;
    hooks.push({ event, matcher, hook });
    return { catch: () => {} };
  };
  register(on, { secret_key: KEY });
  const api = fakeApi({ config, httpResponse });

  const fire = async (event, e, nextResult) => {
    const hook = hooks.find((h) => h.event === event);
    assert.ok(hook, 'no hook for ' + event);
    const next = async (passed) => (typeof nextResult === 'function' ? nextResult(passed) : nextResult);
    const result = await hook.hook(api.$, e, next);
    /* The flush is fire-and-forget by design, so give its promise a turn of
     * the event loop to land before asserting on what was sent. */
    await new Promise((r) => setImmediate(r));
    return result;
  };

  return { fire, api };
}

/* ---- the local agent --------------------------------------------------- */

const AGENT = 'http://127.0.0.1:8091';
const withAgent = (extra = {}) => ({ ...CONFIG, agent: { url: AGENT, ...extra } });

test('agent config: a loopback url enables it', () => {
  const a = readAgentConfig({ config: withAgent() });
  assert.equal(a.enabled, true);
  assert.equal(a.url, AGENT);
});

test('agent config: a trailing slash is normalised away', () => {
  assert.equal(readAgentConfig({ config: { agent: { url: AGENT + '/' } } }).url, AGENT);
});

test('agent config: absent means off, and the mod behaves as before', () => {
  assert.equal(readAgentConfig({ config: CONFIG }).enabled, false);
});

test('agent config: enabled:false wins over a url', () => {
  assert.equal(readAgentConfig({ config: withAgent({ enabled: false }) }).enabled, false);
});

test('agent config: a NON-LOOPBACK url is refused, not honoured', () => {
  /* The whole point. An agent url pointing off the machine would ship the
   * real identifier values to it - the exact thing this tool exists to
   * stop - so a config asking for that is wrong, not authoritative. */
  for (const url of [
    'http://evil.example:8091',
    'https://ai.example.com',
    'http://127.0.0.1.evil.example',
    'http://192.0.2.10:8091',       // TEST-NET-1, a non-loopback address
  ]) {
    const a = readAgentConfig({ config: { agent: { url } } });
    assert.equal(a.enabled, false, url + ' should be refused');
    assert.match(a.reason, /loopback/);
  }
});

test('pendingMappings returns discovered values only, and skips what was sent', () => {
  const vault = { discovered: new Map([['IP_aaaa1111', '10.1.2.3'], ['IP_bbbb2222', '10.4.5.6']]) };
  assert.equal(pendingMappings(vault, new Set()).length, 2);
  const rest = pendingMappings(vault, new Set(['IP_aaaa1111']));
  assert.deepEqual(rest, [{ token: 'IP_bbbb2222', value: '10.4.5.6' }]);
  assert.deepEqual(pendingMappings(null, new Set()), []);
});

test('a discovered pattern hit is submitted to the agent', async () => {
  /* A private IP is a pattern hit, so nothing on anyone's list derives it -
   * which is precisely the case the browser cannot resolve alone. */
  const { fire, api } = agentHarness({ config: withAgent() });
  await fire('prompt.submit', { text: 'the box at 10.44.2.9 is down' }, (e) => e);

  assert.equal(api.requests.length, 1, 'expected one POST to the agent');
  const [req] = api.requests;
  assert.equal(req.url, AGENT + '/mappings');
  assert.equal(req.init.method, 'POST');
  assert.match(req.init.headers['x-claudefuscator-auth'], /^[0-9a-f]{32}$/);

  const sent = JSON.parse(req.init.body).mappings;
  assert.ok(sent.some((m) => m.value === '10.44.2.9'), 'the real value was not submitted');
  assert.ok(sent.every((m) => /^[A-Z]+_[0-9a-f]+$/.test(m.token)), 'a malformed token was sent');
});

test('the key itself is never sent to the agent', async () => {
  const { fire, api } = agentHarness({ config: withAgent() });
  await fire('prompt.submit', { text: 'the box at 10.44.2.9 is down' }, (e) => e);
  const wire = JSON.stringify(api.requests);
  assert.ok(!wire.includes(KEY), 'the key appeared in a request to the agent');
});

test('list entries are not submitted - both sides derive those already', async () => {
  const { fire, api } = agentHarness({ config: withAgent() });
  await fire('prompt.submit', { text: `ping ${REAL_HOST} for ${REAL_PERSON}` }, (e) => e);
  const wire = JSON.stringify(api.requests);
  assert.ok(!wire.includes(REAL_HOST), 'a list entry was sent to the agent');
  assert.ok(!wire.includes(REAL_PERSON), 'a list entry was sent to the agent');
});

test('the same value is submitted once, not once per prompt', async () => {
  const { fire, api } = agentHarness({ config: withAgent() });
  await fire('prompt.submit', { text: 'host 10.44.2.9' }, (e) => e);
  await fire('prompt.submit', { text: 'host 10.44.2.9 again' }, (e) => e);
  assert.equal(api.requests.length, 1, 'the mod re-sent a value it had already shared');
});

test('with no agent configured the mod makes no network call at all', async () => {
  const { fire, api } = agentHarness({ config: CONFIG });
  await fire('prompt.submit', { text: 'the box at 10.44.2.9 is down' }, (e) => e);
  assert.equal(api.requests.length, 0);
});

test('a non-loopback agent url results in no network call', async () => {
  const { fire, api } = agentHarness({ config: { ...CONFIG, agent: { url: 'https://evil.example' } } });
  await fire('prompt.submit', { text: 'the box at 10.44.2.9 is down' }, (e) => e);
  assert.equal(api.requests.length, 0, 'the mod contacted a non-loopback agent');
});

test('a dead agent is reported once and never breaks the prompt', async () => {
  const { fire, api } = agentHarness({
    config: withAgent(), httpResponse: new Error('ECONNREFUSED'),
  });
  const r1 = await fire('prompt.submit', { text: 'host 10.44.2.9' }, (e) => e);
  const r2 = await fire('prompt.submit', { text: 'host 10.44.3.9' }, (e) => e);

  /* The prompt still went through, scrubbed. */
  assert.ok(r1.text.includes('IP_'), 'the prompt was not scrubbed');
  assert.ok(r2.text.includes('IP_'), 'the prompt was not scrubbed');
  const complaints = api.logs.filter((l) => l.includes('local agent'));
  assert.equal(complaints.length, 1, 'the mod should complain once, not every prompt');
});

/* ---- registration surface --------------------------------------------- */

test('registers the events the design depends on', () => {
  const { events } = harness();
  for (const expected of [
    'session.start', 'prompt.submit', 'prompt.section',
    'prompt.context', 'skill.prompt', 'prompt.attachment', 'tool.describe',
    'tool.call', 'ui.render',
  ]) {
    assert.ok(events.includes(expected), 'missing hook for ' + expected);
  }
});

test('each event is registered once, except ui.render which is per component', () => {
  /* Claude Code refuses a module that registers one event twice without a
   * matcher: "on(...) is registered twice without a matcher". */
  const { hooks } = harness();
  const unmatched = hooks.filter((h) => !h.matcher).map((h) => h.event);
  assert.strictEqual(new Set(unmatched).size, unmatched.length,
    'an event is registered twice without a matcher: ' + unmatched.join(', '));

  const renders = hooks.filter((h) => h.event === 'ui.render');
  const components = renders.map((h) => h.matcher.component);
  assert.strictEqual(new Set(components).size, components.length);
  assert.ok(components.includes('UserMessage'), 'your own message would stay tokenized on screen');
  assert.ok(components.includes('AssistantMessage'));
});

/* ---- startup ----------------------------------------------------------- */

test('session.start reports ACTIVE and the entry count', async () => {
  const { logs } = await started();
  assert.ok(logs.some((l) => l.includes('ACTIVE') && l.includes('2 list entries')), logs.join('\n'));
});

test('without a key it stays inert and says so', async () => {
  const { logs } = await started({});
  assert.ok(logs.some((l) => l.includes('INACTIVE') && l.includes('no key')), logs.join('\n'));
});

test('a collision is reported, not swallowed', async () => {
  const bad = { tokenLength: 1, identifiers: Array.from({ length: 40 }, (_, i) => ({ type: 'HOST', value: 'h' + i })) };
  const h = harness({ secret_key: KEY });
  const api = fakeApi({ config: bad });
  await h.find('session.start')(api.$, {}, async (e) => e);
  assert.ok(api.logs.some((l) => l.includes('INACTIVE') && l.includes('collision')), api.logs.join('\n'));
});

/* ---- outbound: real -> tokens ------------------------------------------ */

test('prompt.submit rewrites the typed prompt', async () => {
  /* The gap a settings hook cannot close. */
  const h = await started();
  const { passed, logs } = await h.fire('prompt.submit',
    { text: `why is ${REAL_HOST} down? ask ${REAL_PERSON}` }, (e) => e);

  assert.ok(!passed.text.includes(REAL_HOST), 'hostname reached the model: ' + passed.text);
  assert.ok(!passed.text.includes(REAL_PERSON));
  assert.match(passed.text, /HOST_[0-9a-f]{8}/);
  assert.ok(logs.some((l) => l.includes('scrubbed 2 identifier')), logs.join('\n'));
});

test('a prompt with nothing to scrub is passed through untouched', async () => {
  const h = await started();
  const e = { text: 'what time is it' };
  const { passed } = await h.fire('prompt.submit', e, (x) => x);
  assert.strictEqual(passed, e, 'the event object was copied for no reason');
});

test('prompt.section scrubs a system-prompt section', async () => {
  const h = await started();
  const { result } = await h.fire('prompt.section',
    { name: 'project' }, { text: `The build host is ${REAL_HOST}.` });
  assert.ok(!result.text.includes(REAL_HOST), result.text);
  assert.match(result.text, /HOST_[0-9a-f]{8}/);
});

test('prompt.context scrubs block text AND instructionFiles content', async () => {
  /* The build's types make PromptContextResult { blocks, instructionFiles? },
   * and CLAUDE.md's text lives in both places. Scrubbing only `blocks` left
   * the instruction files untouched. */
  const h = await started();
  const { result } = await h.fire('prompt.context', {}, {
    blocks: [{ name: 'claudeMd', text: `Project host: ${REAL_HOST}` }],
    instructionFiles: [{ path: '/p/CLAUDE.md', kind: 'project', content: `Owner: ${REAL_PERSON}` }],
  });
  assert.ok(!result.blocks[0].text.includes(REAL_HOST), 'block text not scrubbed');
  assert.ok(!result.instructionFiles[0].content.includes(REAL_PERSON),
    'instructionFiles content not scrubbed');
});

test('prompt.context never rewrites a block name or an instruction file path', async () => {
  /* `name` is what a matcher narrows on and `path` must stay a real file.
   * A blanket string walk would mangle both. */
  const h = await started();
  const { result } = await h.fire('prompt.context', {}, {
    blocks: [{ name: 'claudeMd', text: REAL_HOST }],
    instructionFiles: [{ path: '/p/CLAUDE.md', kind: 'project', content: REAL_HOST }],
  });
  assert.strictEqual(result.blocks[0].name, 'claudeMd');
  assert.strictEqual(result.instructionFiles[0].path, '/p/CLAUDE.md');
  assert.strictEqual(result.instructionFiles[0].kind, 'project');
});

test('prompt.compose is deliberately NOT registered', () => {
  /* It appears in the build's type map but the engine's loader refuses a
   * hook on it ("prompt.compose" is not an event). prompt.section and
   * prompt.context cover the same ground. */
  const { events } = harness();
  assert.ok(!events.includes('prompt.compose'));
});

test('tool.describe scrubs the description but not the tool name', async () => {
  const h = await started();
  const { result } = await h.fire('tool.describe',
    { tool: 'Read' }, { description: `Read a file from ${REAL_HOST}` });
  assert.ok(!result.description.includes(REAL_HOST));
});

/* ---- tool.call: both directions ---------------------------------------- */

test('tool arguments are restored so local disk gets real values', async () => {
  const h = await started();
  const vault = await core.buildVault(KEY, CONFIG);
  const token = (await core.scrub(REAL_HOST, vault)).text;

  const { passed } = await h.fire('tool.call',
    { tool: 'Write', file_path: 'notes.txt', content: `host is ${token}` }, 'ok');

  assert.strictEqual(passed.content, `host is ${REAL_HOST}`,
    'a Write would have put a token on disk');
  assert.strictEqual(passed.tool, 'Write', 'the tool name must not be rewritten');
});

test('tool results are scrubbed before Claude reads them', async () => {
  const h = await started();
  const { result } = await h.fire('tool.call',
    { tool: 'Read', file_path: '/etc/hosts' },
    { result: { content: `10.42.7.19 ${REAL_HOST}` }, text: `10.42.7.19 ${REAL_HOST} # ${REAL_PERSON}`, ref: 7 });

  const blob = JSON.stringify(result);
  assert.ok(!blob.includes(REAL_HOST) && !blob.includes(REAL_PERSON), blob);
  assert.match(result.text, /IP_[0-9a-f]{8}/, 'the private IP pattern did not fire');
});

test('a scrubbed tool result drops `ref`', async () => {
  /* `ref` names the messages core already produced, which are the UNSCRUBBED
   * ones, and "a hook that returns the object it got makes core use them
   * verbatim". Keeping it could discard the scrub silently. */
  const h = await started();
  const { result } = await h.fire('tool.call',
    { tool: 'Read' }, { result: REAL_HOST, text: REAL_HOST, ref: 42, isReadOnly: true });
  assert.ok(!('ref' in result), 'ref survived a rewrite');
  assert.strictEqual(result.isReadOnly, true, 'unrelated fields must be preserved');
});

test('a tool result with nothing to scrub keeps its ref', async () => {
  const h = await started();
  const untouched = { result: 'nothing here', text: 'nothing here', ref: 42 };
  const { result } = await h.fire('tool.call', { tool: 'Read' }, untouched);
  assert.strictEqual(result, untouched, 'an unchanged result should be passed through as-is');
});

test('a refusal is passed through untouched', async () => {
  const h = await started();
  const deny = { deny: 'Bash is turned off in this project.' };
  const { result } = await h.fire('tool.call', { tool: 'Bash', command: 'ls' }, deny);
  assert.deepStrictEqual(result, deny);
});

/* ---- inbound: tokens -> real, on screen -------------------------------- */

test('ui.render restores real values in the drawn text', async () => {
  const h = await started();
  const vault = await core.buildVault(KEY, CONFIG);
  const token = (await core.scrub(REAL_HOST, vault)).text;

  for (const component of ['AssistantMessage', 'UserMessage']) {
    const { passed } = await h.fire('ui.render',
      { component, props: { text: `${token} is down` } }, (e) => e, { component });
    assert.strictEqual(passed.props.text, `${REAL_HOST} is down`,
      component + ' still showed a token');
  }
});

test('ui.render deep-restores a ToolUse input object', async () => {
  /* The build's types make ToolUse.input `unknown`, usually an object, so a
   * top-level string check would skip it entirely. */
  const h = await started();
  const vault = await core.buildVault(KEY, CONFIG);
  const token = (await core.scrub(REAL_HOST, vault)).text;

  const { passed } = await h.fire('ui.render',
    { component: 'ToolUse', props: { tool: 'Bash', input: { command: `ssh ${token}` } } },
    (e) => e, { component: 'ToolUse' });
  assert.strictEqual(passed.props.input.command, `ssh ${REAL_HOST}`);
  assert.strictEqual(passed.props.tool, 'Bash', 'read-only prop must not change');
});

test('ui.render leaves a drawing with no tokens alone', async () => {
  const h = await started();
  const e = { component: 'AssistantMessage', props: { text: 'all good' } };
  const { passed } = await h.fire('ui.render', e, (x) => x, { component: 'AssistantMessage' });
  assert.strictEqual(passed, e);
});

/* ---- pure helpers ------------------------------------------------------ */

test('readText/writeText handle every documented result shape', () => {
  assert.deepStrictEqual(readText('hi', {}), { kind: 'string', text: 'hi' });
  assert.deepStrictEqual(readText({ text: 'hi' }, {}), { kind: 'field', text: 'hi' });
  assert.deepStrictEqual(readText(undefined, { text: 'hi' }), { kind: 'event', text: 'hi' });
  assert.deepStrictEqual(readText(undefined, {}), { kind: 'none', text: null });

  assert.strictEqual(writeText({ kind: 'string' }, 'old', 'new'), 'new');
  assert.deepStrictEqual(writeText({ kind: 'field' }, { text: 'old', k: 1 }, 'new'), { text: 'new', k: 1 });
  assert.deepStrictEqual(writeText({ kind: 'event' }, undefined, 'new'), { text: 'new' });
});

test('restoreToolEvent never rewrites structural fields', async () => {
  const vault = await core.buildVault(KEY, CONFIG);
  const e = { tool: 'Bash', tool_use_id: 'tu_1', id: 'x', command: 'echo hi' };
  const out = await restoreToolEvent(e, vault, core);
  assert.strictEqual(out.tool, 'Bash');
  assert.strictEqual(out.tool_use_id, 'tu_1');
});

test('scrubToolResult walks the typed record and keeps its shape', async () => {
  /* ToolCallResult is { deny } | { result, text?, context?, ref?, ... }, so
   * the tool's own record sits under `result` and may be any shape. */
  const vault = await core.buildVault(KEY, CONFIG);
  const { result } = await scrubToolResult({
    result: { content: [{ type: 'text', text: REAL_HOST }] },
    text: REAL_HOST,
    context: [`see ${REAL_HOST}`],
    isReadOnly: true,
  }, vault, core);

  assert.match(result.result.content[0].text, /^HOST_[0-9a-f]{8}$/);
  assert.strictEqual(result.result.content[0].type, 'text');
  assert.match(result.text, /^HOST_[0-9a-f]{8}$/, '`text` is what the model reads');
  assert.ok(!result.context[0].includes(REAL_HOST), '`context` is read by the model too');
  assert.strictEqual(result.isReadOnly, true);
});

test('an errored tool result is scrubbed too', async () => {
  const vault = await core.buildVault(KEY, CONFIG);
  const { result } = await scrubToolResult(
    { isError: true, result: `cannot reach ${REAL_HOST}`, text: `cannot reach ${REAL_HOST}` },
    vault, core);
  assert.strictEqual(result.isError, true);
  assert.ok(!result.text.includes(REAL_HOST));
  assert.ok(!String(result.result).includes(REAL_HOST));
});

test('an unconfigured vault makes every helper a no-op', async () => {
  assert.strictEqual((await scrubToolResult('x', null, core)).result, 'x');
  assert.strictEqual(await restoreToolEvent({ a: 'x' }, null, core).then((r) => r.a), 'x');
  assert.deepStrictEqual(await scrubContextResult({ blocks: [{ name: 'a', text: 'x' }] }, null, core),
    { blocks: [{ name: 'a', text: 'x' }] });
  assert.deepStrictEqual(await scrubSections([{ text: 'x' }], null, core), [{ text: 'x' }]);
});

/* ---- cross-surface agreement ------------------------------------------- */

test('the mod derives the same tokens as the proxy and the extension', async () => {
  /* The mod imports an ESM copy of the core with a footer appended. If that
   * copy ever diverges from the canonical one, the mod and the extension
   * would disagree and restore would silently stop working. */
  const vectors = JSON.parse(
    await (await import('node:fs/promises')).readFile(
      new URL('../shared/test-vectors.json', import.meta.url), 'utf8'));

  for (const t of vectors.tokens) {
    const got = await core.deriveToken(
      vectors.key, t.type, t.value, vectors.config.tokenLength, t.caseSensitive);
    assert.strictEqual(got, t.token, 'the mod derives a different token for ' + t.value);
  }
});
