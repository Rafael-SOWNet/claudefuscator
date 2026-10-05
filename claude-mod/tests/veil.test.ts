/*
 * Runs against the engine itself: `claude plugin test ./claude-mod`.
 *
 * test/mod.test.mjs drives register() with a fake `on`, which proves the
 * logic but not the event shapes. This file is the real thing: the engine
 * loads the plugin and the hooks a test registers sit BENEATH it, standing
 * in for the engine's own behaviour, so what these assert is what Claude
 * Code actually hands the mod.
 *
 * The config is served by answering `fs.read`, because every mods API method
 * is also an event. That keeps the test hermetic - no fixture on disk, and
 * no dependence on the working directory.
 */

import { test, expect } from 'claude-code/testing';

const KEY = 'mod-plugin-test-key';
const OPTIONS = { secret_key: KEY, config_path: 'test-config.json' };

const REAL_HOST = 'build-01.corp.example';
const REAL_PERSON = 'Jane Example';

const BASE = {
  tokenLength: 8,
  internalDomains: ['corp.example'],
  identifiers: [
    { type: 'PERSON', value: REAL_PERSON },
    { type: 'HOST', value: REAL_HOST },
  ],
};
const CONFIG = JSON.stringify(BASE);

/* Serve the config, and let every other read fail as it would. */
function serveConfig(on: any, body: string | null = CONFIG) {
  /* The loader reports its status through $.ui.log; a test has to answer it
   * or the call is dropped and the engine logs a complaint. */
  on('ui.log', async () => ({ value: undefined }));
  on('fs.read', async (_$: any, e: any) => {
    /* The engine resolves a relative path against the PLUGIN directory and
     * hands the hook { path, as }. */
    if (body !== null && String(e.path).endsWith('test-config.json')) return { value: body };
    return { deny: 'not found' };
  });
}

/* ---- outbound: what the model receives --------------------------------- */

test('the typed prompt reaches the model scrubbed', { options: OPTIONS }, async ($, on) => {
  serveConfig(on);
  on('prompt.submit', async (_$, e) => e);

  const result = await $.prompt.submit({ text: `why is ${REAL_HOST} down? ask ${REAL_PERSON}` });
  expect(result.text).not.toContain(REAL_HOST);
  expect(result.text).not.toContain(REAL_PERSON);
  expect(result.text).toMatch(/HOST_[0-9a-f]{8}/);
  expect(result.text).toMatch(/PERSON_[0-9a-f]{8}/);
});

test('a prompt with no identifiers is untouched', { options: OPTIONS }, async ($, on) => {
  serveConfig(on);
  on('prompt.submit', async (_$, e) => e);
  const result = await $.prompt.submit({ text: 'what time is it' });
  expect(result.text).toBe('what time is it');
});

test('the same value gets the same token every time', { options: OPTIONS }, async ($, on) => {
  serveConfig(on);
  on('prompt.submit', async (_$, e) => e);

  const first = await $.prompt.submit({ text: REAL_HOST });
  expect(first.text).toMatch(/^HOST_[0-9a-f]{8}$/);
  const again = await $.prompt.submit({ text: `again: ${REAL_HOST}` });
  expect(again.text).toBe(`again: ${first.text}`);
});

test('with no identifier config the mod is inert', { options: OPTIONS }, async ($, on) => {
  serveConfig(on, null);
  on('prompt.submit', async (_$, e) => e);
  const result = await $.prompt.submit({ text: `ping ${REAL_HOST}` });
  /* Inert means NOT scrubbing. Asserted honestly rather than letting a
   * passing test imply protection that is not there. */
  expect(result.text).toContain(REAL_HOST);
});

/* ---- tool calls: both directions --------------------------------------- */

test('a tool result is scrubbed before Claude reads it', { options: OPTIONS }, async ($, on) => {
  serveConfig(on);
  on('tool.call', async () => ({ result: `10.42.7.19 ${REAL_HOST}` }));

  const result = await $.tool.call({ tool: 'Bash', command: 'cat /etc/hosts' });
  const seen = JSON.stringify(result);
  expect(seen).not.toContain(REAL_HOST);
  expect(seen).toMatch(/HOST_[0-9a-f]{8}/);
  expect(seen).toMatch(/IP_[0-9a-f]{8}/);
});

test('tool arguments are restored, so the tool runs on real values',
  { options: OPTIONS }, async ($, on) => {
    serveConfig(on);
    on('prompt.submit', async (_$, e) => e);

    /* The bottom hook stands for the tool: it records the command it was
     * handed, which is what a real Bash would have executed. */
    let executed: string | undefined;
    on('tool.call', async (_$, e: any) => {
      executed = e.command;
      return { result: 'ok' };
    });

    /* Learn the token the way the model would have seen it. */
    const scrubbed = await $.prompt.submit({ text: REAL_HOST });
    await $.tool.call({ tool: 'Bash', command: `ssh ${scrubbed.text} uptime` });

    expect(executed).toBe(`ssh ${REAL_HOST} uptime`);
  });

/* ---- cross-surface agreement ------------------------------------------ */

test('the mod derives the tokens the proxy and the extension expect',
  { options: OPTIONS }, async ($, on) => {
    /* THE test for this mod. Its sandbox has no usable crypto.subtle, so it
     * takes the core's pure HMAC path while the proxy and the Chrome
     * extension take the WebCrypto one. These two constants were produced by
     * the WebCrypto path in Node; if the engine disagrees with them, the mod
     * and the extension derive different tokens and restore silently fails. */
    serveConfig(on);
    on('prompt.submit', async (_$, e) => e);

    const host = await $.prompt.submit({ text: REAL_HOST });
    expect(host.text).toBe('HOST_371cafb8');

    const person = await $.prompt.submit({ text: REAL_PERSON });
    expect(person.text).toBe('PERSON_5edc3577');
  });

/* ---- project gate ------------------------------------------------------ */

test('a project not on the list leaves everything alone',
  { options: OPTIONS }, async ($, on) => {
    /* The gate exists so that a mod loaded globally still does nothing
     * outside the projects you named. Asserts it is NOT scrubbing, which is
     * the whole point of the setting. */
    on('session.cwd', async () => ({ value: '/work/acme' }));
    serveConfig(on, JSON.stringify({ ...BASE, projects: ['/somewhere/else'] }));
    on('prompt.submit', async (_$, e) => e);

    const result = await $.prompt.submit({ text: `ping ${REAL_HOST}` });
    expect(result.text).toContain(REAL_HOST);
  });

test('a project on the list scrubs as usual', { options: OPTIONS }, async ($, on) => {
    /* Every mods API method is also an event, so the test answers
     * session.cwd rather than depending on where it happens to run. */
    on('session.cwd', async () => ({ value: '/work/acme' }));
    serveConfig(on, JSON.stringify({ ...BASE, projects: ['/work/acme'] }));
    on('prompt.submit', async (_$, e) => e);

    const result = await $.prompt.submit({ text: `ping ${REAL_HOST}` });
    expect(result.text).not.toContain(REAL_HOST);
    expect(result.text).toMatch(/HOST_[0-9a-f]{8}/);
  });

test('a subdirectory of a listed project still scrubs', { options: OPTIONS }, async ($, on) => {
    on('session.cwd', async () => ({ value: '/work/acme/backend/src' }));
    serveConfig(on, JSON.stringify({ ...BASE, projects: ['/work/acme'] }));
    on('prompt.submit', async (_$, e) => e);

    const result = await $.prompt.submit({ text: `ping ${REAL_HOST}` });
    expect(result.text).toMatch(/HOST_[0-9a-f]{8}/);
  });

test('a sibling project whose name merely starts the same does not scrub',
  { options: OPTIONS }, async ($, on) => {
    on('session.cwd', async () => ({ value: '/work/acme-old' }));
    serveConfig(on, JSON.stringify({ ...BASE, projects: ['/work/acme'] }));
    on('prompt.submit', async (_$, e) => e);

    const result = await $.prompt.submit({ text: `ping ${REAL_HOST}` });
    expect(result.text).toContain(REAL_HOST);
  });

/*
 * Collecting the key and the list from the local agent.
 *
 * This is the configuration-free path: nothing in the plugin options,
 * nothing on disk, and the mod still scrubs because the agent hands it
 * both over loopback. Worth testing through the engine rather than in
 * isolation, since what it depends on is the engine's own fs.read,
 * http.fetch and clock.
 */
function serveAgent(on: any, opts: { port?: number; answer?: any; hang?: boolean } = {}, logs?: string[]) {
  const port = opts.port ?? 8099;
  const token = 'bootstrap-token-for-the-test';

  on('ui.log', async (_$: any, e: any) => {
    if (logs) logs.push(String(e?.message ?? e?.text ?? JSON.stringify(e)));
    return { value: undefined };
  });

  /* The handshake lives under the home directory, so the mod has to be
   * able to find one. Served here rather than left to the machine, which
   * would make the test depend on who is running it. */
  on('env.get', async (_$: any, e: any) =>
    (e.name === 'HOME' ? { value: '/home/tester' } : { value: undefined }));

  /* Every mods API method is also an event, so an unanswered clock.sleep
   * REJECTS - which took the whole collection down with it until this was
   * served.
   *
   * Which arm of the race wins is the thing under test, so the wait is
   * driven rather than timed: it never finishes while the agent is
   * answering, and finishes at once when the agent is wedged. Using a
   * real duration here would make the test a race against the machine. */
  on('clock.sleep', async () =>
    (opts.hang ? { value: undefined } : await new Promise(() => {})));

  on('fs.read', async (_$: any, e: any) => {
    /* Separators normalised: the engine hands back a Windows path on
     * Windows, so matching only on "/" silently never fired and made
     * this read as "the mod did not ask". */
    if (String(e.path).split('\\').join('/').endsWith('.claudefuscator/agent.json')) {
      return { value: JSON.stringify({ port, token }) };
    }
    // Everything else missing: no plugin config, no list on disk.
    return { deny: 'not found' };
  });

  on('http.fetch', async (_$: any, e: any) => {
    if (!String(e.url).includes('/bootstrap')) return { deny: 'unexpected host' };
    // The init is its own field on the event, not spread onto it.
    if (e.init?.headers?.['x-claudefuscator-bootstrap'] !== token) {
      return { value: { ok: false, status: 403, headers: {}, text: '{}' } };
    }
    if (opts.hang) {
      // Never resolves, standing in for a wedged agent.
      return await new Promise(() => {});
    }
    return {
      value: {
        ok: true,
        status: 200,
        headers: {},
        text: JSON.stringify(opts.answer ?? { key: KEY, config: BASE }),
      },
    };
  });
}

test('with nothing configured, the key and list come from the agent',
  { options: {} }, async ($, on) => {
    const logs: string[] = [];
    serveAgent(on, {}, logs);
    on('prompt.submit', async (_$: any, e: any) => e);

    const result = await $.prompt.submit({ text: `why is ${REAL_HOST} down?` });

    // The whole point of the connect/enrol flow: this machine holds no
    // key and no list, and still nothing real leaves it.
    expect(result.text).not.toContain(REAL_HOST);
    expect(result.text).toMatch(/HOST_[0-9a-f]{8}/);

    // And it says where they came from, so somebody reading the status
    // can tell a machine running on collected configuration from one
    // running on its own - which otherwise look identical.
    expect(logs.join(' ')).toContain('config: the local agent');
  });

test('an agent that never answers does not hang the prompt',
  { options: {} }, async ($, on) => {
    serveAgent(on, { hang: true });
    on('prompt.submit', async (_$: any, e: any) => e);

    // $.http.fetch has no timeout of its own. Without the clock race this
    // prompt would never return, which costs the session rather than the
    // scrubbing - the worse of the two failures by a long way.
    const result = await $.prompt.submit({ text: `why is ${REAL_HOST} down?` });
    expect(result.text).toContain(REAL_HOST);
  });

test('a configured key is not displaced by the agent',
  { options: OPTIONS }, async ($, on) => {
    // The agent offers a DIFFERENT key. An explicit setting has to win, or
    // the box someone is looking at is lying to them.
    serveConfig(on);
    on('http.fetch', async () => ({
      value: {
        ok: true, status: 200, headers: {},
        text: JSON.stringify({ key: 'a-completely-different-key', config: BASE }),
      },
    }));
    on('prompt.submit', async (_$: any, e: any) => e);

    const withLocal = await $.prompt.submit({ text: REAL_HOST });
    expect(withLocal.text).toMatch(/^HOST_[0-9a-f]{8}$/);

    // Same token the other tests derive, proving the local key was used.
    const again = await $.prompt.submit({ text: `again: ${REAL_HOST}` });
    expect(again.text).toBe(`again: ${withLocal.text}`);
  });

/*
 * Credentials. Invented specimens: right prefix and length, random
 * body, nothing that authenticates anywhere.
 */
const FAKE_PAT = 'ghp_' + 'A'.repeat(36);

test('a credential in the prompt is reported and still sent',
  { options: OPTIONS }, async ($, on) => {
    const logs: string[] = [];
    on('ui.log', async (_$: any, e: any) => {
      logs.push(String(e?.message ?? JSON.stringify(e)));
      return { value: undefined };
    });
    on('fs.read', async (_$: any, e: any) =>
      (String(e.path).endsWith('test-config.json')
        ? { value: CONFIG } : { deny: 'not found' }));
    on('prompt.submit', async (_$: any, e: any) => e);

    const result = await $.prompt.submit({ text: 'deploy with ' + FAKE_PAT });

    // Warned, not tokenized. A token round-trips, and a credential
    // coming back is a new way to spill it.
    expect(logs.join(' ')).toContain('github-token');
    expect(result.text).toContain(FAKE_PAT);
  });

test('the warning never quotes the credential',
  { options: OPTIONS }, async ($, on) => {
    const logs: string[] = [];
    on('ui.log', async (_$: any, e: any) => {
      logs.push(String(e?.message ?? JSON.stringify(e)));
      return { value: undefined };
    });
    on('fs.read', async (_$: any, e: any) =>
      (String(e.path).endsWith('test-config.json')
        ? { value: CONFIG } : { deny: 'not found' }));
    on('prompt.submit', async (_$: any, e: any) => e);

    await $.prompt.submit({ text: 'deploy with ' + FAKE_PAT });

    // Warnings reach logs and scrollback. One that quoted the secret
    // would spread it further than staying quiet would have.
    expect(logs.join(' ')).not.toContain(FAKE_PAT);
  });

test('secretPolicy block stops the prompt', { options: OPTIONS },
  async ($, on) => {
    const blocking = JSON.stringify({ ...BASE, secretPolicy: 'block' });
    on('ui.log', async () => ({ value: undefined }));
    on('fs.read', async (_$: any, e: any) =>
      (String(e.path).endsWith('test-config.json')
        ? { value: blocking } : { deny: 'not found' }));

    let reached = false;
    on('prompt.submit', async (_$: any, e: any) => { reached = true; return e; });

    await $.prompt.submit({ text: 'deploy with ' + FAKE_PAT });

    // Nothing beneath the hook ran, so nothing was sent.
    expect(reached).toBe(false);
  });

test('a prompt with no credential is untouched by the policy',
  { options: OPTIONS }, async ($, on) => {
    serveConfig(on);
    on('prompt.submit', async (_$: any, e: any) => e);

    const result = await $.prompt.submit({ text: 'what time is it' });
    expect(result.text).toBe('what time is it');
  });
