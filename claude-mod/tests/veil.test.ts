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
