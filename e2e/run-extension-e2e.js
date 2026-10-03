'use strict';
/*
 * Headless end-to-end test of the Chrome extension's restore side.
 *
 *   node e2e/run-extension-e2e.js            headless (default)
 *   node e2e/run-extension-e2e.js --headed   watch it run
 *
 * WHICH BROWSER, AND WHY IT MATTERS
 * ---------------------------------
 * Chrome 153 no longer honours --load-extension, so an installed Chrome
 * cannot be driven this way (confirmed on this machine: the content script
 * never injects, headless or headed, with or without
 * --disable-features=DisableLoadExtensionCommandLineSwitch). This runs against
 * Playwright's bundled Chromium, which still supports it. Same engine, but it
 * is NOT the browser you browse with - the manual checks in
 * chrome-extension/TESTING.md remain the only thing that exercises your real
 * Chrome.
 *
 * WHAT IS REAL AND WHAT IS A HARNESS
 * ----------------------------------
 * Real: content.js, claudefuscator-core.js, the manifest's all_frames and
 *       match_origin_as_fallback settings, chrome.storage.local.
 * Harness: a temp copy of the extension with (a) 127.0.0.1 added to the match
 *       patterns, since the fixture is not served from claude.ai, and (b) a
 *       seed script that writes the key and identifier list into storage,
 *       standing in for someone filling in the options page.
 * Nothing in content.js or the core is modified or stubbed.
 */

const { chromium } = require('playwright');
const http = require('node:http');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

const core = require('../shared/claudefuscator-core.js');

const ROOT = path.join(__dirname, '..');
const EXT_SRC = path.join(ROOT, 'chrome-extension');
const FIXTURE = path.join(__dirname, 'fixture', 'claude-like.html');
const HEADED = process.argv.includes('--headed');

const KEY = 'e2e-extension-test-key';
const CONFIG = {
  tokenLength: 8,
  internalDomains: ['corp.example'],
  identifiers: [
    { type: 'PERSON', value: 'Jane Example', aliases: ['J. Example'] },
    { type: 'HOST', value: 'build-01.corp.example' },
  ],
};
const REAL_HOST = 'build-01.corp.example';
const REAL_PERSON = 'Jane Example';

/* Chromium's own binary, located the way Playwright does. */
function chromiumPath() {
  const base = path.join(os.homedir(), 'AppData', 'Local', 'ms-playwright');
  if (!fs.existsSync(base)) return null;
  const dirs = fs.readdirSync(base).filter((d) => d.startsWith('chromium-')).sort();
  for (const d of dirs.reverse()) {
    for (const sub of ['chrome-win64', 'chrome-win', 'chrome-linux']) {
      for (const exe of ['chrome.exe', 'chrome']) {
        const p = path.join(base, d, sub, exe);
        if (fs.existsSync(p)) return p;
      }
    }
  }
  return null;
}

function buildTestExtension(tokens, agentOrigin) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-e2e-ext-'));
  for (const f of fs.readdirSync(EXT_SRC)) {
    const src = path.join(EXT_SRC, f);
    if (fs.statSync(src).isFile()) fs.copyFileSync(src, path.join(dir, f));
  }

  /* Stands in for the options page. Runs at document_start; content.js reads
   * storage at document_idle, and its storage.onChanged listener covers the
   * case where this has not landed yet. */
  const config = agentOrigin ? { ...CONFIG, agent: { url: agentOrigin } } : CONFIG;
  fs.writeFileSync(path.join(dir, 'e2e-seed.js'),
    'chrome.storage.local.set(' +
    JSON.stringify({ key: KEY, config }) +
    ');\n');

  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const local = ['http://127.0.0.1/*', 'http://localhost/*'];
  manifest.content_scripts[0].matches.push(...local);
  manifest.content_scripts.unshift({
    matches: local,
    js: ['e2e-seed.js'],
    run_at: 'document_start',
    all_frames: false,
  });
  /* The fake agent gets an ephemeral port, so host_permissions and the CSP
   * - which pin 8091 in the shipped manifest - are retargeted at it. This
   * is the harness widening its own reach, not the extension's: what is
   * under test is that the extension reaches ONLY what its manifest allows,
   * and that set is still exactly one loopback origin. */
  if (agentOrigin) {
    manifest.host_permissions = [agentOrigin + '/*'];
    manifest.content_security_policy.extension_pages =
      "script-src 'self'; object-src 'self'; connect-src 'self' " + agentOrigin;
  }
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  return dir;
}

/* A stand-in for the local agent: same route, same auth header, same reply
 * shape. It also serves one POISONED mapping, to prove the extension checks
 * what it is told rather than trusting it. */
function serveAgent({ auth, good, poisoned }) {
  const seen = { authHeaders: [], asked: [] };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.authHeaders.push(req.headers['x-claudefuscator-auth'] || null);
      if (req.headers['x-claudefuscator-auth'] !== auth) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end('{"error":"bad auth"}');
        return;
      }
      let tokens = [];
      try { tokens = JSON.parse(body).tokens || []; } catch (_) { /* ignore */ }
      seen.asked.push(...tokens);
      const mappings = {};
      for (const t of tokens) {
        if (good[t]) mappings[t] = good[t];
        if (poisoned[t]) mappings[t] = poisoned[t];
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ mappings, unresolved: [] }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () =>
      resolve({ server, origin: `http://127.0.0.1:${server.address().port}`, seen }));
  });
}

function serveFixture(tokens) {
  let html = fs.readFileSync(FIXTURE, 'utf8');
  for (const [name, value] of Object.entries(tokens)) {
    html = html.split('{{' + name + '}}').join(value);
  }
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () =>
      resolve({ server, origin: `http://127.0.0.1:${server.address().port}` }));
  });
}

/* ---- tiny assertion harness ------------------------------------------ */

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log((ok ? '  PASS  ' : '  FAIL  ') + name + (ok || !detail ? '' : '\n          ' + detail));
}

async function main() {
  const exe = chromiumPath();
  if (!exe) {
    console.error('No Playwright Chromium found. Run: npx playwright install chromium');
    process.exit(2);
  }
  console.log('browser:', exe);

  const vault = await core.buildVault(KEY, CONFIG);
  const tokens = {
    HOST_TOKEN: (await core.scrub(REAL_HOST, vault)).text,
    PERSON_TOKEN: (await core.scrub(REAL_PERSON, vault)).text,
  };
  console.log('tokens :', tokens.HOST_TOKEN, tokens.PERSON_TOKEN);

  /* An IP is a PATTERN hit: nothing in CONFIG derives it, so the extension
   * cannot resolve it on its own. That is exactly the case the agent
   * exists for, and the case that otherwise shows up red. */
  const REAL_IP = '10.44.2.9';
  const IP_TOKEN = await core.deriveToken(KEY, 'IP', REAL_IP, 8);
  /* A token whose value does NOT hash back to it. A correct client must
   * refuse this one however confidently the agent asserts it. */
  const POISON_TOKEN = await core.deriveToken(KEY, 'IP', '10.99.99.99', 8);
  tokens.IP_TOKEN = IP_TOKEN;
  tokens.POISON_TOKEN = POISON_TOKEN;

  const agentAuth = (await core.hmacHex(KEY, 'claudefuscator/mappings/v1')).slice(0, 32);
  const agent = await serveAgent({
    auth: agentAuth,
    good: { [IP_TOKEN]: REAL_IP },
    poisoned: { [POISON_TOKEN]: 'attacker.example' },
  });
  console.log('agent  :', agent.origin);

  const extDir = buildTestExtension(tokens, agent.origin);
  const { server, origin } = await serveFixture(tokens);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cf-e2e-prof-'));

  const args = [
    `--disable-extensions-except=${extDir}`,
    `--load-extension=${extDir}`,
    '--no-first-run',
    '--no-default-browser-check',
  ];
  if (!HEADED) args.push('--headless=new');

  const ctx = await chromium.launchPersistentContext(profile, {
    executablePath: exe,
    headless: false,            // we pass --headless=new ourselves
    args,
  });

  /* Record every request the browser makes, to back the zero-network claim
   * with observed behaviour rather than a source grep. */
  const external = [];
  const toAgent = [];
  ctx.on('request', (req) => {
    const url = req.url();
    if (url.startsWith(origin) || url.startsWith('data:') || url.startsWith('about:')
        || url.startsWith('chrome-extension://') || url.startsWith('blob:')) return;
    if (url.startsWith(agent.origin)) { toAgent.push(url); return; }
    external.push(url);
  });

  try {
    const page = await ctx.newPage();
    await page.goto(origin + '/', { waitUntil: 'load' });
    await page.waitForTimeout(1200);   // storage seed + first restore pass

    const text = (sel) => page.locator(sel).innerText();

    /* 1. assistant text restored */
    const msg = await text('#msg-1');
    check('assistant text: tokens restored to real values',
      msg.includes(REAL_HOST) && msg.includes(REAL_PERSON) && !msg.includes('HOST_'),
      'got: ' + msg);

    /* 2. lookalikes untouched */
    const look = await text('#lookalike');
    check('token-shaped text is not rewritten',
      look.includes('MAX_deadbeef') && look.includes('HOST_zzzzzzzz') && look.includes('PERSON_00000000'),
      'got: ' + look);

    /* 3. editable surfaces untouched - the safety-critical one */
    const composer = await text('#composer');
    check('contenteditable composer is NOT rewritten',
      composer.includes(tokens.HOST_TOKEN) && !composer.includes(REAL_HOST),
      'got: ' + composer);

    const ta = await page.locator('#ta').inputValue();
    check('textarea is NOT rewritten', ta.includes(tokens.HOST_TOKEN) && !ta.includes(REAL_HOST),
      'got: ' + ta);

    const inp = await page.locator('#inp').inputValue();
    check('input value is NOT rewritten', inp.includes(tokens.HOST_TOKEN) && !inp.includes(REAL_HOST),
      'got: ' + inp);

    const rolebox = await text('#rolebox');
    check('role=textbox is NOT rewritten',
      rolebox.includes(tokens.PERSON_TOKEN) && !rolebox.includes(REAL_PERSON),
      'got: ' + rolebox);

    const deep = await text('#deep');
    check('node nested deep inside a contenteditable is NOT rewritten',
      deep.includes(tokens.HOST_TOKEN) && !deep.includes(REAL_HOST),
      'got: ' + deep);

    /* 4. streaming: appended node */
    await page.evaluate((t) => window.__cfStreamAppend('later: ' + t), tokens.HOST_TOKEN);
    await page.waitForTimeout(400);
    const streamed = await text('#stream');
    check('streamed (appended) text is restored',
      streamed.includes(REAL_HOST) && !streamed.includes('HOST_'),
      'got: ' + streamed);

    /* 5. streaming: characterData mutation on an existing node */
    await page.evaluate((t) => window.__cfStreamMutate('mutated: ' + t), tokens.PERSON_TOKEN);
    await page.waitForTimeout(400);
    const mutated = await text('#stream');
    check('characterData mutation is restored',
      mutated.includes(REAL_PERSON) && !mutated.includes('PERSON_'),
      'got: ' + mutated);

    /* 6. artifact in a sandboxed, opaque-origin iframe */
    const frame = page.frames().find((f) => f !== page.mainFrame());
    if (!frame) {
      check('artifact iframe is reachable', false, 'no child frame found');
    } else {
      const art = await frame.locator('#art').innerText();
      check('artifact iframe (opaque origin) content is restored',
        art.includes(REAL_HOST) && !art.includes('HOST_'),
        'got: ' + art);

      /* 7. artifact updated in place, the dynamic-update case */
      await page.evaluate((t) => window.__cfArtifact('mutate', 'Updated target: ' + t), tokens.PERSON_TOKEN);
      await page.waitForTimeout(500);
      const art2 = await frame.locator('#art').innerText();
      check('artifact update in place is restored',
        art2.includes(REAL_PERSON) && !art2.includes('PERSON_'),
        'got: ' + art2);

      await page.evaluate((t) => window.__cfArtifact('append', 'appended ' + t), tokens.HOST_TOKEN);
      await page.waitForTimeout(500);
      const art3 = await frame.locator('#artstream').innerText();
      check('artifact appended content is restored',
        art3.includes(REAL_HOST) && !art3.includes('HOST_'),
        'got: ' + art3);
    }

    /* 8. the highlight stylesheet is injected, with both rules.
     * The painted ranges themselves live in CSS.highlights, which is not
     * observable from the page's own world, so the visual check stays
     * manual - see chrome-extension/TESTING.md. */
    const styleText = await page.evaluate(() => {
      const el = document.getElementById('claudefuscator-style');
      return el ? el.textContent : null;
    });
    check('highlight stylesheet is injected',
      !!styleText && styleText.includes('::highlight(claudefuscator-unveiled)'),
      'got: ' + String(styleText).slice(0, 120));
    check('unresolvable tokens have their own rule',
      !!styleText && styleText.includes('::highlight(claudefuscator-unknown)'),
      'got: ' + String(styleText).slice(0, 160));

    /* 9. the local agent.
     * Give the debounced ask, the round trip and the rescan time to land. */
    await page.waitForTimeout(1500);

    const fromPattern = await text('#frompattern');
    check('a token only the agent knows is resolved and shown',
      fromPattern.includes(REAL_IP) && !fromPattern.includes(IP_TOKEN),
      'got: ' + fromPattern);

    /* The one that matters most. The agent asserted a value for this token;
     * re-deriving the token from that value does not reproduce it, so the
     * extension must refuse it rather than display it. */
    const poisoned = await text('#poisoned');
    check('a value the key does not vouch for is REFUSED, not displayed',
      poisoned.includes(POISON_TOKEN) && !poisoned.includes('attacker.example'),
      'got: ' + poisoned);

    check('the agent was asked only about tokens it could not resolve locally',
      agent.seen.asked.length > 0
        && !agent.seen.asked.includes(tokens.HOST_TOKEN)
        && !agent.seen.asked.includes(tokens.PERSON_TOKEN),
      'asked: ' + agent.seen.asked.join(', '));

    check('every request to the agent carried the proof-of-key header',
      agent.seen.authHeaders.length > 0
        && agent.seen.authHeaders.every((h) => h === agentAuth),
      'saw: ' + agent.seen.authHeaders.join(', '));

    /* 10. the extension's reach.
     * This replaces the old "zero network calls" check. The property is no
     * longer that it calls nothing - resolving values it cannot derive
     * means asking something - but that the ONLY host it ever contacts is
     * the loopback agent its manifest names. */
    check('the agent is the only host the extension contacted',
      external.length === 0 && toAgent.length > 0,
      'external: ' + external.join(', ') + ' | agent: ' + toAgent.length);

    check('the key was never sent to the agent',
      !JSON.stringify(agent.seen).includes(KEY));
  } finally {
    await ctx.close();
    server.close();
    agent.server.close();
    fs.rmSync(profile, { recursive: true, force: true });
    fs.rmSync(extDir, { recursive: true, force: true });
  }

  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  if (failed.length) process.exit(1);
}

main().catch((err) => { console.error(err); process.exit(1); });
