'use strict';
/*
 * Claudefuscator content script - the restore side.
 *
 * Reads the key and identifier list from chrome.storage.local, rebuilds the
 * same token table the plugin built, and swaps tokens for real values in the
 * page. Nothing leaves this machine: there is no fetch, no XHR, no WebSocket,
 * no sendMessage to a server, and the extension holds no network permission.
 *
 * Two hard rules in here, both load-bearing:
 *
 *  1. NEVER touch an editable region. Restoring a token inside the composer
 *     would put the real value into the box you are about to send - the exact
 *     opposite of the point. See EDITABLE_SKIP.
 *
 *  2. Re-entrancy. Our own writes trigger the MutationObserver that watches
 *     for them, so writes are flagged and self-triggered records dropped.
 *
 * Artifacts stream and re-render continuously, and React owns the DOM, so a
 * one-shot pass is not enough: replacement has to be idempotent and re-applied
 * on every mutation, including characterData changes on existing text nodes.
 */

(function () {
  const core = globalThis.ClaudefuscatorCore;
  if (!core) return;

  /* Never descend into these. The first four are editable surfaces; the rest
   * would either corrupt page behaviour or are invisible anyway. */
  const SKIP_TAGS = new Set([
    'TEXTAREA', 'INPUT', 'SELECT', 'OPTION',
    'SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'CODE-INPUT',
  ]);

  function isEditable(el) {
    /* isContentEditable covers the ProseMirror/Lexical composer claude.ai uses
     * and any nested editable node. */
    return el.isContentEditable === true
      || el.getAttribute('contenteditable') === 'true'
      || el.getAttribute('role') === 'textbox';
  }

  function shouldSkip(el) {
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;
    if (SKIP_TAGS.has(el.tagName)) return true;
    if (isEditable(el)) return true;
    if (el.hasAttribute && el.hasAttribute('data-claudefuscator-skip')) return true;
    return false;
  }

  /* Walk up as well as down: a text node deep inside the composer must be
   * skipped even when the mutation record points straight at it. */
  function inSkippedSubtree(node) {
    for (let el = node.parentElement; el; el = el.parentElement) {
      if (shouldSkip(el)) return true;
    }
    return false;
  }

  let vault = null;
  /* Kept beside the vault so an agent's answer can be checked against the
   * key before it is believed. See verifyMappings. */
  let secret = null;
  let writing = false;   // re-entrancy flag
  let scheduled = false;
  const pending = new Set();

  /* Highlighting uses the CSS Custom Highlight API rather than wrapping
   * restored text in a <span>. Wrapping would change the DOM structure under
   * React, which fights back and re-renders; a Highlight is painted from
   * Range objects and touches no nodes at all. Where the API is missing the
   * restore still happens, just unmarked. */
  const HIGHLIGHT = 'claudefuscator-unveiled';
  const UNKNOWN = 'claudefuscator-unknown';
  const canHighlight = typeof CSS !== 'undefined' && CSS.highlights && typeof Highlight === 'function';
  let highlightOn = true;
  let ranges = [];
  let unknownRanges = [];

  /* Token shape, for FLAGGING only - never for restoring. Restoring by shape
   * would rewrite text we did not generate; marking it just says "this looks
   * like a token and I cannot resolve it", which is exactly what you want to
   * know when your list is out of date.
   *
   * Narrowed to type prefixes this config actually knows, so ordinary code
   * like MAX_deadbeef (which does match the raw shape - 'deadbeef' is eight
   * hex characters) is not painted red. */
  let knownTypes = null;
  let tokenShapeRe = null;

  function buildShapeMatcher() {
    knownTypes = new Set(['EMAIL', 'IP', 'MAC', 'HOST']);   // the built-in patterns
    for (const token of vault.tokenToValue.keys()) knownTypes.add(token.split('_')[0]);
    for (const token of vault.discovered.keys()) knownTypes.add(token.split('_')[0]);
    const alt = Array.from(knownTypes).sort().join('|');
    tokenShapeRe = new RegExp('(?<![A-Za-z0-9_])(?:' + alt + ')_[0-9a-f]{8}(?![A-Za-z0-9_])', 'g');
  }

  function styleOnce() {
    if (!canHighlight || document.getElementById('claudefuscator-style')) return;
    const el = document.createElement('style');
    el.id = 'claudefuscator-style';
    /* ::highlight() accepts only a few properties. Keep it subtle: a wash
     * behind the text and a dotted underline, both from currentColor so it
     * reads the same in either theme. */
    el.textContent = '::highlight(' + HIGHLIGHT + ') {'
      + ' background-color: color-mix(in srgb, currentColor 11%, transparent);'
      + ' text-decoration: underline dotted;'
      + ' text-underline-offset: 2px;'
      + ' }'
      /* Red, and only a tint plus a wavy underline, so it reads as "look at
       * this" without shouting over the text. A token left in red is one the
       * extension has no value for: usually a pattern hit, or a list entry
       * added on the Claude Code side but not here yet. */
      + '::highlight(' + UNKNOWN + ') {'
      + ' background-color: color-mix(in srgb, #d6453c 18%, transparent);'
      + ' text-decoration: underline wavy #d6453c;'
      + ' text-underline-offset: 2px;'
      + ' }';
    (document.head || document.documentElement).appendChild(el);
  }

  function paint() {
    if (!canHighlight) return;
    if (!highlightOn) {
      CSS.highlights.delete(HIGHLIGHT);
      CSS.highlights.delete(UNKNOWN);
      return;
    }
    const live = (list) => list.filter((r) => r.startContainer && r.startContainer.isConnected);
    ranges = live(ranges);
    unknownRanges = live(unknownRanges);
    if (ranges.length) CSS.highlights.set(HIGHLIGHT, new Highlight(...ranges));
    else CSS.highlights.delete(HIGHLIGHT);
    if (unknownRanges.length) CSS.highlights.set(UNKNOWN, new Highlight(...unknownRanges));
    else CSS.highlights.delete(UNKNOWN);
  }

  function replaceInTextNode(node) {
    if (!node.data || node.data.indexOf('_') === -1) return; // cheap prefilter
    if (inSkippedSubtree(node)) return;
    const r = core.restoreSpans(node.data, vault);
    if (!r.changed) { markNode(node, []); return; }
    writing = true;
    try {
      node.data = r.text;
    } finally {
      writing = false;
    }
    markNode(node, r.spans);
  }

  /* Record what we unveiled here, and what still looks like a token. */
  function markNode(node, spans) {
    if (!canHighlight) return;
    /* Drop stale ranges for this node before adding new ones, or a re-render
     * accumulates duplicates over the same text. */
    ranges = ranges.filter((range) => range.startContainer !== node);
    unknownRanges = unknownRanges.filter((range) => range.startContainer !== node);

    for (const span of spans || []) {
      const range = new Range();
      try {
        range.setStart(node, span.start);
        range.setEnd(node, span.end);
        ranges.push(range);
      } catch (_) { /* node changed under us; the next pass redraws it */ }
    }

    if (!tokenShapeRe) return;
    tokenShapeRe.lastIndex = 0;
    let m;
    while ((m = tokenShapeRe.exec(node.data)) !== null) {
      const range = new Range();
      try {
        range.setStart(node, m.index);
        range.setEnd(node, m.index + m[0].length);
        unknownRanges.push(range);
      } catch (_) { /* same */ }
      noteUnresolved(m[0]);
    }
  }

  /* ---- the local agent ------------------------------------------------
   *
   * A token this page shows that the vault cannot resolve is, almost
   * always, a PATTERN hit from somewhere else: an IP, a MAC, an internal
   * hostname that was never on anybody's list. Nothing in this extension's
   * own config derives it, which is why it gets marked red.
   *
   * The local agent is the one place that does know, because the mod and
   * the proxy hand it what they discover. This asks it - through the
   * background worker, which is the only part that touches the network.
   *
   * EVERY ANSWER IS VERIFIED BEFORE IT IS SHOWN. The agent is not trusted
   * to be right: a returned value is accepted only if re-deriving the token
   * from it under our own key reproduces the token exactly. That is what
   * keeps a wrong or hostile answer from putting a value on screen that the
   * key does not vouch for, and it is the same check the shared vault
   * design depends on.
   */
  const unresolved = new Set();   // seen on the page, no value yet
  const asked = new Set();        // already put to the agent, right or wrong
  let askTimer = null;
  let asking = false;

  function noteUnresolved(token) {
    if (!secret || asked.has(token) || unresolved.has(token)) return;
    unresolved.add(token);
    if (askTimer) return;
    /* Coalesce: a streaming answer paints the same unknown token dozens of
     * times a second, and each would otherwise be its own round trip. */
    askTimer = setTimeout(() => { askTimer = null; askAgent(); }, 400);
  }

  async function askAgent() {
    if (asking || !vault || !secret || !unresolved.size) return;
    const batch = Array.from(unresolved);
    unresolved.clear();
    for (const t of batch) asked.add(t);

    asking = true;
    let reply = null;
    try {
      reply = await chrome.runtime.sendMessage({
        type: 'claudefuscator-resolve', tokens: batch,
      });
    } catch (_) {
      /* No worker, or the extension was reloaded under us. Leave them red. */
    } finally {
      asking = false;
    }

    const mappings = (reply && reply.mappings) || {};
    const accepted = await verifyMappings(mappings);
    if (!accepted.length) return;

    for (const [token, value] of accepted) vault.discovered.set(token, value);
    core.rebuildRestore(vault);
    /* Rescan so the values that just became known replace their tokens and
     * lose the red marking. */
    scanSubtree(document.body);
    paint();
  }

  /* Re-derive each token from the value we were handed. Only an exact match
   * is accepted; anything else is discarded silently and stays red, which
   * is the honest display for a value we cannot vouch for. */
  async function verifyMappings(mappings) {
    const out = [];
    for (const token of Object.keys(mappings)) {
      const value = mappings[token];
      if (typeof value !== 'string' || !value) continue;
      const type = token.slice(0, token.indexOf('_'));
      if (!type) continue;
      let expected = null;
      try {
        expected = await core.deriveToken(secret, type, value, vault.tokenLength);
      } catch (_) { continue; }
      if (expected === token) out.push([token, value]);
    }
    return out;
  }

  function scanSubtree(root) {
    if (!root) return;
    if (root.nodeType === Node.TEXT_NODE) return replaceInTextNode(root);
    if (root.nodeType !== Node.ELEMENT_NODE && root.nodeType !== Node.DOCUMENT_FRAGMENT_NODE) return;
    if (shouldSkip(root)) return;

    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (!node.data || node.data.indexOf('_') === -1) return NodeFilter.FILTER_REJECT;
        if (inSkippedSubtree(node)) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });

    const targets = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) targets.push(n);
    for (const n of targets) replaceInTextNode(n);
  }

  /* Coalesce bursts of streaming mutations into one pass per frame. Without
   * this, a streaming artifact fires thousands of records a second. */
  function flush() {
    scheduled = false;
    const roots = Array.from(pending);
    pending.clear();
    for (const root of roots) {
      if (root.isConnected === false) continue;
      scanSubtree(root);
    }
    paint();
  }

  function schedule(root) {
    pending.add(root);
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(flush);
  }

  function onMutations(records) {
    if (writing) return; // our own edit
    for (const rec of records) {
      if (rec.type === 'characterData') {
        /* Streaming text: the node already exists and only its data changed. */
        schedule(rec.target);
      } else {
        for (const added of rec.addedNodes) schedule(added);
      }
    }
  }

  let started = false;

  function start() {
    if (started) return;
    started = true;
    styleOnce();
    scanSubtree(document.body || document.documentElement);
    paint();
    const observer = new MutationObserver(onMutations);
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    /* Same-origin iframes (and opaque-origin frames reached via
     * match_origin_as_fallback) get their own content script instance, so
     * nothing extra is needed for those. This only covers a frame that became
     * reachable after load. */
    window.addEventListener('load', () => scanSubtree(document.body), { once: true });
  }

  /* Re-read config when you change it in the options page, so you do not have
   * to reload claude.ai. storage.onChanged is local, not a network event. */
  function watchConfig() {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;

      /* The worker collected a key or a list. What it collected lives in
       * storage.session, which a content script cannot see - only this
       * timestamp crosses, and it is enough to know to ask again. */
      if (changes.collectedAt) {
        init().then((ready) => {
          if (!ready) return;
          start();
          scanSubtree(document.body);
        }).catch(() => {});
        return;
      }
      if (changes.highlight && !changes.key && !changes.config) {
        highlightOn = changes.highlight.newValue !== false;
        paint();
        return;
      }
      if (!changes.key && !changes.config) return;
      init()
        .then((ready) => {
          /* First successful config after a cold start still needs the
           * observer attached, not just a one-off rescan. */
          if (ready) start();
          if (ready) scanSubtree(document.body);
        })
        .catch(() => {});
    });
  }

  /* Asks the worker for something, tolerating the worker being asleep or
   * gone. A failed ask must leave the page inert, never half-configured. */
  async function askWorker(type) {
    try {
      return await chrome.runtime.sendMessage({ type });
    } catch (_) {
      return null;
    }
  }

  async function init() {
    const stored = await chrome.storage.local.get(['key', 'config', 'highlight']);
    /* Default on: seeing what was unveiled is the point of the toggle, and a
     * setting nobody has touched yet should show more, not less. */
    highlightOn = stored.highlight !== false;

    /* In vault mode nothing is typed into this profile: the worker holds
     * the key for the browser session, having collected it once. Asking it
     * is the only way the content script can see that key - it has no
     * network of its own and must not grow one. */
    let key = stored.key;
    if (!key) {
      const held = await askWorker('claudefuscator-key');
      key = held && held.key;
    }
    if (!key) { vault = null; secret = null; return false; }

    let cfg = stored.config;
    if (typeof cfg === 'string') {
      try { cfg = JSON.parse(cfg); } catch (_) { cfg = null; }
    }

    /* The published list wins over the local one where both exist, because
     * the point of publishing is that everybody hides the same things. What
     * does NOT come from the vault is where this extension may connect:
     * that stays local config, and ultimately the manifest, so a server can
     * never talk a browser into sending real values somewhere new. */
    const shared = await askWorker('claudefuscator-rules');
    if (shared && shared.rules) {
      cfg = Object.assign({}, cfg || {}, shared.rules,
                          { agent: (cfg || {}).agent, vault: (cfg || {}).vault });
    }

    if (!cfg) { vault = null; secret = null; return false; }
    try {
      vault = await core.buildVault(key, cfg);
      secret = key;
      buildShapeMatcher();
      /* A new key or list changes what is derivable, so questions already
       * put to the agent under the old one should be asked again. */
      unresolved.clear();
      asked.clear();
    } catch (_) {
      /* Collision or bad config: stay inert rather than restore ambiguously. */
      vault = null;
      secret = null;
      return false;
    }
    return true;
  }

  /* Alt+Shift+H toggles the marking. Handled here rather than through
   * chrome.commands, which would mean declaring a `commands` section and a
   * user-visible shortcut; the worker that now exists is a transport for
   * the agent and nothing else. The choice is persisted, so it carries to
   * other tabs and to the next session. */
  function bindShortcut() {
    window.addEventListener('keydown', (e) => {
      if (!e.altKey || !e.shiftKey) return;
      if ((e.key || '').toLowerCase() !== 'h') return;
      const target = e.target;
      if (target && target.nodeType === Node.ELEMENT_NODE && shouldSkip(target)) return;
      e.preventDefault();
      highlightOn = !highlightOn;
      paint();
      try { chrome.storage.local.set({ highlight: highlightOn }); } catch (_) { /* best effort */ }
    }, true);
  }

  init()
    .then((ready) => {
      watchConfig();
      bindShortcut();
      if (ready) start();
    })
    .catch(() => { /* stay inert */ });
})();
