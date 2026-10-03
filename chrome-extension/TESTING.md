# Verifying the extension

The central claim is that the extension reaches **exactly one host, the
loopback agent, and nothing else**. (It used to be "zero network calls";
that ended when the agent client landed, because resolving values the
extension cannot derive means asking something.) Below are three
independent ways to check it — static, permission-level, and runtime —
plus checks for the two things most likely to go wrong in practice.

> The extension is not installed anywhere yet. Load it unpacked in a
> **separate Chrome profile** the first time.

---

## Check 1 — static: the only network API is one `fetch`, in the worker

```bash
cd chrome-extension
NET='fetch\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|navigator\.connect|importScripts|new Worker|connectNative'

# The content script and the options page must still be completely clean.
grep -rnE "$NET" content.js options.js options.html | grep -vE ':[0-9]+: *(\*|//|/\*)'
```

**Expect no output.** The page-facing half reaches the network by no route
at all; it asks the worker over `chrome.runtime.sendMessage`.

```bash
# The worker is allowed exactly one, and it must be the agent call.
grep -rnE "$NET" background.js | grep -vE ':[0-9]+: *(\*|//|/\*)'
```

**Expect exactly one line**, the `fetch(url + '/resolve', …)` in `resolve()`.
More than one, or one anywhere else, is a regression.

The second `grep -v` drops comment lines. It is needed because the source
*comments* name these APIs when explaining their absence — without the filter
the check reports its own documentation as a hit. Drop the filter if you want
to eyeball those lines and confirm they really are comments.

```bash
# No remote resources referenced from the options page either.
grep -rnE "https?://|//cdn|@import" *.html *.css
```

**Expect no output.** All CSS and JS are local files; there are no web fonts,
no CDN scripts, no remote images.

```bash
# No storage.sync — that would upload the key to a Google account.
grep -rn "storage\.sync" *.js | grep -vE ':[0-9]+: *(\*|//|/\*)'   # expect no output
grep -rc "storage\.local" *.js                                      # expect nonzero in
                                                                    # content.js + options.js
```

---

## Check 2 — permissions: it has no capability to reach the network

```bash
cat manifest.json
```

Confirm all of the following:

| Field | Required value | Why |
| --- | --- | --- |
| `permissions` | `["storage"]` and nothing else | no `tabs`, `scripting`, `webRequest`, `nativeMessaging` |
| `host_permissions` | **absent** | `content_scripts.matches` grants DOM access only; `host_permissions` would grant cross-origin `fetch` |
| `background` | **absent** | no service worker, so no code runs outside a page |
| `externally_connectable` | **absent** | no other site can message it |
| `content_security_policy.extension_pages` | includes `connect-src 'none'` | the browser itself blocks any connection attempt from the options page |

A content script's `fetch` is subject to the *page's* CSP, and with no
`host_permissions` it cannot make cross-origin requests at all. Combined with
check 1, there is no code path and no capability.

---

## Check 3 — runtime: watch it make no requests

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** →
   select `chrome-extension/`.
2. Open the options page, enter a test key and list, **Save**.
3. On the extension card, note there is **no "service worker" link** — nothing
   runs in the background.
4. Open `claude.ai`, then DevTools → **Network** tab.
   - Filter the request list by the extension's ID (visible on the card).
   - Have a conversation containing tokens, let an artifact render and update.
   - **Expect zero requests attributable to the extension.**
5. Cross-check with the browser-wide view: open `chrome://net-export`, click
   **Start Logging to Disk**, exercise the extension, stop, and search the
   resulting JSON for the extension ID.

```bash
# Optional belt-and-braces: cut the machine off entirely and confirm restore
# still works. If it needed the network, it would fail here.
#   1. Load a claude.ai conversation containing tokens
#   2. DevTools -> Network -> set throttling to "Offline"
#   3. Reload is not possible offline, so instead: edit the identifier list in
#      the options page while offline and watch the open tab update.
```

Step 5's offline test is the strongest of the three: the restore path is pure
local computation, so it works with the network disconnected.

---

## Check 4 — the composer is never rewritten

This is a safety control, not a cosmetic one. Restoring a token inside the
claude.ai input box would put the **real value** into the text you are about to
send — the precise opposite of the tool's purpose.

1. On claude.ai, type a **token** (e.g. `HOST_8090567a`) into the message
   composer. Do not send it.
2. **Expect it to stay a token.** If it turns into a real hostname, stop using
   the extension and fix `content.js`.
3. Repeat inside an artifact's code editor and in the conversation-title field.
4. Confirm the same token in the *conversation transcript* above **is**
   restored — that is the positive control proving the script is running.

The skip list in `content.js` covers `textarea`, `input`, `select`,
`isContentEditable`, `[contenteditable="true"]` and `[role="textbox"]`, and it
walks *up* the tree from each text node, so a node nested deep inside the
composer is skipped too.

---

## Check 5 — artifacts, including live updates

Artifacts render in a nested sandboxed iframe and re-render as they stream, so
a one-shot pass is not enough.

1. Ask Claude for an artifact whose content contains a token.
2. **Expect the token to be restored inside the rendered artifact**, and to
   stay restored while it streams and when it is updated in place.
3. Ask for an update to the same artifact and watch the changed region: it must
   restore too, not just the initial render.
4. Confirm the artifact's own code view behaves the same way.

If artifact content is **not** restored, the sandbox origin is the likely
cause:

```
DevTools -> Elements -> find the artifact <iframe> -> read its src
DevTools -> Console -> select the iframe in the context dropdown -> type: location.origin
```

`manifest.json` lists `https://*.claudeusercontent.com/*` alongside
`https://claude.ai/*`, with `all_frames: true` and
`match_origin_as_fallback: true` (the latter is what allows injection into a
frame whose origin is opaque/`null`). **That host is current behaviour, not a
documented guarantee.** If `location.origin` shows something else, add it to
`content_scripts[0].matches` and reload the extension.

---

## Check 6 — the stored data is local only

```
chrome://extensions -> Claudefuscator -> Inspect views: options.html
```

In that console:

```js
// What is actually stored, and where.
await chrome.storage.local.get(null);   // your key + identifier list
await chrome.storage.sync.get(null);    // must be {} — nothing synced
```

Then confirm removal works: click **Erase stored data** on the options page and
re-run both lines. `local` must come back `{}`.

Note honestly what this means: your **real identifier values are stored in this
Chrome profile** in plaintext, because one-way tokens can only be reversed by
recomputing over values you already hold. They are not synced and not
transmitted, but they are on disk in the profile directory. That is the
accepted cost of the short-readable-token scheme.

---

## Check 7 — no false restores

The extension must never rewrite text it did not tokenize.

1. Paste this into a conversation and send it:
   `const MAX_deadbeef = 1; PERSON_00000000 HOST_zzzzzzzz`
2. **Expect all three to stay exactly as typed.** Restore matches an exact set
   of known tokens, never a token *shape*, so unrelated `WORD_hex` text is
   untouched.
3. Change the key in the options page to a wrong value and reload a
   conversation containing real tokens. **Expect the tokens to stay tokens** —
   never to be mapped to some other value.

`npm test` covers both of these at the core level ("text that merely looks like
a token is never restored", "restore only substitutes tokens this vault
generated"); this repeats them end-to-end in the browser.
