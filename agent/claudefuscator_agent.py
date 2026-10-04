"""Claudefuscator local agent.

One loopback service that the mod, the Chrome extension and the proxy all
resolve through. It holds the key, owns the mapping store, and is the only
component that will ever speak to the shared vault.

    mod   --+   x-claudefuscator-auth: HMAC(key, "claudefuscator/mappings/v1")[:32]
    ext   --+-> agent (127.0.0.1) --Entra + TLS--> shared vault
    proxy --+       holds key, does crypto

WHY A SEPARATE PROCESS RATHER THAN AN ENDPOINT ON THE PROXY

  - It works in mod-only mode, where there is no proxy.
  - One Entra client instead of three. The mod and the extension never
    authenticate to anything but loopback.
  - The mod's sandbox has no usable WebCrypto, so it cannot encrypt for the
    shared vault. It does not have to: the agent encrypts on its behalf.

WHAT IT DELIBERATELY DOES NOT DO

  - No bulk export. `/resolve` takes the tokens it is asked about and returns
    only those. A dump of the whole table is the thing an attacker wants, so
    it is not a route that exists.
  - No CORS headers, so a browser page cannot read a response even though it
    can send a request.
  - Binds loopback only. The shared vault is the thing that is reachable by
    other people, and it is reached by this process, not by the clients.

Run it from anywhere; unlike the proxy it reads no files relative to the
working directory.

    CLAUDEFUSCATOR_KEY=...  CLAUDEFUSCATOR_CONFIG=...  python claudefuscator_agent.py
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import secrets
import socket
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'proxy'))

import claudefuscator_core as core          # noqa: E402
import config_merge                         # noqa: E402
import credentials                          # noqa: E402
from vault_client import LOOPBACK_HOSTS, USER_AGENT, _OPENER, VaultClient  # noqa: E402

DEFAULT_PORT = 8091                         # 8090 is the proxy
AUTH_HEADER = 'x-claudefuscator-auth'
AUTH_LABEL = 'claudefuscator/mappings/v1'
MAX_BODY = 1 << 20                          # 1 MiB; a resolve is a list of tokens


class Store:
    """The mapping table, and the lock around it.

    `known` comes from the identifier list and is derivable by anyone holding
    the key. `discovered` is the part that is not: pattern hits whose real
    value nothing else recorded, which is exactly what the browser cannot
    work out for itself.
    """

    def __init__(self, key, config, path=None, shared=None):
        self.key = key
        self.vault = core.build_vault(key, config)
        self.path = pathlib.Path(path) if path else None
        # The shared vault, or None. Only this process ever talks to it.
        self.shared = shared
        self._lock = threading.Lock()
        self._load()

    # ---- persistence ---------------------------------------------------

    def _load(self):
        """Discovered values survive a restart, or the browser loses every
        pattern hit each time the agent is bounced."""
        if not self.path or not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            return                          # a corrupt cache is an empty one
        for token, value in (data.get('discovered') or {}).items():
            self.vault.discovered[token] = value
        self.vault._rebuild_restore()

    def _save(self):
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            body = json.dumps({
                'warning': 'Contains real identifier values in plaintext.',
                'tokenVersion': core.TOKEN_VERSION,
                'discovered': dict(self.vault.discovered),
            }, indent=2)
            # 0600 where the platform honours it; on Windows the file inherits
            # the profile ACL, which already restricts it to this user.
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(body)
        except OSError:
            pass                            # losing the cache must not stop the agent

    # ---- api -----------------------------------------------------------

    def auth_token(self):
        """Proof the caller holds the same key, without sending the key."""
        return core.hmac_hex(self.key, AUTH_LABEL)[:32]

    def resolve(self, tokens):
        out, missing = self._resolve_local(tokens)

        if not missing or self.shared is None:
            return out

        # Deliberately outside the lock. This is a network call to another
        # host; holding the mapping lock across it would stall every other
        # client of this agent for as long as the vault takes to answer, or
        # for the whole timeout when it is down.
        fetched = self.shared.resolve(missing)

        if fetched:
            with self._lock:
                for token, value in fetched.items():
                    # Local values win. A row from the vault must not be able
                    # to displace one this machine derived or discovered
                    # itself, which is the only mapping it has first-hand
                    # knowledge of.
                    if token in self.vault.token_to_value or token in self.vault.discovered:
                        continue
                    self.vault.discovered[token] = value
                    out[token] = value
                self.vault._rebuild_restore()
                self._save()

        return out

    def _resolve_local(self, tokens):
        """What this machine already knows, and what it does not."""
        with self._lock:
            out, missing = {}, []
            for token in tokens:
                if not isinstance(token, str):
                    continue
                if token in self.vault.token_to_value:
                    out[token] = self.vault.token_to_value[token]
                elif token in self.vault.discovered:
                    out[token] = self.vault.discovered[token]
                else:
                    missing.append(token)
            return out, missing

    def submit(self, entries):
        """Write-once per token.

        Under a correct client a token determines its value, so a conflict
        means a bug, a key mismatch, or an attempt to poison. Record it and
        keep the first value rather than letting the last writer win.
        """
        added, conflicts, accepted = 0, [], []
        with self._lock:
            for entry in entries:
                # A client sending junk must get a 200 with added: 0, not a
                # 500. Anything can POST here; robustness is part of the
                # interface.
                if not isinstance(entry, dict):
                    continue
                token = entry.get('token')
                value = entry.get('value')
                if not isinstance(token, str) or not isinstance(value, str):
                    continue
                existing = self.vault.token_to_value.get(token) or self.vault.discovered.get(token)
                if existing is not None:
                    if existing != value:
                        conflicts.append(token)
                    continue
                self.vault.discovered[token] = value
                accepted.append({'token': token, 'value': value})
                added += 1
            if added:
                self.vault._rebuild_restore()
                self._save()

        # Outside the lock, for the same reason resolve's fetch is. Best
        # effort: a value that fails to reach the vault is still resolvable
        # here, so the cost of a failed push is that colleagues see it red,
        # not that anything is lost.
        if added and self.shared is not None:
            self.shared.submit([(e['token'], e['value']) for e in accepted])

        return added, conflicts

    def counts(self):
        with self._lock:
            return len(self.vault.token_to_value), len(self.vault.discovered)


class Handler(BaseHTTPRequestHandler):
    store = None
    server_version = 'claudefuscator-agent'
    sys_version = ''                        # do not advertise the Python version

    def log_message(self, fmt, *args):
        # One line per request, without the resolved tokens.
        sys.stderr.write('%s - %s\n' % (self.address_string(), fmt % args))

    # ---- plumbing ------------------------------------------------------

    def _json(self, status, payload):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        # Deliberately no Access-Control-Allow-Origin: a page may send a
        # request but must never read the response.
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self):
        presented = self.headers.get(AUTH_HEADER) or ''
        return hmac.compare_digest(presented, Handler.store.auth_token())

    def _read_json(self):
        try:
            length = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            return None
        if length <= 0:
            return None
        if length > MAX_BODY:
            # Answer rather than hang up. Replying without draining the body
            # makes the client see a connection reset instead of the 400,
            # so drain a bounded amount and then close the connection rather
            # than reading a body we have already refused.
            remaining = min(length, MAX_BODY)
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
            self.close_connection = True
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    # ---- routes --------------------------------------------------------

    def do_GET(self):
        if self.path == '/healthz':
            known, discovered = Handler.store.counts()
            # No values here, and no auth needed: it says the agent is up and
            # how much it holds, never what.
            self._json(200, {
                'status': 'ok',
                'tokenVersion': core.TOKEN_VERSION,
                'known': known,
                'discovered': discovered,
            })
            return
        self._json(404, {'error': 'not found'})

    def do_POST(self):
        if self.path not in ('/resolve', '/mappings'):
            self._json(404, {'error': 'not found'})
            return

        if not self._authorised():
            self._json(403, {'error': 'bad or missing ' + AUTH_HEADER})
            return

        payload = self._read_json()
        if payload is None:
            self._json(400, {'error': 'body must be JSON and under 1 MiB'})
            return

        if self.path == '/resolve':
            tokens = payload.get('tokens')
            if not isinstance(tokens, list):
                self._json(400, {'error': 'expected {"tokens": [...]}'})
                return
            mappings = Handler.store.resolve(tokens)
            self._json(200, {
                'mappings': mappings,
                'unresolved': [t for t in tokens if isinstance(t, str) and t not in mappings],
            })
            return

        entries = payload.get('mappings')
        if not isinstance(entries, list):
            self._json(400, {'error': 'expected {"mappings": [{token, value}, ...]}'})
            return
        added, conflicts = Handler.store.submit(entries)
        self._json(200, {'added': added, 'conflicts': conflicts})


def build_store(args):
    key, _source = resolve_key()
    if not key:
        return None, 'no key set, in the environment or the Claude Code plugin config'

    candidates = [
        args.config,
        os.environ.get('CLAUDEFUSCATOR_CONFIG'),
        os.path.join(os.getcwd(), 'claudefuscator.local.json'),
        os.path.expanduser('~/.claudefuscator/identifiers.json'),
    ]
    raw, source = None, None
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            try:
                with open(candidate, 'rb') as f:
                    raw = json.load(f)
            except (OSError, json.JSONDecodeError) as e:
                return None, f'config at {candidate} is not valid JSON: {e}'
            source = candidate
            break
    if raw is None:
        return None, 'no identifier config found'

    merged = config_merge.merge_config(
        raw, config_merge.file_pack_loader(os.path.dirname(source)), source
    )
    shared, vault_status = VaultClient.from_config(merged['config'], key)

    try:
        store = Store(key, merged['config'], args.cache, shared=shared)
    except Exception as e:                  # collision, bad entry
        return None, str(e)

    known, discovered = store.counts()
    return store, (f'ACTIVE ({known} known, {discovered} discovered; '
                   f'config: {source}; vault: {vault_status})')


FINGERPRINT_LABEL = 'claudefuscator/fingerprint/v1'


# Claude Code keeps a mod's userConfig here, and the mod reads its key from
# `options.secret_key` before falling back to the environment. The agent
# reads the same place, in the same order, so one setting serves both and
# nobody has to keep an environment variable and a config entry in step.
#
# Not a new copy of the key: it is the copy the mod already uses. Putting it
# in two places would be the thing worth avoiding.
CLAUDE_SETTINGS = os.path.join(os.path.expanduser('~'), '.claude', 'settings.json')
PLUGIN_KEYS = ('claudefuscator@claudefuscator', 'claudefuscator')


def _claude_plugin_options():
    """The mod's configured options, or {}. Never raises."""
    try:
        with open(CLAUDE_SETTINGS, 'rb') as f:
            settings = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}

    configs = settings.get('pluginConfigs')
    if not isinstance(configs, dict):
        return {}

    for name in PLUGIN_KEYS:
        entry = configs.get(name)
        if isinstance(entry, dict):
            options = entry.get('options')
            if isinstance(options, dict):
                return options

    # The install may be under a marketplace name this does not know. Take a
    # single claudefuscator-looking entry rather than guessing between several.
    candidates = [v.get('options') for k, v in configs.items()
                  if 'claudefuscator' in k.lower()
                  and isinstance(v, dict) and isinstance(v.get('options'), dict)]
    return candidates[0] if len(candidates) == 1 else {}


def resolve_key():
    """The Claudefuscator key, and where it came from.

    Returns (key, source). `source` names the place, never the value - it is
    printed, and the key must not be.
    """
    from_env = os.environ.get('CLAUDEFUSCATOR_KEY', '').strip()
    if from_env:
        return from_env, 'CLAUDEFUSCATOR_KEY'

    configured = _claude_plugin_options().get('secret_key')
    if isinstance(configured, str) and configured.strip():
        return configured.strip(), 'the Claude Code plugin config'

    return None, None


NO_KEY = (
    'No key configured.\n'
    '\n'
    'The agent looks in two places, in this order:\n'
    '  1. the CLAUDEFUSCATOR_KEY environment variable\n'
    '  2. secret_key in the Claude Code plugin config\n'
    '     (' + CLAUDE_SETTINGS + ', under pluginConfigs)\n'
    '\n'
    'The second is the same setting the mod reads, so setting it there means\n'
    'one place rather than two. In Claude Code: /plugin, pick claudefuscator,\n'
    'then configure, then secret_key.'
)


def resolve_config_path(explicit=None):
    """Where the identifier list lives.

    Prefers an explicit --config, then the environment, then the path the
    mod is already configured with, then the conventional location. The
    third is what makes the agent and the mod agree about which list is in
    force without it being said twice.
    """
    candidates = [
        explicit,
        os.environ.get('CLAUDEFUSCATOR_CONFIG'),
        _claude_plugin_options().get('config_path'),
        os.path.join(os.getcwd(), 'claudefuscator.local.json'),
        os.path.join(os.path.expanduser('~'), '.claudefuscator', 'identifiers.json'),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def load_config(explicit=None):
    """The identifier list as a dict, or {}."""
    path = resolve_config_path(explicit)
    if not path:
        return {}
    try:
        with open(path, 'rb') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def print_fingerprint():
    """Say which key is configured, without saying what it is.

    Escrow turns on a question nobody can answer by looking: is the sealed
    copy the same key that is in use? Comparing the secrets themselves
    means both parties revealing them to each other, which is how a copy
    gets pasted into a chat window.

    An HMAC over a fixed label, truncated, settles it instead. It is
    derived from the key, so it differs if a single character does; it is
    one-way, so it discloses nothing; and it is stable, so two people in
    different rooms can read eight characters to each other.

    Its own label, not the one /mappings uses: that value authenticates to
    the agent, so printing it would be printing a credential rather than a
    checksum.
    """
    key, source = resolve_key()
    if not key:
        print(NO_KEY, file=sys.stderr)
        return 2

    print(f'key fingerprint: {core.hmac_hex(key, FINGERPRINT_LABEL)[:8]}  '
          f'({core.TOKEN_VERSION})')
    print('Same key on another machine prints the same eight characters. '
          'Different key, different fingerprint - compare these rather than '
          'the keys themselves.')
    return 0


def connect(args):
    """Get a vault credential by having the person approve this agent.

    The alternative was telling them to create one in the web UI and paste
    it into a terminal, where it lands in a shell history, a scrollback
    buffer and - this has happened on this project - a chat window.

    The shape, which is PKCE in all but name:

      1. invent a verifier, keep it in this process
      2. send only its SHA-256 to the browser, with the port to come back to
      3. the person signs in and approves
      4. the browser returns a one-time code to loopback
      5. exchange code + verifier directly with the host over TLS

    Step 4 is the one worth looking at twice. Anything running as this user
    could watch that redirect, so the code it carries has to be worthless
    alone - which is exactly what the verifier buys.
    """
    raw = load_config(args.config)
    vault = (raw or {}).get('vault')
    url = (vault or {}).get('url', '').strip().rstrip('/') if isinstance(vault, dict) else ''

    if not url:
        print('No vault.url configured, so there is nothing to connect to.\n'
              'Put the server address in your identifier list:\n'
              '  { "vault": { "url": "https://ai.example.com" } }', file=sys.stderr)
        return 2

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' and parsed.hostname not in LOOPBACK_HOSTS:
        print(f'Refusing to connect over {parsed.scheme} to {parsed.hostname}: a '
              'credential would cross the wire in clear.', file=sys.stderr)
        return 2

    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode('utf-8')).digest()).rstrip(b'=').decode()
    state = secrets.token_urlsafe(16)

    received = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            parts = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parts.query)

            if parts.path != '/claudefuscator/connected':
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return

            # Compared before the code is touched. Without it, any page the
            # browser happens to load could drive this listener.
            if (query.get('state') or [''])[0] != state:
                received['error'] = 'the browser came back with the wrong state'
            else:
                received['code'] = (query.get('code') or [''])[0]

            body = (b'<!doctype html><meta charset="utf-8">'
                    b'<title>Claudefuscator</title>'
                    b'<body style="font:14px system-ui;padding:3rem;max-width:34rem">'
                    b'<h1 style="font-size:1.2rem">Connected</h1>'
                    b'<p>You can close this tab and go back to the terminal.</p>')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # Port 0: the OS picks a free one. A fixed port would collide with
    # whatever else is running and, worse, would let something squat on it
    # and receive the redirect.
    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    port = server.server_address[1]

    target = (f'{url}/claudefuscator/connect'
              f'?challenge={urllib.parse.quote(challenge)}'
              f'&port={port}'
              f'&state={urllib.parse.quote(state)}'
              f'&label={urllib.parse.quote(args.label or socket.gethostname())}')

    print('Approve this agent in your browser:\n')
    print(f'  {target}\n')
    print('Opening it for you. Waiting up to two minutes.')
    try:
        webbrowser.open(target)
    except Exception:
        print('(could not open a browser - use the link above)')

    server.timeout = 120
    server.handle_request()
    server.server_close()

    if received.get('error'):
        print(f'Not connected: {received["error"]}', file=sys.stderr)
        return 1
    if not received.get('code'):
        print('Not connected: nothing came back from the browser in time.',
              file=sys.stderr)
        return 1

    body = json.dumps({'code': received['code'], 'verifier': verifier}).encode('utf-8')
    request = urllib.request.Request(
        url + '/api/vault/connect/exchange', data=body, method='POST',
        headers={'Content-Type': 'application/json', 'User-Agent': USER_AGENT})

    try:
        with _OPENER.open(request, timeout=20) as response:
            issued = json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        # Status only. An error body from this endpoint can echo the
        # request, and the request carries the code and the verifier.
        print(f'Not connected: the vault answered {e.code}.', file=sys.stderr)
        return 1
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        print(f'Not connected: {type(e).__name__}', file=sys.stderr)
        return 1

    token = issued.get('token')
    if not token:
        print('Not connected: the vault returned no credential.', file=sys.stderr)
        return 1

    try:
        credentials.store(url, token)
    except credentials.CredentialError as e:
        print(f'Connected, but the credential could not be stored: {e}', file=sys.stderr)
        return 1

    print(f'\nConnected to {url} as "{issued.get("label")}".')
    print(f'Credential stored: {credentials.protection()}.')
    if not credentials.WINDOWS:
        print('NOTE: on this platform it is NOT encrypted at rest - only the '
              'file permissions protect it.')
    return 0


def disconnect(_args):
    """Forget the stored credential."""
    if credentials.clear():
        print('Forgotten. The credential in the vault still exists - revoke it '
              'there too if this machine should no longer have one.')
        return 0
    print('Nothing stored here.')
    return 0


def enrol_key(args):
    """Store this machine's key in the vault, wrapped under the API token."""
    key, source = resolve_key()
    if not key:
        print(NO_KEY, file=sys.stderr)
        return 2

    raw = load_config(args.config)
    client, status = VaultClient.from_config(raw, key)
    if client is None:
        print(f'No vault to enrol with: {status}', file=sys.stderr)
        return 2

    # Said before the network call, so a run that cannot work is diagnosable
    # from its own output. The source, never the key.
    print(f'Key from {source}; vault {status}.')

    ok, err = client.enrol_key()
    if not ok:
        print(f'Not enrolled: {err}', file=sys.stderr)
        return 1

    # Verified by reading it back, because an enrolment that silently
    # stored the wrong thing would only surface in a browser that cannot
    # unveil anything, with nothing to point at.
    if client.fetch_key() != key:
        print('Enrolled, but it did not read back as the same key. Do not rely '
              'on it.', file=sys.stderr)
        return 1

    print('Enrolled, and verified by reading it back.')
    print('Any browser with this same API token can now collect the key for '
          'its session. The vault holds it wrapped under that token and '
          'cannot open it from the database alone - but a compromise of the '
          'running host can. See docs/UNVEIL-SERVER.md.')
    return 0


def publish_identifiers(args):
    """Seal a local file and publish it as the shared identifier list.

    Here rather than on the web page that composes the list, because
    sealing needs the key and a server able to seal could read everything
    it stores. The agent is the component that holds the key, so the agent
    is what publishes.
    """
    key, source = resolve_key()
    if not key:
        print(NO_KEY, file=sys.stderr)
        return 2

    if args.version is None:
        print('--version is required. It has to increase on every publish: the '
              'vault refuses one that does not, and the envelope binds it so an '
              'older list cannot be replayed as the current one.', file=sys.stderr)
        return 2

    try:
        with open(args.publish_identifiers, 'r', encoding='utf-8') as f:
            text = f.read()
    except OSError as e:
        print(f'Could not read {args.publish_identifiers}: {e}', file=sys.stderr)
        return 2

    try:
        json.loads(text)
    except json.JSONDecodeError as e:
        # Refused here rather than discovered by every agent that fetches
        # it. A published list that does not parse leaves everyone on their
        # local config, which looks exactly like nobody having published.
        print(f'{args.publish_identifiers} is not valid JSON: {e}', file=sys.stderr)
        return 2

    raw = None
    for candidate in (args.config, os.environ.get('CLAUDEFUSCATOR_CONFIG'),
                      os.path.join(os.getcwd(), 'claudefuscator.local.json'),
                      os.path.expanduser('~/.claudefuscator/identifiers.json')):
        if candidate and os.path.exists(candidate):
            try:
                with open(candidate, 'rb') as f:
                    raw = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            break

    client, status = VaultClient.from_config(raw or {}, key)
    if client is None:
        print(f'No vault to publish to: {status}', file=sys.stderr)
        return 2

    ok, err = client.publish_identifiers(text, args.version)
    if not ok:
        print(f'Not published: {err}', file=sys.stderr)
        return 1

    print(f'Published version {args.version} ({len(text)} bytes, sealed).')
    print('Agents pick it up on their next fetch; nothing here can read it back '
          'without the key.')
    return 0


def main():
    parser = argparse.ArgumentParser(description='Claudefuscator local agent')
    parser.add_argument('--port', type=int, default=int(os.environ.get('CLAUDEFUSCATOR_AGENT_PORT', DEFAULT_PORT)))
    parser.add_argument('--config', help='identifier list; defaults to CLAUDEFUSCATOR_CONFIG')
    parser.add_argument(
        '--connect', action='store_true',
        help='get a vault credential by approving this agent in your browser, '
             'instead of creating one by hand and pasting it')
    parser.add_argument(
        '--disconnect', action='store_true',
        help='forget the stored vault credential on this machine')
    parser.add_argument(
        '--label', default=None,
        help='what to call this agent in the vault (default: this hostname)')
    parser.add_argument(
        '--enrol-key', action='store_true',
        help="wrap this machine's key under your API token and store it in "
             'the vault, so a browser can collect it once per session. Read '
             'the trade-off in docs/UNVEIL-SERVER.md before using it.')
    parser.add_argument(
        '--fingerprint', action='store_true',
        help='print a short fingerprint of the configured key and exit. Reveals '
             'nothing about the key; two copies match if and only if their '
             'fingerprints do.')
    parser.add_argument(
        '--publish-identifiers', metavar='FILE',
        help='seal FILE and publish it as the shared identifier list, then exit. '
             'Needs the ManageIdentifiers role.')
    parser.add_argument(
        '--version', type=int, metavar='N',
        help='version for --publish-identifiers. Must increase: the vault '
             'refuses one that does not, and the envelope binds it so an '
             'older list cannot be replayed as the current one.')
    parser.add_argument('--cache', default=os.environ.get(
        'CLAUDEFUSCATOR_CACHE', os.path.expanduser('~/.claudefuscator/discovered.json')),
        help='where discovered values persist. Holds real values in plaintext.')
    args = parser.parse_args()

    if args.fingerprint:
        return print_fingerprint()

    if args.connect:
        return connect(args)

    if args.disconnect:
        return disconnect(args)

    if args.enrol_key:
        return enrol_key(args)

    if args.publish_identifiers:
        return publish_identifiers(args)

    store, status = build_store(args)
    if store is None:
        # Refuse to start rather than serve an empty table: a silently empty
        # agent looks exactly like a working one from the browser's side.
        print(f'Claudefuscator agent: INACTIVE ({status}). Not starting.', file=sys.stderr)
        return 2

    Handler.store = store
    print(f'Claudefuscator agent: {status}')
    print(f'Listening on http://127.0.0.1:{args.port} (loopback only)')

    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
