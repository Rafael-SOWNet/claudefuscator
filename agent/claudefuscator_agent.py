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
import getpass
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import secrets
import socket
import stat
import sys
import threading
import time
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

    # What /bootstrap hands out, and the per-run token that guards it.
    # Held in memory only; the token also goes to a user-only file so the
    # mod can find it, the key and the list never do.
    bootstrap_token = None
    bootstrap_key = None
    bootstrap_config = None
    bootstrap_config_path = None

    @staticmethod
    def current_config():
        """The identifier list as it is on disk RIGHT NOW.

        Not the snapshot taken at startup. The agent is a long-running
        service and the list is a file people edit; serving the version
        from whenever the machine last booted meant an edit silently
        never reached the mod, which went on scrubbing with the old list
        and said nothing was wrong.

        A few kilobytes read once per mod load. The key stays memoised -
        that one costs a network round trip and does not change under
        you the way a local file does.
        """
        fresh = load_config(Handler.bootstrap_config_path)
        return fresh if fresh else Handler.bootstrap_config

    # When the pairing window closes, as a monotonic deadline. None means
    # shut. Opened only by someone who can read the handshake file, and
    # spent by the first client through it.
    pair_until = None
    pair_claimed = False

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
        expected = Handler.store.auth_token()

        if hmac.compare_digest(presented, expected):
            return True

        # Says WHICH failure, because the two need different fixes and a
        # bare 403 sent a whole afternoon after the wrong one. "Missing"
        # means a caller that never sent the header; "mismatched" means a
        # caller holding a different key.
        #
        # Neither value is logged. Only its length, which is enough to
        # tell a truncated header from a wrong one and discloses nothing:
        # these are HMAC prefixes, not secrets, but the key they prove is.
        why = ('no ' + AUTH_HEADER if not presented
               else f'{AUTH_HEADER} mismatched (presented {len(presented)} '
                    f'chars, expected {len(expected)}) - the caller holds a '
                    f'different key')
        sys.stderr.write('refused: ' + why + '\n')
        return False

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

        if self.path == '/pair/state':
            # For the --pair command to report an outcome rather than
            # leaving somebody guessing whether the browser took it.
            presented = self.headers.get(BOOTSTRAP_HEADER) or ''
            if not Handler.bootstrap_token or not hmac.compare_digest(
                    presented, Handler.bootstrap_token):
                self._json(403, {'error': 'bad or missing ' + BOOTSTRAP_HEADER})
                return
            open_for = (Handler.pair_until - time.monotonic()
                        if Handler.pair_until else 0)
            self._json(200, {
                'claimed': Handler.pair_claimed,
                'secondsLeft': max(0, round(open_for)),
            })
            return

        if self.path == '/bootstrap':
            # Hands the mod the key and the identifier list, so a machine
            # can run with neither configured locally.
            #
            # NOT guarded by the usual proof-of-key header, because the
            # caller is asking for the very key that header is built from.
            # The guard is instead a token this run wrote to a file only
            # this user can read, which keeps the bar exactly where it
            # already was: anyone who can read that file can read the
            # stored vault credential beside it and collect the key
            # themselves anyway.
            #
            # Per run, so it is not a standing credential, and never
            # logged.
            presented = self.headers.get(BOOTSTRAP_HEADER) or ''
            if not Handler.bootstrap_token or not hmac.compare_digest(
                    presented, Handler.bootstrap_token):
                self._json(403, {'error': 'bad or missing ' + BOOTSTRAP_HEADER})
                return

            self._json(200, {
                'key': Handler.bootstrap_key,
                'config': Handler.current_config(),
                'tokenVersion': core.TOKEN_VERSION,
            })
            return

        self._json(404, {'error': 'not found'})

    def _pair_open(self):
        """Open the pairing window. Needs the handshake token."""
        presented = self.headers.get(BOOTSTRAP_HEADER) or ''
        if not Handler.bootstrap_token or not hmac.compare_digest(
                presented, Handler.bootstrap_token):
            self._json(403, {'error': 'bad or missing ' + BOOTSTRAP_HEADER})
            return

        Handler.pair_until = time.monotonic() + PAIR_WINDOW_SECONDS
        Handler.pair_claimed = False
        self._json(200, {'open': True, 'seconds': PAIR_WINDOW_SECONDS})

    def _pair_claim(self):
        """Hand the key and the list to whoever asks, during the window.

        UNAUTHENTICATED, deliberately, and this is the one route that is.
        The client asking is a browser extension: it cannot read the
        handshake file, and it has no credential of its own until this
        call gives it one. Something has to go first.

        What makes it safe is not a secret but a shape:

          - the window only opens when somebody at the terminal says so,
            and that person had to be able to read the handshake file,
          - it lasts seconds, not for ever,
          - the first claim spends it,
          - and the agent sends NO CORS headers, so a web page can make
            this request but cannot read the answer. That last one is
            load-bearing. Adding Access-Control-Allow-Origin here would
            turn a deliberate, time-boxed handover into any page on the
            internet being able to take the key during the window.
        """
        now = time.monotonic()
        if Handler.pair_until is None or now > Handler.pair_until:
            self._json(403, {'error': 'no pairing window is open'})
            return

        # Spent on first use. Two clients pairing from one window would
        # mean the second one nobody asked for.
        Handler.pair_until = None
        Handler.pair_claimed = True

        self._json(200, {
            'key': Handler.bootstrap_key,
            'config': Handler.current_config(),
            'tokenVersion': core.TOKEN_VERSION,
        })

    def do_POST(self):
        if self.path == '/pair/open':
            self._pair_open()
            return

        if self.path == '/pair':
            self._pair_claim()
            return

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
    key, _source = resolve_key(getattr(args, 'key', None))
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


def resolve_key(explicit=None, allow_vault=True):
    """The Claudefuscator key, and where it came from.

    Returns (key, source). `source` names the place, never the value - it is
    printed, and the key must not be.

    Four sources, most explicit first: the --key argument, the
    environment, the Claude Code plugin config, and finally the vault,
    which is what lets a machine hold no key of its own at all.

    `allow_vault=False` for the one caller that must not use it: enrolment
    is about putting a LOCAL key into the vault, and taking the vault's
    own answer as its input would just write back what is already there.
    """
    if explicit:
        # `-` means stdin: the scriptable path that keeps the key out of
        # both the shell history and the process command line, where any
        # other process on the machine can read it.
        if explicit == '-':
            piped = sys.stdin.readline().strip()
            return (piped, 'standard input') if piped else (None, None)

        # Said every time, not once. A key on the command line is in the
        # shell history and in the process list, where anything running as
        # this user can read it - and both outlive the command. The person
        # asked for this path deliberately, so it works; it does not get
        # to be quiet about what it costs.
        print('WARNING: --key puts the key in your shell history and in the '
              'process list. Use "--key -" to pipe it in, or omit it and be '
              'prompted.', file=sys.stderr)
        return explicit.strip(), 'the --key argument'

    from_env = os.environ.get('CLAUDEFUSCATOR_KEY', '').strip()
    if from_env:
        return from_env, 'CLAUDEFUSCATOR_KEY'

    configured = _claude_plugin_options().get('secret_key')
    if isinstance(configured, str) and configured.strip():
        return configured.strip(), 'the Claude Code plugin config'

    if allow_vault:
        collected, why = _key_from_vault()
        if collected:
            return collected, 'the vault'
        if why:
            # Reported, never swallowed. "Nothing is configured" and "the
            # vault would not give it to me" need completely different
            # actions, and both otherwise present as the same silence.
            return None, None

    return None, None


_VAULT_KEY = []            # memo: [] unasked, [None] asked and failed, [key] got it


def _key_from_vault(config=None):
    """The enrolled key, unwrapped with the stored credential.

    This is what lets a machine hold no key at all: connect once, and the
    key arrives from the vault for as long as the credential is valid.
    It is unwrapped here and kept in memory for the life of the process -
    never written anywhere, which is the whole difference between
    collecting a key and storing one.

    Returns (key, problem). Both None means simply not configured for it.
    """
    if _VAULT_KEY:
        return _VAULT_KEY[0], None

    raw = config if config is not None else load_config()
    vault = (raw or {}).get('vault')
    if not isinstance(vault, dict) or not (vault.get('url') or '').strip():
        return None, None

    # A placeholder secret: unwrapping the enrolled key uses the API
    # credential, not the Claudefuscator key - which is the point, since
    # at this moment we do not have one. The client is used for this one
    # call and discarded, so nothing can later seal with the placeholder.
    client, status = VaultClient.from_config(raw, '')
    if client is None:
        return None, status

    collected = client.fetch_key()
    if not collected:
        _VAULT_KEY.append(None)
        return None, client.last_error or 'nothing enrolled'

    _VAULT_KEY.append(collected)
    return collected, None


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


HANDSHAKE_PATH = os.path.join(
    os.path.expanduser('~'), '.claudefuscator', 'agent.json')
BOOTSTRAP_HEADER = 'x-claudefuscator-bootstrap'

# Long enough to switch to the browser and click; short enough
# that a window left open by mistake is not a standing offer.
PAIR_WINDOW_SECONDS = 60


def write_handshake(port):
    """Tell the mod where this agent is and how to ask it for a key.

    A file rather than a fixed convention, because the thing that needs
    protecting is not the port - it is the right to call /bootstrap. The
    token in here is generated per run and is the only credential for
    that route.

    Putting it in a file keeps the bar exactly where it already was:
    whoever can read this file can read the stored vault credential
    sitting beside it, and could collect the key themselves. It does not
    lower the bar to "any local process", which an unauthenticated
    loopback route would have done.

    Returns the token, or None if it could not be written - in which case
    the agent still serves everything else and says the bootstrap is off.
    """
    token = secrets.token_urlsafe(32)
    try:
        os.makedirs(os.path.dirname(HANDSHAKE_PATH), exist_ok=True)
        handle = os.open(
            HANDSHAKE_PATH,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(handle, 'w', encoding='utf-8') as f:
            json.dump({'port': port, 'token': token}, f)
    except OSError:
        return None
    return token


def clear_handshake():
    """Remove the handshake file. Best effort."""
    try:
        os.remove(HANDSHAKE_PATH)
    except OSError:
        pass


def fingerprint(key):
    """Eight characters that identify a key without disclosing it.

    One derivation, used everywhere a key is named, so two places cannot
    print different fingerprints for the same key and make people think
    they hold different ones.
    """
    return core.hmac_hex(key, FINGERPRINT_LABEL)[:8]


def print_fingerprint(args=None):
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
    key, source = resolve_key(getattr(args, 'key', None))
    if not key:
        print(NO_KEY, file=sys.stderr)
        return 2

    print(f'key fingerprint: {fingerprint(key)}  ({core.TOKEN_VERSION})')
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


def print_status(args):
    """What this machine is configured with, without revealing any of it.

    Exists because every failure in this tool looks the same from the
    outside: nothing happens. "Is it scrubbing?", "did the connect work?"
    and "is my key the same one my colleague has?" are the three questions
    people actually ask, and before this they had no way to ask them.

    Prints sources and fingerprints only. Never a key, never a credential.
    """
    key, source = resolve_key(args.key)
    config_path = resolve_config_path(args.config)

    print('Key          : ', end='')
    if key:
        print(f'from {source}, fingerprint {fingerprint(key)}')
    else:
        print('NOT CONFIGURED - nothing will be scrubbed')

    print(f'Identifiers  : {config_path or "NOT FOUND - nothing will be scrubbed"}')

    raw = load_config(args.config)
    vault = (raw or {}).get('vault')
    url = (vault or {}).get('url', '').strip().rstrip('/') if isinstance(vault, dict) else ''

    if not url:
        print('Vault        : not configured (local mode)')
        return 0 if key else 1

    print(f'Vault        : {url}')

    client, vault_status = VaultClient.from_config(raw, key or 'unused')
    if client is None:
        print(f'Credential   : {vault_status}')
        return 1

    print(f'Credential   : stored ({credentials.protection()})')

    enrolled = client.fetch_key()
    if enrolled is None:
        # 404 is the ordinary state before anyone enrols, not a fault.
        # Printing the status code here sent the reader looking for a
        # server problem that was not there.
        reason = ('nothing enrolled yet - run with --enrol-key'
                  if client.last_status == 404
                  else client.last_error or 'could not be read')
        print(f'Enrolled key : {reason}')
    elif not key:
        print(f'Enrolled key : present, fingerprint {fingerprint(enrolled)}')
    elif enrolled == key:
        print(f'Enrolled key : matches this machine ({fingerprint(enrolled)})')
    else:
        # The quiet disaster. Both keys work, both scrub, and neither side
        # can resolve the other's tokens - which looks like the vault
        # losing data rather than two keys being in play.
        print(f'Enrolled key : DIFFERENT from this machine '
              f'(enrolled {fingerprint(enrolled)}, '
              f'local {fingerprint(key)})')
        print('               Tokens made here will not resolve for anyone '
              'using the enrolled one.')
        return 1

    # Non-zero whenever this machine would not actually scrub. The whole
    # point of a status command in this project is that silence and
    # success look identical, so exiting 0 while reporting "nothing will
    # be scrubbed" would reproduce the failure it exists to expose.
    return 0 if key and config_path else 1


def pair(_args):
    """Open a pairing window on the running agent, and report the outcome.

    The browser gets the key this way rather than from the vault,
    because the vault's copy is wrapped under the credential that
    enrolled it - which belongs to the agent, not to any browser. Only
    the enrolling client can open that blob, so handing browsers a
    different token could never have worked.

    Over loopback the agent already has the key in memory, and the
    person running this command is the same person sitting at the
    browser. That is the whole trust argument, and it is a better one
    than a second credential nobody wanted to manage.
    """
    try:
        with open(HANDSHAKE_PATH, encoding='utf-8') as f:
            handshake = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        print('No running agent found. Start it first:\n'
              '  python agent/claudefuscator_agent.py', file=sys.stderr)
        return 2

    base = f"http://127.0.0.1:{handshake['port']}"

    def ask(path, method='GET'):
        request = urllib.request.Request(base + path, method=method,
                                         data=b'' if method == 'POST' else None)
        request.add_header(BOOTSTRAP_HEADER, handshake['token'])
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode('utf-8'))

    try:
        opened = ask('/pair/open', 'POST')
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # A running agent that has never heard of pairing. Saying "not
            # answering" sent me looking at the handshake file when the
            # answer was that the process was started from older code.
            print('The agent that is running does not support pairing - it '
                  'predates it. Restart it and try again.', file=sys.stderr)
        else:
            print(f'The agent refused to open a window ({e.code}).', file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError, ValueError):
        print('No agent answered on that port. The handshake file may name a '
              'process that has since stopped; start the agent again.',
              file=sys.stderr)
        return 1

    seconds = opened.get('seconds', PAIR_WINDOW_SECONDS)
    print(f'Pairing is open for {seconds} seconds.')
    print()
    print('  In the extension options, press "Pair with local agent".')
    print()
    print('Nothing is typed or pasted: the key goes straight from this agent')
    print('to the extension over loopback, and is held in that browser only')
    print('until it closes.')

    deadline = time.monotonic() + seconds + 2
    while time.monotonic() < deadline:
        time.sleep(1)
        try:
            state = ask('/pair/state')
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
            continue
        if state.get('claimed'):
            print('\nPaired. The extension has the key for this browser session.')
            return 0

    print('\nNobody paired in time; the window is shut and nothing was handed '
          'over. Run this again when the browser is ready.', file=sys.stderr)
    return 1


def disconnect(_args):
    """Forget the stored credential."""
    if credentials.clear():
        print('Forgotten. The credential in the vault still exists - revoke it '
              'there too if this machine should no longer have one.')
        return 0
    print('Nothing stored here.')
    return 0


def prompt_for_key():
    """Ask for the key at the terminal, without echoing it.

    Better than telling somebody to export it first, which is what this
    replaced. An exported key is in the shell history, in the process
    command line where other processes can read it, and in the
    environment of everything that shell then starts. A prompt is none of
    those: it is read straight into this process and goes no further.

    Paste tends to bring a trailing newline or a stray space with it, so
    the value is stripped - a key differing by one invisible character
    derives entirely different tokens and looks completely fine.
    """
    # Checked before prompting, because getpass reads the terminal rather
    # than stdin: with no terminal it does not fail, it WAITS - forever, in
    # a script or a CI job, with no output saying why. A clear refusal is
    # the only acceptable behaviour there.
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print('No terminal to ask on. Run this from an interactive shell, or '
              'set CLAUDEFUSCATOR_KEY for this one command.', file=sys.stderr)
        return None

    print('Paste the Claudefuscator key. It will not be shown.')
    print('(This is the shared key that derives tokens - NOT your vault '
          'credential, which is already stored.)')
    try:
        typed = getpass.getpass('Key: ').strip()
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return None
    except Exception as e:
        # getpass falls back to echoing on some terminals and raises on
        # others. Either way, say so rather than letting a key appear on
        # screen unannounced.
        print(f'Could not read without echoing ({type(e).__name__}). Refusing '
              'to ask for a key in the clear.', file=sys.stderr)
        return None

    if not typed:
        print('Nothing entered.', file=sys.stderr)
        return None

    return typed


def enrol_key(args):
    """Store this machine's key in the vault, wrapped under the API token."""
    key, source = resolve_key(args.key, allow_vault=False)

    if not key:
        # Asked for rather than refused. This is the one moment in the
        # whole design where a person has to handle the key at all, and
        # after it nothing on any machine needs it configured again.
        key = prompt_for_key()
        source = 'what you just pasted'

    if not key:
        return 2

    raw = load_config(args.config)
    client, status = VaultClient.from_config(raw, key)
    if client is None:
        print(f'No vault to enrol with: {status}', file=sys.stderr)
        return 2

    # The confusion this catches: two different secrets are in play - the
    # shared Claudefuscator key, which derives tokens, and the per-person
    # API credential, which authenticates to the vault. Setting the second
    # where the first belongs is an easy mistake and a silent one. It would
    # scrub perfectly happily and derive tokens nobody else on earth
    # derives, and the first sign would be colleagues unable to resolve
    # anything you sent them.
    if key == client._token:
        print('That is your vault credential, not the Claudefuscator key.\n'
              '\n'
              'They are different secrets. The key derives tokens and is the '
              'same for everyone who must resolve each other\'s; the '
              'credential authenticates you to the vault and is yours alone. '
              'Enrolling the credential as the key would scrub happily and '
              'produce tokens no colleague can resolve.',
              file=sys.stderr)
        return 2

    # Said before the network call, so a run that cannot work is diagnosable
    # from its own output. The source and a fingerprint, never the key.
    #
    # The fingerprint is here rather than only afterwards because this is
    # the moment a mistyped or half-pasted key can still be caught. Once
    # it is in the vault, every browser that collects it scrubs with it,
    # and the symptom is colleagues unable to resolve anything.
    print(f'Key from {source}, fingerprint {fingerprint(key)}.')
    print(f'Vault {status}.')

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
    key, source = resolve_key(args.key)
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
        '--key', default=None,
        help='the Claudefuscator key, for scripts and for getting out of '
             'trouble. Use "-" to read it from standard input, which keeps it '
             'out of your shell history and out of the process command line; '
             'passing the value literally puts it in both.')
    parser.add_argument(
        '--status', action='store_true',
        help='what this machine is configured with, and whether the enrolled '
             'key matches it. Prints sources and fingerprints, never secrets.')
    parser.add_argument(
        '--connect', action='store_true',
        help='get a vault credential by approving this agent in your browser, '
             'instead of creating one by hand and pasting it')
    parser.add_argument(
        '--pair', action='store_true',
        help='hand the key to a browser extension over loopback, during a '
             'short window you open from here. Nothing is typed or pasted.')
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
        return print_fingerprint(args)

    if args.status:
        return print_status(args)

    if args.connect:
        return connect(args)

    if args.pair:
        return pair(args)

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

    # What the mod will collect, so it needs nothing configured itself.
    key, key_source = resolve_key(args.key)
    Handler.bootstrap_key = key
    Handler.bootstrap_config_path = args.config
    Handler.bootstrap_config = load_config(args.config)
    Handler.bootstrap_token = write_handshake(args.port)

    if Handler.bootstrap_token:
        print(f'Mod bootstrap: ready (key from {key_source})')
    else:
        print('Mod bootstrap: UNAVAILABLE - the mod will need its own key '
              'and identifier list.', file=sys.stderr)

    try:
        server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    finally:
        # The handshake names a port and a token for a process that is no
        # longer listening. Left behind, the mod would spend its startup
        # budget on a connection that cannot be made.
        clear_handshake()
    return 0


if __name__ == '__main__':
    sys.exit(main())
