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
import hmac
import json
import os
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'proxy'))

import claudefuscator_core as core          # noqa: E402
import config_merge                         # noqa: E402
from vault_client import VaultClient         # noqa: E402

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
    key = os.environ.get('CLAUDEFUSCATOR_KEY', '').strip()
    if not key:
        return None, 'no CLAUDEFUSCATOR_KEY set'

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
    key = os.environ.get('CLAUDEFUSCATOR_KEY', '').strip()
    if not key:
        print('No CLAUDEFUSCATOR_KEY set; nothing to fingerprint.', file=sys.stderr)
        return 2

    print(f'key fingerprint: {core.hmac_hex(key, FINGERPRINT_LABEL)[:8]}  '
          f'({core.TOKEN_VERSION})')
    print('Same key on another machine prints the same eight characters. '
          'Different key, different fingerprint - compare these rather than '
          'the keys themselves.')
    return 0


def publish_identifiers(args):
    """Seal a local file and publish it as the shared identifier list.

    Here rather than on the web page that composes the list, because
    sealing needs the key and a server able to seal could read everything
    it stores. The agent is the component that holds the key, so the agent
    is what publishes.
    """
    key = os.environ.get('CLAUDEFUSCATOR_KEY', '').strip()
    if not key:
        print('No CLAUDEFUSCATOR_KEY set; nothing can be sealed.', file=sys.stderr)
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
