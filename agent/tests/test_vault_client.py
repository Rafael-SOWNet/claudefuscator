"""Tests for the agent's client to the shared vault.

The vault is the one component here that someone else operates. These tests
are mostly about not trusting it: what it returns is opened under our key
and checked against the token before any of it reaches a caller.
"""

import json
import pathlib
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))
sys.path.insert(0, str(AGENT_DIR.parent / 'proxy'))

import claudefuscator_agent as agent        # noqa: E402
import claudefuscator_core as core          # noqa: E402
import vault_crypto as vc                   # noqa: E402
from vault_client import VaultClient        # noqa: E402

KEY = 'vault-client-test-key'
REAL_IP = '10.44.2.9'
TOKEN = core.derive_token(KEY, 'IP', REAL_IP, 8)


class FakeVault(BaseHTTPRequestHandler):
    """Stands in for ai.example.com. `rows` and `seen` are class state so a
    test can arrange answers and inspect what was asked."""

    rows = {}
    seen = {'auth': [], 'tokens': [], 'submitted': []}
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = json.loads(self.rfile.read(length) or b'{}')
        FakeVault.seen['auth'].append(self.headers.get('Authorization'))

        if self.path.endswith('/resolve'):
            asked = body.get('tokens') or []
            FakeVault.seen['tokens'].extend(asked)
            payload = {
                'mappings': [FakeVault.rows[t] for t in asked if t in FakeVault.rows],
                'unresolved': [t for t in asked if t not in FakeVault.rows],
                'withheld': 0,
            }
        else:
            FakeVault.seen['submitted'].extend(body.get('mappings') or [])
            payload = {'added': len(body.get('mappings') or []), 'conflicts': [], 'rejected': []}

        out = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)


def row_for(token, value, key=KEY, product=None):
    envelope = vc.seal(key, token, value, product=product)
    return {
        'token': token, 'tokenVersion': core.TOKEN_VERSION, 'product': product,
        'envelopeVersion': envelope['v'], 'nonce': envelope['n'],
        'ciphertext': envelope['ct'],
    }


@pytest.fixture
def vault():
    FakeVault.rows = {}
    FakeVault.seen = {'auth': [], 'tokens': [], 'submitted': []}
    server = ThreadingHTTPServer(('127.0.0.1', 0), FakeVault)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_address[1]}'
    try:
        yield url, FakeVault
    finally:
        server.shutdown()
        server.server_close()


# ---- not trusting the server -----------------------------------------

def test_a_row_the_key_cannot_open_is_dropped(vault):
    url, fake = vault
    fake.rows[TOKEN] = row_for(TOKEN, REAL_IP, key='somebody-elses-key')

    client = VaultClient(url, 'pat', KEY)
    assert client.resolve([TOKEN]) == {}


def test_a_tampered_row_is_dropped(vault):
    url, fake = vault
    row = row_for(TOKEN, REAL_IP)
    row['ciphertext'] = row['ciphertext'][:-4] + 'AAAA'
    fake.rows[TOKEN] = row

    client = VaultClient(url, 'pat', KEY)
    assert client.resolve([TOKEN]) == {}


def test_a_row_that_opens_but_does_not_hash_back_is_REFUSED(vault):
    """The one that matters most.

    A writer holding the key can seal a wrong value perfectly well, and it
    decrypts cleanly. Only re-deriving the token from the value catches it.
    """
    url, fake = vault
    fake.rows[TOKEN] = row_for(TOKEN, 'attacker.example')

    client = VaultClient(url, 'pat', KEY)
    assert client.resolve([TOKEN]) == {}


def test_a_genuine_row_is_accepted(vault):
    url, fake = vault
    fake.rows[TOKEN] = row_for(TOKEN, REAL_IP)

    client = VaultClient(url, 'pat', KEY)
    assert client.resolve([TOKEN]) == {TOKEN: REAL_IP}


def test_a_row_bound_to_another_product_does_not_open(vault):
    url, fake = vault
    row = row_for(TOKEN, REAL_IP, product='Widget')
    row['product'] = 'DigiPrint'          # claim a different one
    fake.rows[TOKEN] = row

    client = VaultClient(url, 'pat', KEY)
    assert client.resolve([TOKEN]) == {}


# ---- the credential ---------------------------------------------------

def test_the_bearer_token_is_sent_and_the_key_is_not(vault):
    url, fake = vault
    fake.rows[TOKEN] = row_for(TOKEN, REAL_IP)

    VaultClient(url, 'aiplatform_pat_secret', KEY).resolve([TOKEN])

    assert fake.seen['auth'] == ['Bearer aiplatform_pat_secret']
    assert KEY not in json.dumps(fake.seen)


def test_plain_http_to_a_remote_host_is_refused():
    """The bearer token would be on the wire in clear."""
    client, status = VaultClient.from_config(
        {'vault': {'url': 'http://ai.example.com'}}, KEY)
    assert client is None
    assert 'https' in status


def test_the_credential_is_not_read_from_the_config_file(monkeypatch):
    """A config file is shared, diffed and sometimes pasted."""
    monkeypatch.delenv('CLAUDEFUSCATOR_VAULT_TOKEN', raising=False)
    client, status = VaultClient.from_config(
        {'vault': {'url': 'https://ai.example.com', 'token': 'in-the-file'}}, KEY)
    assert client is None
    assert 'CLAUDEFUSCATOR_VAULT_TOKEN' in status


def test_no_vault_configured_is_not_an_error():
    client, status = VaultClient.from_config({}, KEY)
    assert client is None
    assert status == 'not configured'


# ---- submitting -------------------------------------------------------

def test_submitted_values_go_up_encrypted(vault):
    url, fake = vault
    added, _ = VaultClient(url, 'pat', KEY).submit([(TOKEN, REAL_IP)])

    assert added == 1
    wire = json.dumps(fake.seen['submitted'])
    assert REAL_IP not in wire, 'a real value was sent in clear'
    assert TOKEN in wire


def test_a_pair_our_own_key_does_not_vouch_for_is_not_submitted(vault):
    """Write-once means a wrong row could never be corrected, so a local bug
    must not be allowed to propagate to everyone."""
    url, fake = vault
    added, _ = VaultClient(url, 'pat', KEY).submit([(TOKEN, 'wrong-value')])

    assert added == 0
    assert fake.seen['submitted'] == []


# ---- redirects: the credential must not follow one --------------------

class RedirectingVault(BaseHTTPRequestHandler):
    """Answers every call with a redirect to another host, which is what the
    live server does to an unauthenticated API caller."""

    target = 'http://127.0.0.1:1/signin'
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def do_POST(self):
        length = int(self.headers.get('Content-Length') or 0)
        self.rfile.read(length)
        self.send_response(302)
        self.send_header('Location', RedirectingVault.target)
        self.send_header('Content-Length', '0')
        self.end_headers()


@pytest.fixture
def redirecting():
    server = ThreadingHTTPServer(('127.0.0.1', 0), RedirectingVault)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f'http://127.0.0.1:{server.server_address[1]}'
    finally:
        server.shutdown()
        server.server_close()


def test_a_redirect_is_refused_and_never_followed(redirecting):
    """Against the live server an unauthenticated call answers 302 to the
    identity provider. urllib follows redirects by default and carries
    custom headers across hosts, so following one would send the bearer
    token to a host that is not the vault. It must not.
    """
    client = VaultClient(redirecting, 'aiplatform_pat_secret', KEY, timeout=5)

    assert client.resolve([TOKEN]) == {}
    # And the failure says something a person can act on.
    assert 'token' in (client.last_error or '')


def test_a_redirect_on_submit_is_refused_too(redirecting):
    client = VaultClient(redirecting, 'aiplatform_pat_secret', KEY, timeout=5)
    assert client.submit([(TOKEN, REAL_IP)]) == (0, [])


# ---- failing soft -----------------------------------------------------

def test_an_unreachable_vault_resolves_to_nothing_rather_than_raising():
    client = VaultClient('http://127.0.0.1:9', 'pat', KEY, timeout=1)
    assert client.resolve([TOKEN]) == {}
    assert client.submit([(TOKEN, REAL_IP)]) == (0, [])
    assert 'unreachable' in (client.last_error or '')


# ---- the agent end to end --------------------------------------------

def test_the_agent_resolves_through_the_vault_and_caches_it(vault, tmp_path):
    """The whole point: a token this machine has never seen resolves because
    a colleague's machine discovered it."""
    url, fake = vault
    fake.rows[TOKEN] = row_for(TOKEN, REAL_IP)

    client = VaultClient(url, 'pat', KEY)
    store = agent.Store(KEY, {'tokenLength': 8, 'identifiers': []},
                        tmp_path / 'cache.json', shared=client)

    assert store.resolve([TOKEN]) == {TOKEN: REAL_IP}

    # Cached locally, so the second answer needs no round trip and survives
    # the vault being down or out of hours.
    fake.seen['tokens'].clear()
    assert store.resolve([TOKEN]) == {TOKEN: REAL_IP}
    assert fake.seen['tokens'] == []


def test_a_local_value_is_never_displaced_by_the_vault(vault, tmp_path):
    """This machine has first-hand knowledge; the vault has hearsay."""
    url, fake = vault
    fake.rows[TOKEN] = row_for(TOKEN, 'attacker.example')

    store = agent.Store(KEY, {'tokenLength': 8, 'identifiers': []},
                        tmp_path / 'cache.json', shared=VaultClient(url, 'pat', KEY))
    store.submit([{'token': TOKEN, 'value': REAL_IP}])

    assert store.resolve([TOKEN]) == {TOKEN: REAL_IP}


def test_the_agent_pushes_what_it_discovers(vault, tmp_path):
    url, fake = vault
    store = agent.Store(KEY, {'tokenLength': 8, 'identifiers': []},
                        tmp_path / 'cache.json', shared=VaultClient(url, 'pat', KEY))

    store.submit([{'token': TOKEN, 'value': REAL_IP}])

    assert len(fake.seen['submitted']) == 1
    assert REAL_IP not in json.dumps(fake.seen['submitted'])


def test_without_a_vault_the_agent_behaves_exactly_as_before(tmp_path):
    store = agent.Store(KEY, {'tokenLength': 8, 'identifiers': []},
                        tmp_path / 'cache.json')
    store.submit([{'token': TOKEN, 'value': REAL_IP}])
    assert store.resolve([TOKEN]) == {TOKEN: REAL_IP}
