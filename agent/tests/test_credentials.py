"""Tests for where the agent keeps its vault credential.

The claim being defended is narrow and worth stating: what sits on disk
should be useless to anyone who copies it. On Windows that is DPAPI's job,
not ours, so most of these check that we called it correctly and that we
did not quietly write the credential somewhere in the clear instead.
"""

import json
import pathlib
import sys

import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))
sys.path.insert(0, str(AGENT_DIR.parent / 'proxy'))

import credentials                            # noqa: E402
from vault_client import VaultClient           # noqa: E402

URL = 'https://vault.example.com'
TOKEN = 'reference-credential-not-a-real-one'


@pytest.fixture
def store(tmp_path, monkeypatch):
    """Point the store at a throwaway directory.

    Without this the suite would read and overwrite the real credential of
    whoever is running it, which is both destructive and a way to make a
    test pass because of a machine's state.
    """
    monkeypatch.setattr(credentials, 'STORE_DIR', str(tmp_path))
    monkeypatch.setattr(credentials, 'STORE_PATH', str(tmp_path / 'credential.json'))
    return tmp_path / 'credential.json'


def test_the_credential_is_not_on_disk_in_the_clear(store):
    credentials.store(URL, TOKEN)

    raw = store.read_bytes()
    assert TOKEN.encode() not in raw
    assert TOKEN not in raw.decode('utf-8', 'replace')


@pytest.mark.skipif(not credentials.WINDOWS, reason='DPAPI is Windows-only')
def test_windows_protects_it_with_dpapi(store):
    credentials.store(URL, TOKEN)

    # Recorded in the file so a later read knows how to open it - and so
    # that a downgrade to the unprotected path is visible rather than
    # silent.
    assert json.loads(store.read_text())['protection'] == 'dpapi'
    assert 'DPAPI' in credentials.protection()


def test_it_reads_back_what_was_stored(store):
    credentials.store(URL, TOKEN)
    assert credentials.load(URL) == TOKEN


def test_a_credential_is_not_served_for_another_vault(store):
    credentials.store(URL, TOKEN)

    # A credential is issued by one host for one host. Handing it to
    # another would send a bearer token somewhere it was never meant to go,
    # which is the whole failure the url checks elsewhere exist to stop.
    assert credentials.load('https://other.example.com') is None
    # A trailing slash is the same host, not another one.
    assert credentials.load(URL + '/') == TOKEN


def test_storing_again_replaces_rather_than_accumulates(store):
    credentials.store(URL, TOKEN)
    credentials.store(URL, 'a-newer-credential')
    assert credentials.load(URL) == 'a-newer-credential'


def test_nothing_stored_is_not_an_error(store):
    # Not being connected yet is the ordinary state of a fresh install.
    assert credentials.load(URL) is None


def test_a_corrupt_store_is_reported_rather_than_ignored(store):
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text(json.dumps({'protection': 'dpapi', 'blob': 'not base64 !!'}))

    # Silently treating this as "no credential" would send somebody looking
    # for a server problem when the fix is to connect again.
    with pytest.raises(credentials.CredentialError):
        credentials.load(URL)


def test_clearing_forgets_it(store):
    credentials.store(URL, TOKEN)
    assert credentials.clear() is True
    assert credentials.load(URL) is None
    assert credentials.clear() is False


@pytest.mark.skipif(
    credentials.WINDOWS,
    reason='Windows does not honour POSIX mode bits; DPAPI is the protection there')
def test_the_store_is_not_world_readable(store):
    credentials.store(URL, TOKEN)
    mode = store.stat().st_mode & 0o077

    # On POSIX this is the ONLY thing protecting the credential, since
    # there is no DPAPI to fall back on - which is why the store says so
    # out loud rather than implying the Windows story applies everywhere.
    assert mode == 0, oct(mode)


# ---- how the client picks a credential --------------------------------

def _config():
    return {'vault': {'enabled': True, 'url': URL}}


def test_the_client_uses_a_stored_credential(store, monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_VAULT_TOKEN', raising=False)
    credentials.store(URL, TOKEN)

    client, status = VaultClient.from_config(_config(), 'a-key')
    assert client is not None, status
    assert 'ACTIVE' in status


def test_the_environment_still_wins(store, monkeypatch):
    credentials.store(URL, TOKEN)
    monkeypatch.setenv('CLAUDEFUSCATOR_VAULT_TOKEN', 'from-the-environment')

    client, _ = VaultClient.from_config(_config(), 'a-key')
    # Not asserted by reading the token back out - it is never exposed -
    # but an explicit export must take precedence over a stored one.
    assert client is not None
    assert client._token == 'from-the-environment'


def test_a_credential_for_another_vault_does_not_connect_this_one(store, monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_VAULT_TOKEN', raising=False)
    credentials.store('https://somewhere.else.example', TOKEN)

    client, status = VaultClient.from_config(_config(), 'a-key')
    assert client is None
    assert 'not connected' in status


def test_not_connected_says_how_to_connect(store, monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_VAULT_TOKEN', raising=False)

    _client, status = VaultClient.from_config(_config(), 'a-key')
    # The message is the entire user interface at this point.
    assert '--connect' in status
