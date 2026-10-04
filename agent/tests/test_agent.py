"""Tests for the local agent.

The claims that matter here are refusals: the agent serves real identifier
values, so most of these assert that it does NOT do something.
"""

import json
import os
import pathlib
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest
import requests

AGENT_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))
sys.path.insert(0, str(AGENT_DIR.parent / 'proxy'))

import claudefuscator_agent as agent        # noqa: E402
import claudefuscator_core as core          # noqa: E402

KEY = 'agent-test-key'
CONFIG = {
    'tokenLength': 8,
    'internalDomains': ['corp.example'],
    'identifiers': [
        {'type': 'PERSON', 'value': 'Jane Example'},
        {'type': 'HOST', 'value': 'build-01.corp.example'},
    ],
}
REAL_PERSON = 'Jane Example'
REAL_HOST = 'build-01.corp.example'


def auth():
    return core.hmac_hex(KEY, agent.AUTH_LABEL)[:32]


@pytest.fixture
def running(tmp_path):
    store = agent.Store(KEY, CONFIG, tmp_path / 'discovered.json')
    agent.Handler.store = store
    server = ThreadingHTTPServer(('127.0.0.1', 0), agent.Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_address[1]}'
    try:
        yield url, store
    finally:
        server.shutdown()
        server.server_close()


def post(url, path, payload, with_auth=True):
    headers = {'Content-Type': 'application/json'}
    if with_auth:
        headers[agent.AUTH_HEADER] = auth()
    return requests.post(url + path, data=json.dumps(payload), headers=headers, timeout=10)


def token_for(type_, value):
    return core.derive_token(KEY, type_, value, 8)


# ---- refusals ---------------------------------------------------------

def test_resolve_refuses_without_the_auth_header(running):
    url, _ = running
    r = post(url, '/resolve', {'tokens': [token_for('PERSON', REAL_PERSON)]}, with_auth=False)
    assert r.status_code == 403
    assert REAL_PERSON not in r.text


def test_resolve_refuses_a_wrong_token(running):
    url, _ = running
    r = requests.post(url + '/resolve', data=json.dumps({'tokens': []}),
                      headers={agent.AUTH_HEADER: 'f' * 32}, timeout=10)
    assert r.status_code == 403


def test_there_is_no_bulk_export(running):
    """A dump of the whole table is what an attacker wants, so no route
    returns one. /resolve answers only about tokens it was given."""
    url, _ = running
    for path in ('/mappings', '/resolve', '/all', '/export', '/dump'):
        r = requests.get(url + path, headers={agent.AUTH_HEADER: auth()}, timeout=10)
        assert r.status_code == 404, f'GET {path} should not exist'
        assert REAL_PERSON not in r.text


def test_no_cors_header_is_sent(running):
    """A page may send a request; it must never read the response."""
    url, _ = running
    r = post(url, '/resolve', {'tokens': []})
    assert 'Access-Control-Allow-Origin' not in r.headers


def test_healthz_reports_counts_but_no_values(running):
    url, _ = running
    r = requests.get(url + '/healthz', timeout=10)      # no auth needed
    assert r.status_code == 200
    body = r.json()
    assert body['known'] == 2
    assert REAL_PERSON not in r.text and REAL_HOST not in r.text


def test_an_oversized_body_is_rejected(running):
    url, _ = running
    r = requests.post(url + '/resolve',
                      data=json.dumps({'tokens': ['x' * (agent.MAX_BODY + 10)]}),
                      headers={agent.AUTH_HEADER: auth()}, timeout=10)
    assert r.status_code == 400


# ---- resolving --------------------------------------------------------

def test_resolve_returns_only_the_tokens_asked_for(running):
    url, _ = running
    wanted = token_for('PERSON', REAL_PERSON)
    other = token_for('HOST', REAL_HOST)
    r = post(url, '/resolve', {'tokens': [wanted]})
    body = r.json()
    assert body['mappings'] == {wanted: REAL_PERSON}
    assert other not in r.text, 'a token that was not asked about came back'


def test_resolve_reports_what_it_could_not_resolve(running):
    """This is what drives the red marking in the extension."""
    url, _ = running
    r = post(url, '/resolve', {'tokens': ['HOST_zzzzzzzz']})
    assert r.json()['mappings'] == {}
    assert r.json()['unresolved'] == ['HOST_zzzzzzzz']


# ---- submitting -------------------------------------------------------

def test_a_submitted_mapping_becomes_resolvable(running):
    url, _ = running
    tok = token_for('IP', '10.44.2.9')
    assert post(url, '/resolve', {'tokens': [tok]}).json()['mappings'] == {}
    assert post(url, '/mappings', {'mappings': [{'token': tok, 'value': '10.44.2.9'}]}).json()['added'] == 1
    assert post(url, '/resolve', {'tokens': [tok]}).json()['mappings'] == {tok: '10.44.2.9'}


def test_writes_are_write_once_and_conflicts_are_reported(running):
    """Under a correct client a token determines its value, so a conflict is
    a bug, a key mismatch, or poisoning. Keep the first value and say so."""
    url, _ = running
    tok = token_for('IP', '10.44.2.9')
    post(url, '/mappings', {'mappings': [{'token': tok, 'value': '10.44.2.9'}]})
    r = post(url, '/mappings', {'mappings': [{'token': tok, 'value': 'attacker.example'}]})
    assert r.json()['added'] == 0
    assert r.json()['conflicts'] == [tok]
    assert post(url, '/resolve', {'tokens': [tok]}).json()['mappings'] == {tok: '10.44.2.9'}


def test_submitting_cannot_overwrite_a_list_entry(running):
    url, _ = running
    tok = token_for('PERSON', REAL_PERSON)
    r = post(url, '/mappings', {'mappings': [{'token': tok, 'value': 'Someone Else'}]})
    assert r.json()['conflicts'] == [tok]
    assert post(url, '/resolve', {'tokens': [tok]}).json()['mappings'] == {tok: REAL_PERSON}


def test_junk_entries_are_ignored_not_fatal(running):
    url, _ = running
    r = post(url, '/mappings', {'mappings': [{'token': 1}, {'value': 'x'}, 'nope', {}]})
    assert r.status_code == 200
    assert r.json()['added'] == 0


# ---- persistence ------------------------------------------------------

def test_discovered_values_survive_a_restart(tmp_path):
    """Otherwise the browser loses every pattern hit each time the agent is
    bounced."""
    cache = tmp_path / 'discovered.json'
    tok = token_for('IP', '10.44.2.9')

    first = agent.Store(KEY, CONFIG, cache)
    first.submit([{'token': tok, 'value': '10.44.2.9'}])
    assert cache.exists()

    second = agent.Store(KEY, CONFIG, cache)
    assert second.resolve([tok]) == {tok: '10.44.2.9'}


def test_a_corrupt_cache_is_treated_as_empty(tmp_path):
    cache = tmp_path / 'discovered.json'
    cache.write_text('{ not json', encoding='utf-8')
    store = agent.Store(KEY, CONFIG, cache)          # must not raise
    assert store.counts() == (2, 0)


def test_the_cache_warns_what_it_holds(tmp_path):
    cache = tmp_path / 'discovered.json'
    store = agent.Store(KEY, CONFIG, cache)
    store.submit([{'token': token_for('IP', '10.1.2.3'), 'value': '10.1.2.3'}])
    data = json.loads(cache.read_text(encoding='utf-8'))
    assert 'plaintext' in data['warning']
    assert data['tokenVersion'] == core.TOKEN_VERSION


# ---- startup ----------------------------------------------------------

def test_it_refuses_to_start_without_a_key(monkeypatch, tmp_path):
    """A silently empty agent looks exactly like a working one from the
    browser's side, so it must not start at all."""
    monkeypatch.delenv('CLAUDEFUSCATOR_KEY', raising=False)
    # Pinned to an empty home as well as an empty environment. The agent now
    # also reads the Claude Code plugin config, so on a machine where that
    # carries a key this would quietly pass by starting successfully - which
    # is the opposite of what it claims to check.
    import importlib
    empty_home = tmp_path / 'home'
    (empty_home / '.claude').mkdir(parents=True)
    monkeypatch.setenv('HOME', str(empty_home))
    monkeypatch.setenv('USERPROFILE', str(empty_home))
    mod = importlib.reload(agent)

    args = type('A', (), {'config': None, 'cache': str(tmp_path / 'c.json')})()
    store, status = mod.build_store(args)
    assert store is None
    # Names both places it looked, so somebody who set the other one can
    # tell why nothing happened.
    assert 'environment' in status and 'plugin config' in status


def test_it_refuses_to_start_without_a_config(monkeypatch, tmp_path):
    monkeypatch.setenv('CLAUDEFUSCATOR_KEY', KEY)
    monkeypatch.delenv('CLAUDEFUSCATOR_CONFIG', raising=False)
    monkeypatch.chdir(tmp_path)

    # Point HOME at an empty directory too. The last candidate build_store
    # tries is ~/.claudefuscator/identifiers.json, so without this the test
    # passes or fails depending on whether whoever runs it happens to use
    # the tool - it went red the moment a real config appeared in a home
    # directory, which is the wrong reason for a test to change colour.
    monkeypatch.setenv('HOME', str(tmp_path))
    monkeypatch.setenv('USERPROFILE', str(tmp_path))

    args = type('A', (), {'config': None, 'cache': str(tmp_path / 'c.json')})()
    store, status = agent.build_store(args)
    assert store is None
    assert 'no identifier config' in status


def test_it_starts_from_a_config_file(monkeypatch, tmp_path):
    cfg = tmp_path / 'ids.json'
    cfg.write_text(json.dumps(CONFIG), encoding='utf-8')
    monkeypatch.setenv('CLAUDEFUSCATOR_KEY', KEY)
    args = type('A', (), {'config': str(cfg), 'cache': str(tmp_path / 'c.json')})()
    store, status = agent.build_store(args)
    assert store is not None
    assert status.startswith('ACTIVE') and '2 known' in status


# ---- key fingerprint ---------------------------------------------------

def test_the_fingerprint_is_stable_and_key_dependent(capsys, monkeypatch):
    """Escrow's unanswerable question - is the sealed copy the key in use? -
    without either party revealing a key to the other."""
    monkeypatch.setenv('CLAUDEFUSCATOR_KEY', 'the-key')
    agent.print_fingerprint()
    first = capsys.readouterr().out.splitlines()[0]

    agent.print_fingerprint()
    assert capsys.readouterr().out.splitlines()[0] == first, 'not stable'

    monkeypatch.setenv('CLAUDEFUSCATOR_KEY', 'the-kez')
    agent.print_fingerprint()
    assert capsys.readouterr().out.splitlines()[0] != first, 'one character changed nothing'


def test_the_fingerprint_does_not_contain_the_key(capsys, monkeypatch):
    secret = 'a-distinctive-secret-value'
    monkeypatch.setenv('CLAUDEFUSCATOR_KEY', secret)
    agent.print_fingerprint()
    out = capsys.readouterr().out

    assert secret not in out
    for i in range(0, len(secret) - 3):
        assert secret[i:i + 4] not in out, 'a fragment of the key was printed'


def test_the_fingerprint_is_not_the_agent_auth_token(capsys, monkeypatch):
    """That value authenticates to the agent, so printing it would be
    printing a credential rather than a checksum."""
    monkeypatch.setenv('CLAUDEFUSCATOR_KEY', KEY)
    agent.print_fingerprint()
    out = capsys.readouterr().out

    assert core.hmac_hex(KEY, agent.AUTH_LABEL)[:8] not in out


def test_no_key_is_refused_rather_than_fingerprinting_nothing(monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_KEY', raising=False)
    assert agent.print_fingerprint() == 2


# ---- cross-surface ----------------------------------------------------

def test_the_agent_agrees_with_the_committed_vectors():
    """It derives tokens with the same core as the proxy, the plugin, the mod
    and the extension. If it did not, nothing it served would resolve."""
    vectors = json.loads(
        (AGENT_DIR.parent / 'shared' / 'test-vectors.json').read_text(encoding='utf-8'))
    store = agent.Store(vectors['key'], vectors['config'], None)
    for t in vectors['tokens']:
        assert store.resolve([t['token']]).get(t['token']) == t['value'], \
            f'the agent cannot resolve {t["token"]}'


# ---- where the key comes from ----------------------------------------
#
# The mod reads options.secret_key before the environment. The agent has to
# agree, or one of them scrubs with a key the other does not have and the
# failure shows up as tokens that will not resolve.

def _settings(tmp_path, options):
    import json as _json
    home = tmp_path / 'home'
    (home / '.claude').mkdir(parents=True)
    (home / '.claude' / 'settings.json').write_text(_json.dumps({
        'pluginConfigs': {'claudefuscator@claudefuscator': {'options': options}}
    }), encoding='utf-8')
    return home


def _reload(monkeypatch, home):
    """Re-import the agent so CLAUDE_SETTINGS picks up the fake home."""
    import importlib
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('USERPROFILE', str(home))
    return importlib.reload(agent)


def test_the_key_is_read_from_the_claude_plugin_config(tmp_path, monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_KEY', raising=False)
    mod = _reload(monkeypatch, _settings(tmp_path, {'secret_key': 'from-plugin-config'}))

    key, source = mod.resolve_key()
    assert key == 'from-plugin-config'
    # The source is printed; it must name the place, never the value.
    assert 'plugin config' in source
    assert 'from-plugin-config' not in source


def test_the_environment_wins_over_the_plugin_config(tmp_path, monkeypatch):
    mod = _reload(monkeypatch, _settings(tmp_path, {'secret_key': 'from-plugin-config'}))
    monkeypatch.setenv('CLAUDEFUSCATOR_KEY', 'from-environment')

    # An explicitly exported key is the one somebody meant right now.
    key, source = mod.resolve_key()
    assert key == 'from-environment'
    assert source == 'CLAUDEFUSCATOR_KEY'


def test_no_key_anywhere_is_reported_not_guessed(tmp_path, monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_KEY', raising=False)
    mod = _reload(monkeypatch, _settings(tmp_path, {}))

    key, source = mod.resolve_key()
    assert key is None and source is None
    # The message has to say both places, or somebody sets the one the
    # agent is not reading and cannot tell why nothing happened.
    assert 'CLAUDEFUSCATOR_KEY' in mod.NO_KEY
    assert 'secret_key' in mod.NO_KEY


def test_an_empty_secret_key_counts_as_unset(tmp_path, monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_KEY', raising=False)
    mod = _reload(monkeypatch, _settings(tmp_path, {'secret_key': '   '}))

    # Whitespace would otherwise build a vault that derives tokens nothing
    # else derives - scrubbing, but to values no colleague can resolve.
    assert mod.resolve_key() == (None, None)


def test_the_identifier_list_is_found_through_the_plugin_config(tmp_path, monkeypatch):
    monkeypatch.delenv('CLAUDEFUSCATOR_CONFIG', raising=False)
    listing = tmp_path / 'shared-list.json'
    listing.write_text('{"identifiers": []}', encoding='utf-8')
    mod = _reload(monkeypatch, _settings(tmp_path, {'config_path': str(listing)}))

    # The agent and the mod must agree on WHICH list is in force.
    assert mod.resolve_config_path() == str(listing)


def test_an_explicit_config_beats_the_plugin_config(tmp_path, monkeypatch):
    chosen = tmp_path / 'chosen.json'
    chosen.write_text('{"identifiers": []}', encoding='utf-8')
    other = tmp_path / 'other.json'
    other.write_text('{"identifiers": []}', encoding='utf-8')
    mod = _reload(monkeypatch, _settings(tmp_path, {'config_path': str(other)}))

    assert mod.resolve_config_path(str(chosen)) == str(chosen)
