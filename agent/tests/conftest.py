"""Keeps the agent's tests off this machine's real configuration.

Every source the agent reads for a key or a credential lives under the
home directory, and one of them now reaches the network: with a vault
configured and a credential stored, `resolve_key()` will fetch the
enrolled key from a live server.

That makes the whole suite vulnerable to a particular kind of wrong
answer - a test that passes, or fails, because of the developer's own
setup rather than the code. This project has already been bitten twice:
once by a test that only passed because `~/.claudefuscator/identifiers.json`
did not exist, and once by `test_it_refuses_to_start_without_a_key`
quietly succeeding on a machine whose plugin config held a key.

So every test gets an empty home unless it builds its own. Opt out with
`@pytest.mark.real_home` if a test genuinely needs the machine's state -
nothing does today, and anything that did would deserve the explanation.
"""

import pathlib
import sys

import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))
sys.path.insert(0, str(AGENT_DIR.parent / 'proxy'))


def pytest_configure(config):
    config.addinivalue_line(
        'markers',
        'real_home: let this test see the machine\'s own configuration')


@pytest.fixture(autouse=True)
def _isolated_home(request, tmp_path, monkeypatch):
    if 'real_home' in request.keywords:
        return

    home = tmp_path / 'isolated-home'
    (home / '.claudefuscator').mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setenv('USERPROFILE', str(home))

    # expanduser is what every lookup goes through, and on Windows it
    # consults USERPROFILE and HOMEPATH rather than HOME - so setting HOME
    # alone leaves the real profile reachable, which is exactly the hole
    # this fixture exists to close.
    #
    # Resolved against HOME at call time rather than captured here, so a
    # test that re-points HOME to build its own fixture still gets its
    # own - otherwise this fixture would silently override them, which
    # cost two passing tests the first time it was written this way.
    import os
    real_expanduser = os.path.expanduser

    def _current_home():
        return os.environ.get('HOME') or os.environ.get('USERPROFILE') or str(home)

    monkeypatch.setattr(pathlib.Path, 'home', lambda: pathlib.Path(_current_home()))
    monkeypatch.setattr(
        os.path, 'expanduser',
        lambda p: _current_home() + p[1:] if p.startswith('~') else real_expanduser(p))

    # The credential store caches its paths at import time.
    import credentials
    monkeypatch.setattr(credentials, 'STORE_DIR', str(home / '.claudefuscator'))
    monkeypatch.setattr(
        credentials, 'STORE_PATH', str(home / '.claudefuscator' / 'credential.json'))

    # And the key lookup memoises whatever it last collected.
    import claudefuscator_agent
    monkeypatch.setattr(claudefuscator_agent, '_VAULT_KEY', [])
    monkeypatch.setattr(
        claudefuscator_agent, 'CLAUDE_SETTINGS',
        str(home / '.claude' / 'settings.json'))
