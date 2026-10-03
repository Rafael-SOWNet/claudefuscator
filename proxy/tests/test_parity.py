"""Asserts the Python core reproduces shared/test-vectors.json byte for byte.

This is the file that makes a second implementation acceptable. The vectors
are generated from the JS reference (tools/gen-vectors.js); if this suite goes
red, the Python port has drifted from the JS one and tokens produced by the
proxy would no longer be restorable by the Chrome extension.

Failures here are never "just update the expected value" - find out which side
changed and why first.
"""

import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import claudefuscator_core as core  # noqa: E402

VECTORS_PATH = pathlib.Path(__file__).resolve().parents[2] / 'shared' / 'test-vectors.json'
VECTORS = json.loads(VECTORS_PATH.read_text(encoding='utf-8'))


def _vault():
    return core.build_vault(VECTORS['key'], VECTORS['config'])


def test_token_version_matches():
    assert VECTORS['tokenVersion'] == core.TOKEN_VERSION, (
        'TOKEN_VERSION differs between the vector file and the Python core'
    )


@pytest.mark.parametrize('case', VECTORS['tokens'], ids=lambda c: c['token'])
def test_token_derivation_matches_js(case):
    got = core.derive_token(
        VECTORS['key'], case['type'], case['value'], VECTORS['config']['tokenLength'],
        case.get('caseSensitive', False),
    )
    assert got == case['token'], f'Python derived a different token for {case["value"]!r}'


@pytest.mark.parametrize('case', VECTORS['scrub'], ids=lambda c: c['name'])
def test_scrub_matches_js(case):
    # Fresh vault per case: `discovered` from one case must not change another.
    vault = _vault()
    out, hits = vault.scrub(case['input'])
    assert out == case['output'], f'Python scrubbed differently: {case["name"]}'
    assert hits == case['hits'], f'Python hit records differ: {case["name"]}'


@pytest.mark.parametrize('case', VECTORS['scrub'], ids=lambda c: c['name'])
def test_restore_matches_js(case):
    vault = _vault()
    out, _ = vault.scrub(case['input'])
    assert vault.restore(out) == case['restored'], f'Python restored differently: {case["name"]}'


def test_private_ip_classification_matches():
    for ip in ['10.0.0.1', '172.16.0.1', '172.31.255.254', '192.168.0.1',
               '100.64.0.1', '100.127.0.1', '169.254.1.1']:
        assert core.is_private_ipv4(ip), f'missed private range: {ip}'
    for ip in ['172.15.0.1', '172.32.0.1', '100.63.0.1', '100.128.0.1',
               '11.0.0.1', '192.167.0.1', '9.9.9.9', '127.0.0.1',
               '8.8.8.8', '10.0.0.256', '10.0.0', '']:
        assert not core.is_private_ipv4(ip), f'false positive: {ip}'


def test_collision_is_a_hard_error():
    with pytest.raises(core.CollisionError):
        core.build_vault('k', {
            'tokenLength': 1,
            'identifiers': [{'type': 'HOST', 'value': f'h{i}'} for i in range(40)],
        })


def test_missing_key_raises():
    with pytest.raises(ValueError):
        core.build_vault('', VECTORS['config'])


def test_map_strings_keeps_shape():
    vault = _vault()
    src = {'a': 'Jane Example', 'b': [1, 'build-01.corp.example', None], 'c': {'d': True}}
    out = core.map_strings(src, lambda s: vault.scrub(s)[0])
    assert out['a'].startswith('PERSON_')
    assert out['b'][0] == 1
    assert out['b'][1].startswith('HOST_')
    assert out['b'][2] is None
    assert out['c']['d'] is True
