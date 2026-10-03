"""The Python half of the vault envelope contract.

shared/vault-vectors.json is read by this file and by VaultVectorTests in
`example/ai`. This half asserts the rows are genuine; that half asserts they
survive the real server and a real database unchanged. Neither claim is
worth much without the other: rows that open perfectly but get mangled in
transit resolve to nothing, and rows that survive transit but were never
valid resolve to nothing either.
"""

import io
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'agent'))
sys.path.insert(0, str(ROOT / 'proxy'))

import claudefuscator_core as core          # noqa: E402
import vault_crypto as vc                   # noqa: E402

VECTORS = json.loads(
    io.open(ROOT / 'shared' / 'vault-vectors.json', encoding='utf-8').read())


def envelope_of(row):
    return {'v': row['envelopeVersion'], 'n': row['nonce'], 'ct': row['ciphertext']}


@pytest.mark.parametrize('row', VECTORS['rows'], ids=lambda r: r['token'])
def test_every_committed_row_opens_to_its_value(row):
    assert vc.open_envelope(
        VECTORS['key'], row['token'], envelope_of(row), product=row['product']
    ) == row['value']


@pytest.mark.parametrize('row', VECTORS['rows'], ids=lambda r: r['token'])
def test_every_committed_row_hashes_back_to_its_token(row):
    """Opening proves someone with the key wrote it. Only this proves the
    value is the one the token stands for."""
    assert vc.verify_token(VECTORS['key'], row['token'], row['value'])


@pytest.mark.parametrize('row', VECTORS['rows'], ids=lambda r: r['token'])
def test_a_row_does_not_open_under_the_wrong_product(row):
    """The AAD binding, pinned so a change to it cannot pass unnoticed."""
    wrong = 'SomethingElse' if row['product'] != 'SomethingElse' else 'Other'
    with pytest.raises(vc.VaultCryptoError):
        vc.open_envelope(VECTORS['key'], row['token'], envelope_of(row), product=wrong)


def test_the_fixture_covers_a_non_ascii_value():
    """It has to survive UTF-8, base64, a varchar column, JSON and the trip
    back. An all-ASCII fixture would not notice an encoding fault anywhere
    along that path."""
    assert any(not row['value'].isascii() for row in VECTORS['rows'])


def test_the_fixture_matches_the_formats_this_build_produces():
    """A fixture generated under an older envelope or token version would
    pass every test above while pinning something nobody ships."""
    assert VECTORS['tokenVersion'] == core.TOKEN_VERSION
    assert VECTORS['envelopeVersion'] == vc.ENVELOPE_VERSION


def test_no_ciphertext_contains_its_plaintext():
    """The fixture is committed, so this is also a check that generating it
    never accidentally writes a real value into the repository."""
    for row in VECTORS['rows']:
        assert row['value'] not in row['ciphertext']
        assert row['value'] not in row['nonce']
