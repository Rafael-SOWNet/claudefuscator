"""Tests for the vault's client-side encryption.

What is being defended here is a specific claim: a full compromise of the
host yields ciphertext, not the deanonymisation mapping. Most of these
assert that something FAILS - a row moved between products, a byte flipped,
a wrong key - because those failures are the claim.
"""

import base64
import json
import pathlib
import sys

import pytest

AGENT_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(AGENT_DIR))
sys.path.insert(0, str(AGENT_DIR.parent / 'proxy'))

import vault_crypto as vc                   # noqa: E402
import claudefuscator_core as core          # noqa: E402

KEY = 'vault-test-key'
TOKEN = 'IP_abc12345'
VALUE = '10.44.2.9'


# ---- the round trip ---------------------------------------------------

def test_a_sealed_value_opens_again():
    env = vc.seal(KEY, TOKEN, VALUE, product='acme')
    assert vc.open_envelope(KEY, TOKEN, env, product='acme') == VALUE


def test_the_plaintext_is_not_in_the_envelope():
    """The whole point: this is what the server stores."""
    env = vc.seal(KEY, TOKEN, VALUE, product='acme')
    blob = str(env)
    assert VALUE not in blob
    assert KEY not in blob
    raw = base64.b64decode(env['ct'])
    assert VALUE.encode() not in raw


def test_unicode_survives():
    env = vc.seal(KEY, 'PERSON_aaaa1111', 'Jan Müller — Řež')
    assert vc.open_envelope(KEY, 'PERSON_aaaa1111', env) == 'Jan Müller — Řež'


def test_the_same_value_seals_differently_every_time():
    """A fresh nonce per row, so equal values do not produce equal rows and
    the server cannot tell which mappings repeat."""
    a = vc.seal(KEY, TOKEN, VALUE)
    b = vc.seal(KEY, TOKEN, VALUE)
    assert a['n'] != b['n'] and a['ct'] != b['ct']
    assert vc.open_envelope(KEY, TOKEN, a) == vc.open_envelope(KEY, TOKEN, b) == VALUE


# ---- the refusals -----------------------------------------------------

def test_a_wrong_key_cannot_open_it():
    env = vc.seal(KEY, TOKEN, VALUE)
    with pytest.raises(vc.VaultCryptoError):
        vc.open_envelope('some-other-key', TOKEN, env)


def test_a_row_cannot_be_lifted_into_another_product():
    """The AAD binds the row to its product, so a server that moved rows
    between products would produce rows that simply do not decrypt."""
    env = vc.seal(KEY, TOKEN, VALUE, product='acme')
    with pytest.raises(vc.VaultCryptoError):
        vc.open_envelope(KEY, TOKEN, env, product='widget')


def test_a_row_cannot_be_replayed_under_another_token():
    env = vc.seal(KEY, TOKEN, VALUE, product='acme')
    with pytest.raises(vc.VaultCryptoError):
        vc.open_envelope(KEY, 'IP_99999999', env, product='acme')


def test_a_single_flipped_byte_is_detected():
    env = vc.seal(KEY, TOKEN, VALUE)
    raw = bytearray(base64.b64decode(env['ct']))
    raw[0] ^= 0x01
    env['ct'] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(vc.VaultCryptoError):
        vc.open_envelope(KEY, TOKEN, env)


def test_a_malformed_envelope_raises_rather_than_returning_junk():
    for bad in [None, {}, {'v': 1}, {'v': 99, 'n': 'x', 'ct': 'y'},
                {'v': 1, 'n': '!!!', 'ct': '!!!'}]:
        with pytest.raises(vc.VaultCryptoError):
            vc.open_envelope(KEY, TOKEN, bad)


def test_the_envelope_records_its_version():
    """A rotation to another construction must be distinguishable, not
    silently misread as this one."""
    assert vc.seal(KEY, TOKEN, VALUE)['v'] == vc.ENVELOPE_VERSION


# ---- key separation ---------------------------------------------------

def test_the_vault_key_is_not_the_claudefuscator_key():
    """The thing that encrypts values must not be the same bytes as the
    thing that derives tokens."""
    derived = vc.value_key(KEY)
    assert derived != KEY.encode()
    assert len(derived) == vc.KEY_BYTES


def test_the_vault_key_is_deterministic():
    """Every client must derive the same one, or nobody reads anyone's rows."""
    assert vc.value_key(KEY) == vc.value_key(KEY)
    assert vc.value_key(KEY) != vc.value_key(KEY + 'x')


# ---- the reader's integrity check -------------------------------------

def test_verify_token_accepts_a_genuine_pair():
    token = core.derive_token(KEY, 'IP', VALUE, 8)
    assert vc.verify_token(KEY, token, VALUE)


def test_verify_token_rejects_a_poisoned_pair():
    """The vault cannot check its own rows, so every reader does. This is
    what stops a compromised writer making anyone display a value the key
    does not vouch for."""
    token = core.derive_token(KEY, 'IP', VALUE, 8)
    assert not vc.verify_token(KEY, token, 'attacker.example')
    assert not vc.verify_token('another-key', token, VALUE)
    assert not vc.verify_token(KEY, 'not-a-token', VALUE)


def test_a_sealed_row_that_opens_can_still_fail_verification():
    """Encryption and vouching are different questions. A writer holding the
    key can seal a wrong value perfectly well; only the token check catches
    it, which is why readers must do both."""
    token = core.derive_token(KEY, 'IP', VALUE, 8)
    env = vc.seal(KEY, token, 'attacker.example')
    opened = vc.open_envelope(KEY, token, env)
    assert opened == 'attacker.example'          # decrypts fine
    assert not vc.verify_token(KEY, token, opened)   # and is still refused


# --- enrolment: the key, wrapped under an API token --------------------
#
# This is the one place the key is stored anywhere but an endpoint, so what
# matters is exactly how much that costs. The wrapping makes a database
# dump useless; it does not make a live host compromise harmless, and no
# test here should be read as claiming it does.

ENROL_TOKEN = 'reference-api-token-not-a-real-one'
ENROL_KEY = 'enrolment-test-key'


def test_the_wrapped_key_does_not_contain_the_key():
    wrapped = vc.wrap_key(ENROL_KEY, ENROL_TOKEN)
    blob = base64.b64decode(wrapped['ct'])
    assert ENROL_KEY.encode() not in blob
    assert ENROL_KEY not in json.dumps(wrapped)


def test_the_right_token_unwraps_it():
    assert vc.unwrap_key(vc.wrap_key(ENROL_KEY, ENROL_TOKEN), ENROL_TOKEN) == ENROL_KEY


def test_a_wrong_token_cannot_unwrap_it():
    wrapped = vc.wrap_key(ENROL_KEY, ENROL_TOKEN)
    # One character. Anything less strict and a near-miss token would
    # produce a near-miss key, which derives wrong tokens and silently
    # unveils nothing.
    with pytest.raises(vc.VaultCryptoError):
        vc.unwrap_key(wrapped, ENROL_TOKEN[:-1] + 'X')


def test_an_empty_token_is_refused_rather_than_treated_as_a_token():
    with pytest.raises(vc.VaultCryptoError):
        vc.unwrap_key(vc.wrap_key(ENROL_KEY, ENROL_TOKEN), '')


def test_wrapping_the_same_key_twice_differs():
    # Fresh nonce each time, so two people enrolling the same key do not
    # produce the same blob and reveal that they share one.
    a = vc.wrap_key(ENROL_KEY, ENROL_TOKEN)
    b = vc.wrap_key(ENROL_KEY, ENROL_TOKEN)
    assert a['ct'] != b['ct']
    assert a['n'] != b['n']


def test_a_flipped_byte_in_the_wrapping_is_detected():
    wrapped = vc.wrap_key(ENROL_KEY, ENROL_TOKEN)
    raw = bytearray(base64.b64decode(wrapped['ct']))
    raw[0] ^= 0x01
    wrapped['ct'] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(vc.VaultCryptoError):
        vc.unwrap_key(wrapped, ENROL_TOKEN)


def test_the_enrolment_wrapping_is_not_the_value_wrapping():
    # Different HKDF info, so a blob from one context cannot be replayed
    # into the other even by someone holding both secrets.
    wrapped = vc.wrap_key(ENROL_KEY, ENROL_TOKEN)
    with pytest.raises(vc.VaultCryptoError):
        vc.open_envelope(ENROL_TOKEN, 'HOST_whatever', wrapped)
