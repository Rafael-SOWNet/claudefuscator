"""Client-side encryption for the shared vault.

The vault stores rows the host cannot read. The key lives on employees'
machines and is never given to the server, so a full compromise of the host
yields ciphertext rather than the deanonymisation mapping. That is the
property that makes putting the vault next to the AI corpus defensible, and
everything in this file exists to hold it up.

    valueKey   = HKDF-SHA256(key, info = "claudefuscator/vault/v1")
    ciphertext = AES-256-GCM(valueKey, value, aad = version | product | token)
    stored     = token -> {v, n, ct}        <- all the server ever sees

WHY AES-GCM FROM `cryptography` AND NOT SOMETHING HAND-ROLLED

The core's HMAC has a hand-written fallback because the mod's sandbox has no
usable WebCrypto and HMAC is ~80 lines verifiable against RFC 4231. An AEAD
is a different proposition, and this file does not have the mod's excuse:
the agent is ordinary Python. So it uses a reviewed implementation, and the
mod never encrypts at all - it hands values to the agent, which does.

WHAT THE AAD IS FOR

The additional data binds each row to the token, the product and the token
version it was written under. None of it is secret - the point is that a row
cannot be lifted into another product, replayed under a different token, or
carried across a key rotation without the open failing. Without it, a server
that can reorder rows could make a mapping mean something else; with it,
such a row simply fails to decrypt.

WHAT THIS DOES NOT PROTECT, SAID PLAINLY

Metadata is in the clear: row count, which product holds how many, when they
were written and by whom, and each token's TYPE prefix and frequency. An
attacker learns you have 412 customer names even if they learn no name.
Encryption is also not access control - invited_users, roles and product
grants still do that work - and the key is on the endpoint, so a compromised
client is a compromised mapping.
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import claudefuscator_core as core

VAULT_VERSION = 'claudefuscator/vault/v1'
ENVELOPE_VERSION = 1
NONCE_BYTES = 12            # 96 bits, the size AES-GCM is specified for
KEY_BYTES = 32              # AES-256


class VaultCryptoError(Exception):
    """A value could not be sealed or opened. Never carries the plaintext."""


def value_key(secret):
    """Derive the vault's encryption key from the Claudefuscator key.

    A separate derivation rather than the key itself, so the thing that
    encrypts values is not the same bytes as the thing that derives tokens.
    No salt: there is one key per organisation and the info string already
    separates this use from every other.
    """
    if not secret:
        raise VaultCryptoError('no key')
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=None,
        info=VAULT_VERSION.encode('utf-8'),
    ).derive(secret.encode('utf-8') if isinstance(secret, str) else secret)


def _aad(token, product):
    """version | product | token, unambiguously.

    Length-prefixed rather than joined with a separator: a product named
    `a|b` must not be able to produce the same AAD as some other pairing.
    """
    parts = [core.TOKEN_VERSION, product or '', token]
    out = bytearray()
    for p in parts:
        b = p.encode('utf-8')
        out += len(b).to_bytes(4, 'big') + b
    return bytes(out)


def seal(secret, token, value, product=None):
    """value -> the envelope the server stores. Never reversible by it."""
    if not isinstance(token, str) or not token:
        raise VaultCryptoError('a row must have a token')
    if not isinstance(value, str):
        raise VaultCryptoError('a row must have a string value')
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(value_key(secret)).encrypt(
        nonce, value.encode('utf-8'), _aad(token, product))
    return {
        'v': ENVELOPE_VERSION,
        'n': base64.b64encode(nonce).decode('ascii'),
        'ct': base64.b64encode(ct).decode('ascii'),
    }


def open_envelope(secret, token, envelope, product=None):
    """The envelope back to the value, or VaultCryptoError.

    Fails rather than guesses. A row written under another product, another
    token or another token version does not decrypt, and neither does one
    that has been altered by a byte.
    """
    if not isinstance(envelope, dict):
        raise VaultCryptoError('not an envelope')
    if envelope.get('v') != ENVELOPE_VERSION:
        raise VaultCryptoError(f'unsupported envelope version {envelope.get("v")!r}')
    try:
        nonce = base64.b64decode(envelope['n'], validate=True)
        ct = base64.b64decode(envelope['ct'], validate=True)
    except (KeyError, ValueError, TypeError) as e:
        raise VaultCryptoError(f'malformed envelope: {e}') from None
    try:
        plain = AESGCM(value_key(secret)).decrypt(nonce, ct, _aad(token, product))
    except InvalidTag:
        raise VaultCryptoError('the row does not authenticate under this key, '
                               'token, product and token version') from None
    try:
        return plain.decode('utf-8')
    except UnicodeDecodeError:
        raise VaultCryptoError('the row did not decode as text') from None


def verify_token(secret, token, value, token_length=None):
    """Does this value actually hash back to this token?

    The vault cannot check its own rows - checking needs the key - so every
    reader does it instead. This is the same check the Chrome extension
    performs on what the agent tells it, and it is what keeps a compromised
    or buggy writer from making anyone display a value the key does not
    vouch for.
    """
    if not isinstance(token, str) or '_' not in token:
        return False
    type_ = token.split('_', 1)[0]
    length = token_length or (len(token) - len(type_) - 1)
    try:
        return core.derive_token(secret, type_, value, length) == token
    except Exception:
        return False
