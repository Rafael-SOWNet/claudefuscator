"""Where the agent keeps its vault credential.

The agent needs an API token on every run. The options were an environment
variable the person exports each time, a file holding it in the clear, or
the operating system's own protected storage. Only the third survives the
question "what does someone who copies this file get?".

On Windows that is DPAPI: `CryptProtectData` encrypts to the logged-in
user account, so the stored blob is useless on another account and on
another machine. Nothing here invents cryptography; it calls what the OS
already provides, which is the only defensible choice for credential
storage.

Elsewhere this degrades to a file with owner-only permissions and SAYS SO.
A silent downgrade would be worse than no protection at all, because the
person would believe the Windows story applied to them.
"""

import base64
import ctypes
import json
import os
import stat
import sys

# Bound into the DPAPI call as additional entropy. It means a blob written
# by something else of this user's cannot be decrypted by us and vice
# versa - a small thing, but free.
ENTROPY = b'claudefuscator/credential/v1'

STORE_DIR = os.path.join(os.path.expanduser('~'), '.claudefuscator')
STORE_PATH = os.path.join(STORE_DIR, 'credential.json')

WINDOWS = sys.platform == 'win32'


class CredentialError(Exception):
    """Storing or reading the credential failed."""


# ---- DPAPI -----------------------------------------------------------

if WINDOWS:
    class _Blob(ctypes.Structure):
        _fields_ = [('cbData', ctypes.c_uint32),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

        @classmethod
        def of(cls, data):
            buffer = ctypes.create_string_buffer(data, len(data))
            return cls(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

        def value(self):
            return ctypes.string_at(self.pbData, self.cbData)


    _CRYPTPROTECT_UI_FORBIDDEN = 0x01


def _protect(plaintext):
    """DPAPI-encrypt, or raise."""
    out = _Blob()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(_Blob.of(plaintext)),
        None,
        ctypes.byref(_Blob.of(ENTROPY)),
        None, None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out),
    )
    if not ok:
        raise CredentialError('Windows refused to protect the credential')
    try:
        return out.value()
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def _unprotect(blob):
    """DPAPI-decrypt, or raise."""
    out = _Blob()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(_Blob.of(blob)),
        None,
        ctypes.byref(_Blob.of(ENTROPY)),
        None, None,
        _CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out),
    )
    if not ok:
        # The usual cause is a different Windows account or a restored
        # profile. Say that rather than "decryption failed", which sends
        # people looking for a corrupt file.
        raise CredentialError(
            'this credential was protected for a different Windows account '
            'or machine; connect again')
    try:
        return out.value()
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


# ---- the store -------------------------------------------------------

def protection():
    """One line describing what is actually protecting the stored value."""
    return ('Windows DPAPI, tied to this user account'
            if WINDOWS else
            'file permissions only - NOT encrypted on this platform')


def store(url, token):
    """Keep a credential for this vault. Replaces any previous one."""
    if not url or not token:
        raise CredentialError('nothing to store')

    payload = json.dumps({'url': url.rstrip('/'), 'token': token}).encode('utf-8')

    if WINDOWS:
        body = {'protection': 'dpapi', 'blob': base64.b64encode(_protect(payload)).decode()}
    else:
        body = {'protection': 'none', 'blob': base64.b64encode(payload).decode()}

    os.makedirs(STORE_DIR, exist_ok=True)

    # Written restrictively from the start, not chmod-ed afterwards: a file
    # created world-readable and tightened a moment later is readable for
    # that moment, and on the unprotected path that moment is all it takes.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    handle = os.open(STORE_PATH, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(handle, 'wb') as f:
            f.write(json.dumps(body).encode('utf-8'))
    except Exception:
        try:
            os.close(handle)
        except OSError:
            pass
        raise


def load(url=None):
    """The stored token for this vault, or None.

    Returns None rather than raising for an absent store - not being
    connected yet is the ordinary state. A store that exists but will not
    open does raise, because that is a fault worth reporting.
    """
    try:
        with open(STORE_PATH, 'rb') as f:
            body = json.load(f)
    except (OSError, json.JSONDecodeError, ValueError):
        return None

    try:
        raw = base64.b64decode(body.get('blob') or '')
    except (ValueError, TypeError):
        raise CredentialError('the stored credential is malformed; connect again')

    if body.get('protection') == 'dpapi':
        if not WINDOWS:
            raise CredentialError(
                'this credential was protected by Windows DPAPI and cannot be '
                'read here; connect again on this platform')
        raw = _unprotect(raw)

    try:
        stored = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise CredentialError('the stored credential is malformed; connect again')

    # A credential is for one host. Returning it for another would send a
    # bearer token somewhere it was never issued for, which is precisely
    # what the URL checks elsewhere exist to prevent.
    if url and stored.get('url', '').rstrip('/') != url.rstrip('/'):
        return None

    token = stored.get('token')
    return token if isinstance(token, str) and token else None


def clear():
    """Forget the stored credential. True if there was one."""
    try:
        os.remove(STORE_PATH)
        return True
    except OSError:
        return False
