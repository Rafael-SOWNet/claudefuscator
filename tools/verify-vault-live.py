"""Verify the whole chain against the LIVE vault.

Run this from a shell that already has the credential:

    export CLAUDEFUSCATOR_VAULT_TOKEN=aiplatform_pat_...
    python tools/verify-vault-live.py

It is the one path no test can cover, because every test stands in for the
server. Here the server is real: a value is sealed on this machine, pushed
over TLS to ai.example.com, read back out of Postgres, decrypted, and checked
against the key.

It writes ONE row, under a key used for nothing else and an invented value,
so nothing real enters the vault. The row is left in place and named so it
is obvious what it is; delete it afterwards with:

    DELETE FROM vault_mappings WHERE token LIKE 'HOST_%' AND token_version
      = 'claudefuscator/v1' AND created_at > now() - interval '1 hour';

The token is read from the environment and never printed.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'proxy'))
sys.path.insert(0, os.path.join(ROOT, 'agent'))

import claudefuscator_core as core          # noqa: E402
import vault_crypto as vc                   # noqa: E402
from vault_client import VaultClient        # noqa: E402

URL = os.environ.get('CLAUDEFUSCATOR_VAULT_URL', 'https://ai.example.com')

# A key for this check and nothing else, and an invented value. A real
# identifier written into the shared vault by a smoke test would be a real
# identifier in the shared vault forever - writes are write-once.
KEY = 'live-verification-key-2026-10-03'
VALUE = 'verify-01.corp.example'

results = []


def check(name, ok, detail=''):
    results.append(ok)
    print(('  PASS  ' if ok else '  FAIL  ') + name + (('\n          ' + detail) if detail and not ok else ''))


def main():
    if not os.environ.get('CLAUDEFUSCATOR_VAULT_TOKEN', '').strip():
        print('CLAUDEFUSCATOR_VAULT_TOKEN is not set in this shell.')
        return 2

    print(f'vault  : {URL}')
    token = core.derive_token(KEY, 'HOST', VALUE, 8)
    print(f'token  : {token}\n')

    client, status = VaultClient.from_config({'vault': {'url': URL}}, KEY)
    check('client configured', client is not None, status)
    if client is None:
        return 1

    # 1. The credential is accepted at all. This is the step that proves the
    #    personal API token path works end to end - Entra sign-in, the token
    #    the UI issued, invited_users, roles - without the agent knowing
    #    anything about any of it.
    before = client.resolve([token])
    check('the vault accepted the credential',
          client.last_error is None,
          str(client.last_error))
    if client.last_error:
        return 1

    check('the token is not already present', before == {},
          f'already resolved to something: {list(before)}')

    # 2. Seal here, store there. The server never sees the value.
    added, conflicts = client.submit([(token, VALUE)])
    check('a sealed row was accepted', added == 1,
          f'added={added} conflicts={conflicts} err={client.last_error}')

    # 3. Read it back out of a real database, decrypt, and verify.
    got = client.resolve([token])
    check('the row came back and decrypted', got.get(token) == VALUE,
          f'got {got!r}')

    # 4. The check that matters most: decryption alone proves only that
    #    someone holding the key wrote it. Only re-deriving the token from
    #    the value proves the value is the one the token stands for.
    check('the returned value hashes back to its token',
          vc.verify_token(KEY, token, got.get(token, '')))

    # 5. Write-once, enforced by the database, not just by the store.
    again, conflicts2 = client.submit([(token, VALUE)])
    check('a second write is refused as a conflict',
          again == 0 and token in conflicts2,
          f'added={again} conflicts={conflicts2}')

    # 6. A different key must not be able to read it. Same row, same
    #    credential, wrong key: the server hands over the ciphertext and the
    #    client refuses it, which is the whole point of the design.
    other = VaultClient(URL, os.environ['CLAUDEFUSCATOR_VAULT_TOKEN'],
                        'a-completely-different-key')
    check('another key cannot read the row', other.resolve([token]) == {})

    print()
    passed = sum(1 for r in results if r)
    print(f'{passed}/{len(results)} checks passed')
    print(f'\nLeft one row in the vault: {token}')
    print('Delete it when you are done - see the docstring.')
    return 0 if passed == len(results) else 1


if __name__ == '__main__':
    sys.exit(main())
