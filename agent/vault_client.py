"""The agent's client to the shared vault.

The agent is the only component that ever speaks to the vault. That was the
argument for it existing at all: one place holding the key, one credential,
and clients - the mod, the extension, the proxy - that authenticate to
loopback and nothing else.

    mod   --+
    ext   --+-> agent --TLS + bearer--> ai.example.com /api/vault
    proxy --+     seals, opens, verifies

WHAT THIS TRUSTS, AND WHAT IT DOES NOT

It trusts the server to store and return rows. It does not trust the server
to be right about them. Every value that comes back is opened under our own
key and then checked by re-deriving its token; anything that fails either
step is discarded and never reaches a caller. A compromised server can
therefore withhold mappings or serve garbage, but it cannot make the
browser display a value the key does not vouch for.

AUTHENTICATION

A personal API token, created by the user after signing in to ai.example.com
normally. Not an Entra client of our own: the server already resolves a
bearer token to the same claims and the same invited_users lookup the
browser uses, so removing someone from the access list stops their agent
too. The token is read from the environment and never written to a config
file, a log line or a tool argument.
"""

import json
import os
import urllib.error
import urllib.request

import vault_crypto as vc


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect, rather than following it.

    Found against the live server: an unauthenticated call to /api/vault
    answers 302 to the identity provider, because an unauthenticated caller
    is challenged and the challenge scheme is OpenID Connect. urllib follows
    redirects by default AND carries custom headers across hosts, so an
    agent whose token had expired would have sent
    `Authorization: Bearer aiplatform_pat_...` to login.microsoftonline.com.

    Nothing about that is hypothetical - it is what this client did until
    this handler existed. A redirect is never a valid answer to a JSON API
    call here, so treating one as an error loses nothing and closes the
    leak whatever the server does next.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)

USER_AGENT = 'claudefuscator-agent'
DEFAULT_TIMEOUT = 8
MAX_BATCH = 500             # matches the server's per-request cap


class VaultClient:
    """Resolve and submit against the shared vault. Fails soft, never raises
    at a caller: a vault that is down must degrade to red marks in the
    browser, not to a broken agent."""

    def __init__(self, base_url, token, secret, product=None, timeout=DEFAULT_TIMEOUT):
        self.base_url = (base_url or '').rstrip('/')
        self._token = token            # never logged, never echoed
        self.secret = secret
        self.product = product
        self.timeout = timeout
        self.last_error = None

    # ---- configuration -------------------------------------------------

    @classmethod
    def from_config(cls, config, secret):
        """Returns (client, status). client is None when not configured,
        which leaves the agent working exactly as it did before."""
        raw = (config or {}).get('vault')
        if not isinstance(raw, dict) or raw.get('enabled') is False:
            return None, 'not configured'

        url = (raw.get('url') or '').strip().rstrip('/')
        if not url:
            return None, 'no vault.url set'

        # Plain http would put the bearer token and the ciphertext on the
        # wire in clear. Loopback is allowed so the server can be exercised
        # locally; nothing else is.
        if not url.startswith('https://'):
            if not url.startswith(('http://127.0.0.1', 'http://localhost')):
                return None, f'vault.url must be https, refusing {url}'

        token = os.environ.get('CLAUDEFUSCATOR_VAULT_TOKEN', '').strip()
        if not token:
            # Deliberately not read from the config file: that file is
            # shared, diffed and sometimes pasted. A credential belongs in
            # the environment.
            return None, 'no CLAUDEFUSCATOR_VAULT_TOKEN set'

        return cls(url, token, secret, product=raw.get('product')), f'ACTIVE ({url})'

    # ---- transport -----------------------------------------------------

    def _post(self, path, payload):
        body = json.dumps(payload).encode('utf-8')
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            method='POST',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + self._token,
                'User-Agent': USER_AGENT,
            },
        )
        try:
            with _OPENER.open(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                # The sign-in redirect. Say what it means rather than
                # reporting a bare status nobody can act on.
                self.last_error = ('the vault did not accept the token - sign in '
                                   'to ai.example.com and create a new one')
                return None
            # Status only. The body of an error from an authenticated
            # endpoint can echo the request, and the request carries tokens.
            self.last_error = f'vault answered {e.code}'
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
            self.last_error = f'vault unreachable: {type(e).__name__}'
        return None

    # ---- api -----------------------------------------------------------

    def resolve(self, tokens):
        """token -> real value, for the rows this user may read and whose
        values the key vouches for. Unverifiable rows are dropped."""
        wanted = [t for t in tokens if isinstance(t, str) and t][:MAX_BATCH]
        if not wanted or not self.secret:
            return {}

        self.last_error = None
        reply = self._post('/api/vault/resolve', {'tokens': wanted})
        if not reply:
            return {}

        out = {}
        for row in reply.get('mappings') or []:
            if not isinstance(row, dict):
                continue
            token = row.get('token')
            if not isinstance(token, str):
                continue
            # These exact names are the cross-repo contract, and the two
            # sides are configured independently. They are pinned by
            # VaultEndpointTests.The_response_uses_the_field_names_the_agent_reads
            # in example/ai, which asserts them over real HTTP. Read them
            # plainly rather than guessing at casing: a silent fallback
            # would turn a broken contract into mappings that quietly stop
            # resolving, which is this tool's worst failure mode.
            envelope = {
                'v': row.get('envelopeVersion'),
                'n': row.get('nonce'),
                'ct': row.get('ciphertext'),
            }
            product = row.get('product')
            try:
                value = vc.open_envelope(self.secret, token, envelope, product=product)
            except vc.VaultCryptoError:
                # Wrong key, tampered row, or a row bound to another product.
                # Dropped rather than surfaced: an unopenable row is not a
                # value, and showing a placeholder would be worse than red.
                continue

            # Opening proves the row was written by someone holding the key.
            # It does NOT prove the value is the one the token stands for -
            # a writer with the key can seal a wrong value perfectly well.
            # Only this check refuses that.
            if not vc.verify_token(self.secret, token, value):
                continue

            out[token] = value

        return out

    def submit(self, pairs, product=None):
        """Seal and store token -> value pairs. Returns (added, conflicts)."""
        if not pairs or not self.secret:
            return 0, []

        chosen = product or self.product
        rows = []
        for token, value in list(pairs)[:MAX_BATCH]:
            if not isinstance(token, str) or not isinstance(value, str):
                continue
            # Never submit something our own key does not vouch for. A local
            # bug that recorded a wrong pair would otherwise propagate to
            # everyone, and write-once means it could not be corrected.
            if not vc.verify_token(self.secret, token, value):
                continue
            try:
                envelope = vc.seal(self.secret, token, value, product=chosen)
            except vc.VaultCryptoError:
                continue
            rows.append({
                'token': token,
                'tokenVersion': vc.core.TOKEN_VERSION,
                'product': chosen,
                'envelopeVersion': envelope['v'],
                'nonce': envelope['n'],
                'ciphertext': envelope['ct'],
            })

        if not rows:
            return 0, []

        self.last_error = None
        reply = self._post('/api/vault/mappings', {'mappings': rows})
        if not reply:
            return 0, []

        return int(reply.get('added') or 0), list(reply.get('conflicts') or [])
