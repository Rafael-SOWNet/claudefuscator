"""Claudefuscator core - Python port of shared/claudefuscator-core.js.

This is a SECOND IMPLEMENTATION of a wire format, which is a drift risk. The
guard is shared/test-vectors.json: a fixed key and value set with the expected
token for each, asserted by both the JS suite (test/vectors.test.js) and the
Python suite (proxy/tests/test_parity.py). If you change derivation here
without changing the JS, parity tests fail on both sides.

Everything that affects a derived token - normalisation, the HMAC message
layout, the token shape, the regex boundaries - must match the JS byte for
byte in behaviour. Comments marked PARITY mark those places.
"""

import hashlib
import hmac
import re
import unicodedata

TOKEN_VERSION = 'claudefuscator/v1'   # PARITY: same literal as the JS
DEFAULT_TOKEN_LENGTH = 8

# PARITY: match boundaries. `.` is deliberately NOT in the character class;
# the dotted-context lookarounds handle it, so a value at the end of a
# sentence still matches while `corp.example` does not match inside
# `build-01.corp.example`.
_BOUNDARY = '[A-Za-z0-9_%+@-]'
LEFT = '(?<!' + _BOUNDARY + r')(?<![A-Za-z0-9]\.)'
RIGHT = '(?!' + _BOUNDARY + r')(?!\.[A-Za-z0-9])'


def escape_regex(s):
    return re.escape(str(s))


def normalise(value):
    """PARITY: JS does String(v).normalize('NFKC').trim().toLowerCase().

    Python's str.strip() and JS's String.trim() differ on exotic whitespace,
    and str.lower() differs from JS toLowerCase() on a few locale-independent
    edge cases (notably the Turkish dotted I is the same in both, but
    U+0130 lowercases to a two-character sequence in Python and in JS alike).
    For the ASCII-plus-Latin-1 identifiers this tool targets they agree; the
    test vectors include non-ASCII cases to keep that honest.
    """
    return unicodedata.normalize('NFKC', str(value)).strip().lower()


def hmac_hex(secret, message):
    return hmac.new(
        secret.encode('utf-8'), message.encode('utf-8'), hashlib.sha256
    ).hexdigest()


def derive_token(secret, type_, value, token_length=DEFAULT_TOKEN_LENGTH, case_sensitive=False):
    """PARITY: TYPE_<n hex of HMAC-SHA256(key, "claudefuscator/v1/TYPE/subject")>.

    Case-sensitive entries hash the EXACT spelling, so `Acme` and `ACME`
    get different tokens and each restores to itself. Required for code: a
    case-folding round trip turns ACME_TIMEOUT into Acme_TIMEOUT, a
    different symbol, silently breaking the file.
    """
    t = re.sub(r'[^A-Z0-9]', '', str(type_ or 'OTHER').upper())
    subject = ('cs:' + str(value).strip()) if case_sensitive else normalise(value)
    digest = hmac_hex(secret, TOKEN_VERSION + '/' + t + '/' + subject)
    return t + '_' + digest[:token_length or DEFAULT_TOKEN_LENGTH]


def is_private_ipv4(text):
    """PARITY: RFC1918 + CGNAT + link-local only. Public, loopback, 0.0.0.0
    and broadcast are deliberately left alone."""
    parts = str(text).split('.')
    if len(parts) != 4:
        return False
    nums = []
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255:
            return False
        nums.append(n)
    a, b = nums[0], nums[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    if a == 169 and b == 254:
        return True
    return False


def _builtin_patterns(config):
    on = {'email': True, 'privateIp': True, 'mac': True, 'internalHost': True}
    on.update(config.get('patterns') or {})
    out = []

    if on.get('email'):
        out.append({
            'name': 'email',
            'type': 'EMAIL',
            'source': LEFT + r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}' + RIGHT,
            'guard': None,
        })

    if on.get('privateIp'):
        out.append({
            'name': 'privateIp',
            'type': 'IP',
            'source': r'(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9])(?!\.[0-9])',
            'guard': is_private_ipv4,
        })

    if on.get('mac'):
        out.append({
            'name': 'mac',
            'type': 'MAC',
            'source': r'(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])',
            'guard': None,
        })

    domains = [d for d in (config.get('internalDomains') or []) if d]
    if on.get('internalHost') and domains:
        alt = '|'.join(escape_regex(d) for d in domains)
        label = r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?'
        out.append({
            'name': 'internalHost',
            'type': 'HOST',
            'source': LEFT + label + r'(?:\.' + label + r')*\.(?:' + alt + ')' + RIGHT,
            'guard': None,
        })

    return out


class CollisionError(ValueError):
    pass


class Vault:
    """Everything needed to scrub and restore, derived from (secret, config)."""

    def __init__(self, secret, config):
        if not secret:
            raise ValueError('Claudefuscator: no key supplied')
        cfg = config or {}
        self.secret = secret
        self.token_length = cfg.get('tokenLength') or DEFAULT_TOKEN_LENGTH
        self.token_to_value = {}
        self.literal_to_token = {}
        self.compound_literals = set()
        self.compound_tokens = set()
        self.case_sensitive_literals = set()
        self.discovered = {}

        collisions = []
        for item in cfg.get('identifiers') or []:
            if not item or not item.get('value'):
                continue
            type_ = str(item.get('type') or 'OTHER').upper()
            spellings = [x for x in [item['value']] + list(item.get('aliases') or []) if x]

            # PARITY: `compound` implies case-sensitive, and each spelling keeps
            # its OWN token instead of collapsing onto the canonical one.
            # Aliases exist to make several spellings mean one thing, which is
            # right for a person's name and wrong for a symbol.
            case_sensitive = item.get('compound') is True or item.get('caseSensitive') is True

            for spelling in (spellings if case_sensitive else [item['value']]):
                token = derive_token(self.secret, type_, spelling, self.token_length, case_sensitive)
                existing = self.token_to_value.get(token)
                if existing is not None and existing != spelling:
                    collisions.append((token, existing, spelling))
                    continue
                self.token_to_value[token] = spelling
                self.literal_to_token[str(spelling)] = token
                if case_sensitive:
                    self.case_sensitive_literals.add(str(spelling))
                if item.get('compound'):
                    self.compound_literals.add(str(spelling))
                    self.compound_tokens.add(token)

            if not case_sensitive:
                token = self.literal_to_token.get(item['value'])
                for alias in spellings[1:]:
                    self.literal_to_token[str(alias)] = token

        # PARITY: a truncated-HMAC collision makes restore ambiguous, so it is
        # a hard error on both sides, not a warning.
        if collisions:
            detail = '; '.join(f'{t} <- {a} , {b}' for t, a, b in collisions)
            raise CollisionError(
                f'Claudefuscator: token collision at tokenLength={self.token_length}: '
                f'{detail}. Raise tokenLength in your config (both sides).'
            )

        # PARITY: allow-list wins over everything, pattern or literal. The
        # safety valve for an over-broad personal filter - a short acronym or a
        # harvested term that collides with an ordinary Dutch or English word.
        self.allow = set()
        for word in cfg.get('allowList') or []:
            if word:
                self.allow.add(normalise(word))

        self.patterns = _builtin_patterns(cfg)
        self._compile()

    def _compile(self):
        """PARITY: one combined regex, one pass, literals first and sorted
        longest-first so a configured literal beats the generic patterns and
        a longer literal beats a shorter overlapping one."""
        alternatives = []
        literals = sorted(self.literal_to_token.keys(), key=lambda s: (-len(s), s))
        for literal in literals:
            # PARITY: `compound` literals also match inside a code identifier,
            # so `Acme` hits in `AcmeClient`. Renames a LABEL inside code;
            # does not hide what the code does - see CLAUDE.md.
            is_compound = literal in self.compound_literals
            alternatives.append({
                'kind': 'literal',
                'literal': literal,
                'caseSensitive': literal in self.case_sensitive_literals,
                'source': escape_regex(literal) if is_compound
                          else LEFT + escape_regex(literal) + RIGHT,
            })
        for p in self.patterns:
            alternatives.append({
                'kind': 'pattern',
                'type': p['type'],
                'name': p['name'],
                'guard': p['guard'],
                'source': p['source'],
            })

        self.alternatives = alternatives

        # PARITY: the same patterns again, anchorable at one position, so
        # scrub can ask whether a literal that won a position is only a
        # FRAGMENT of a longer pattern match starting in the same place.
        self.pattern_probes = [
            {'alt': {'kind': 'pattern', 'type': p['type'], 'name': p['name'],
                     'guard': p['guard']},
             're': re.compile(p['source'], re.IGNORECASE)}
            for p in self.patterns
        ]
        self.scrub_re = (
            re.compile('|'.join('(' + a['source'] + ')' for a in alternatives), re.IGNORECASE)
            if alternatives else None
        )
        self._rebuild_restore()

    def _rebuild_restore(self):
        all_tokens = sorted(
            list(self.token_to_value.keys()) + list(self.discovered.keys()),
            key=lambda s: -len(s),
        )
        # PARITY: two boundary rules.
        #   strict   - token must stand alone, so MAX_deadbeef is never
        #              rewritten and nothing we did not generate is restored.
        #   compound - legitimately glued to other identifier characters
        #              (ORG_81da0267Client); no left boundary and only a
        #              not-a-hex-digit right boundary, which still prevents
        #              matching a PREFIX of a longer token.
        compound = [escape_regex(t) for t in all_tokens if t in self.compound_tokens]
        strict = [escape_regex(t) for t in all_tokens if t not in self.compound_tokens]
        parts = []
        if strict:
            parts.append(r'(?<![A-Za-z0-9_])(?:' + '|'.join(strict) + r')(?![A-Za-z0-9_])')
        if compound:
            parts.append(r'(?:' + '|'.join(compound) + r')(?![0-9a-f])')
        self.restore_re = re.compile('|'.join(parts)) if parts else None

    def scrub(self, text):
        """Real values -> tokens. Returns (text, hits). Hits carry token/type
        only, never the real value, so they are safe to log."""
        src = '' if text is None else str(text)
        if not self.scrub_re or not src:
            return src, []

        hits = []
        pieces = []
        cursor = 0
        pos = 0

        while True:
            m = self.scrub_re.search(src, pos)
            if m is None:
                break
            if m.group(0) == '':
                pos = m.start() + 1
                continue
            if m.start() < cursor:
                pos = cursor
                continue

            group_index = m.lastindex
            if not group_index:
                pos = m.start() + 1
                continue
            alt = self.alternatives[group_index - 1]

            # PARITY: every candidate starting HERE, longest first.
            #
            # Alternation order alone is not enough. Literals come first so a
            # listed value gets its list token - the only kind the Chrome side
            # can restore. But a `compound` literal drops the word boundary to
            # match inside a symbol name, and that let a short literal win a
            # position where a longer pattern also started: `Acme` beat the
            # email pattern in `Acme@partner.example` and sent the domain
            # upstream in clear, and a case-sensitive literal that then failed
            # its exact-case check consumed the position and leaked the whole
            # address. Longest wins; a literal wins a tie.
            candidates = [{'alt': alt, 'text': m.group(0)}]
            for probe in self.pattern_probes:
                pm = probe['re'].match(src, m.start())
                if pm and pm.group(0) and len(pm.group(0)) > len(m.group(0)):
                    candidates.append({'alt': probe['alt'], 'text': pm.group(0)})
            candidates.sort(
                key=lambda c: (-len(c['text']), 0 if c['alt']['kind'] == 'literal' else 1))

            token = None
            type_ = None
            chosen = None
            for candidate in candidates:
                resolved = self._resolve_candidate(candidate)
                if resolved:
                    token, type_ = resolved
                    chosen = candidate
                    break

            if not token:
                # PARITY: resume one character along, not past the rejected
                # text, or a value starting inside it is lost.
                pos = m.start() + 1
                continue

            pieces.append(src[cursor:m.start()])
            pieces.append(token)
            cursor = m.start() + len(chosen['text'])
            pos = cursor
            hits.append({
                'token': token,
                'type': type_,
                'source': 'list' if chosen['alt']['kind'] == 'literal' else chosen['alt']['name'],
            })

        pieces.append(src[cursor:])
        return ''.join(pieces), hits

    def _resolve_candidate(self, candidate):
        """One candidate to (token, type), or None when it must not be
        tokenized. PARITY with resolveCandidate in the JavaScript core."""
        alt = candidate['alt']
        text = candidate['text']

        # PARITY: allow-list wins over everything, pattern or literal.
        if normalise(text) in self.allow:
            return None

        if alt['kind'] == 'literal':
            # PARITY: resolve exact case by the TEXT THAT MATCHED, not by the
            # alternative that won the position - otherwise a sibling spelling
            # sorting first would drop the match entirely.
            if alt.get('caseSensitive'):
                if text not in self.case_sensitive_literals:
                    return None
                token = self.literal_to_token.get(text)
            else:
                token = self.literal_to_token.get(alt['literal'])
            return (token, token.split('_')[0]) if token else None

        if alt['guard'] and not alt['guard'](text):
            return None
        token = derive_token(self.secret, alt['type'], text, self.token_length)
        if token not in self.discovered:
            self.discovered[token] = text
            self._rebuild_restore()
        return token, alt['type']

    def restore(self, text):
        """Tokens -> real values. Pure substitution over the known token set."""
        src = '' if text is None else str(text)
        if not self.restore_re or not src:
            return src

        def sub(m):
            tok = m.group(0)
            if tok in self.token_to_value:
                return self.token_to_value[tok]
            if tok in self.discovered:
                return self.discovered[tok]
            return tok

        return self.restore_re.sub(sub, src)


def map_strings(value, fn):
    """Walk a JSON-ish value, applying fn to every string leaf and keeping the
    shape. PARITY with the JS mapStrings."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [map_strings(v, fn) for v in value]
    if isinstance(value, dict):
        return {k: map_strings(v, fn) for k, v in value.items()}
    return value


def build_vault(secret, config):
    return Vault(secret, config)


# ---- credentials -----------------------------------------------------
#
# PARITY with findSecrets/describeSecrets in the JS core.
#
# Found and REPORTED, never tokenized. A token round-trips, which is the
# point for a name and a disaster for a credential: restore would put the
# live secret back into tool calls that write to disk. Handling them also
# invites pasting them, and a missed prefix then sends the secret up in
# the clear - silently, and far more expensively than a missed name.
#
# No finding ever carries the value. Findings reach logs and status
# lines, so the thing found must not travel with them.
SECRET_PATTERNS = [
    # Longest and most specific first: sk-ant- would otherwise be
    # reported as the generic sk- family, naming the wrong vendor.
    ('anthropic-api-key', re.compile(r'\bsk-ant-[A-Za-z0-9_-]{20,}')),
    ('openai-api-key', re.compile(r'\bsk-[A-Za-z0-9]{32,}')),
    ('github-pat', re.compile(r'\bgithub_pat_[A-Za-z0-9_]{22,}')),
    ('github-token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}')),
    ('gitlab-pat', re.compile(r'\bglpat-[A-Za-z0-9_-]{20,}')),
    ('slack-token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}')),
    ('aws-access-key-id',
     re.compile(r'\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b')),
    ('google-api-key', re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')),
    ('npm-token', re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')),
    ('huggingface-token', re.compile(r'\bhf_[A-Za-z0-9]{34,}')),
    ('digitalocean-token', re.compile(r'\bdop_v1_[a-f0-9]{64}\b')),
    ('sendgrid-key', re.compile(r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b')),
    ('pypi-token', re.compile(r'\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}')),
    ('private-key-block', re.compile(r'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----')),
    ('json-web-token',
     re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')),
]


def find_secrets(text):
    """Every credential-shaped thing in `text`.

    Returns [{'name', 'index', 'length'}] - the family, where it starts,
    and how long it is. Never the value.
    """
    subject = text if isinstance(text, str) else ''
    if not subject:
        return []

    found = []
    claimed = []

    for name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(subject):
            if not m.group(0):
                continue
            start, end = m.start(), m.end()
            # One finding per span, or a PAT is counted by two families
            # and a count of findings stops meaning a count of secrets.
            if any(start < c_end and end > c_start for c_start, c_end in claimed):
                continue
            claimed.append((start, end))
            found.append({'name': name, 'index': start, 'length': end - start})

    return sorted(found, key=lambda f: f['index'])


def describe_secrets(findings):
    """A one-line summary: which families, how many of each."""
    counts = {}
    for f in findings or []:
        counts[f['name']] = counts.get(f['name'], 0) + 1
    return ', '.join(f'{n} x{c}' if c > 1 else n for n, c in counts.items())
