"""Python mirror of shared/config-merge.js.

Resolves the layered config (packs + project identifiers) into one flat list.
Merge order is part of the wire contract: if the proxy and the Chrome
extension end up with different flat lists, tokens diverge and restore
silently stops working. Parity is asserted by proxy/tests/test_merge_parity.py
against the same fixtures test/merge.test.js uses.

Rule, deliberately boring: concatenate packs in listed order, then the
project's own identifiers last; for a repeated normalised value the LAST
entry wins.
"""

import json
import os
import unicodedata

MAX_PACK_DEPTH = 5


def _norm_key(value):
    return unicodedata.normalize('NFKC', str(value)).strip().lower()


def merge_config(config, load_pack, source='config'):
    """load_pack(ref, origin) -> {'config': {...}, 'source': str} or None."""
    warnings = []
    seen = {}
    merged = []
    loaded_packs = []

    def add_all(identifiers, origin):
        for item in identifiers or []:
            if not item or not item.get('value'):
                continue
            entry = {
                'type': str(item.get('type') or 'OTHER').upper(),
                'value': item['value'],
            }
            if item.get('aliases'):
                entry['aliases'] = list(item['aliases'])
            # These change how the entry is MATCHED and TOKENIZED; dropping
            # them would silently disable compound/exact-case behaviour.
            if item.get('compound') is True:
                entry['compound'] = True
            if item.get('caseSensitive') is True:
                entry['caseSensitive'] = True

            key = _norm_key(item['value'])
            if key in seen:
                at = seen[key]
                prev = merged[at]
                if prev['type'] != entry['type'] or prev.get('aliases', []) != entry.get('aliases', []):
                    warnings.append(
                        f'"{item["value"]}" redefined by {origin} '
                        f'(was {prev["type"]} from {prev["_origin"]}, now {entry["type"]}); later wins'
                    )
                entry['_origin'] = origin
                merged[at] = entry
                continue
            entry['_origin'] = origin
            seen[key] = len(merged)
            merged.append(entry)

    def expand(cfg, origin, depth):
        if depth > MAX_PACK_DEPTH:
            raise ValueError(f'Claudefuscator: pack nesting deeper than {MAX_PACK_DEPTH} at {origin}')
        for ref in cfg.get('packs') or []:
            pack = load_pack(ref, origin)
            if not pack:
                warnings.append(f'pack not found: {ref} (referenced by {origin})')
                continue
            loaded_packs.append(pack.get('source') or ref)
            expand(pack.get('config') or {}, pack.get('source') or ref, depth + 1)
            add_all((pack.get('config') or {}).get('identifiers'), pack.get('source') or ref)

    expand(config, source, 0)
    add_all(config.get('identifiers'), source)

    # Short vocabulary terms are the main way a personal filter goes wrong.
    # "XYZ" is bounded so it will not fire inside "AcmeTest", but it will fire
    # on any standalone occurrence, including unrelated ones.
    for entry in merged:
        # caseSensitive is the recommended remedy, so do not then warn about
        # it: a warning you have already acted on is noise.
        if entry.get('caseSensitive') or entry.get('compound'):
            continue
        for literal in [entry['value']] + list(entry.get('aliases') or []):
            s = str(literal)
            if len(s) <= 3 and s.isalnum():
                warnings.append(
                    f'"{s}" ({entry["_origin"]}) is a {len(s)}-character term; it will match any '
                    'standalone occurrence. Consider caseSensitive, a longer form, or dropping it.'
                )

    flat = []
    for e in merged:
        out = {'type': e['type'], 'value': e['value']}
        if e.get('aliases'):
            out['aliases'] = e['aliases']
        if e.get('compound'):
            out['compound'] = True
        if e.get('caseSensitive'):
            out['caseSensitive'] = True
        flat.append(out)

    resolved = dict(config)
    resolved.pop('packs', None)
    resolved['identifiers'] = flat
    return {'config': resolved, 'warnings': warnings, 'packs': loaded_packs}


def file_pack_loader(base_dir):
    """Resolves pack refs relative to the file that referenced them."""
    roots = {'config': base_dir}

    def load(ref, origin):
        root = roots.get(origin) or os.path.dirname(origin) or base_dir
        path = ref if os.path.isabs(ref) else os.path.join(root, ref)
        if not os.path.exists(path):
            return None
        with open(path, 'rb') as f:
            cfg = json.load(f)
        roots[path] = os.path.dirname(path)
        return {'config': cfg, 'source': path}

    return load
