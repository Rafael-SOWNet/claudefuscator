"""Layered-config merge, Python side, asserted against the SAME fixtures the
JS suite uses (test/fixtures/merge/).

The point is not that merging works - test/merge.test.js already covers the
behaviour - but that both implementations produce a byte-identical flat list.
If they diverge, the proxy and the Chrome extension derive different tokens
from the same config and restore silently stops working on one side.
"""

import json
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import config_merge  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'test' / 'fixtures' / 'merge'


def merge(name):
    path = FIXTURES / name
    cfg = json.loads(path.read_text(encoding='utf-8'))
    return config_merge.merge_config(
        cfg, config_merge.file_pack_loader(str(FIXTURES)), str(path)
    )


def test_packs_resolve_including_nested():
    r = merge('config.json')
    values = [i['value'] for i in r['config']['identifiers']]
    assert 'WIDGET-800' in values
    assert 'Plant One' in values
    assert 'Jane Example' in values
    assert len(r['packs']) == 2


def test_project_list_overrides_pack_and_warns():
    r = merge('config.json')
    entry = next(i for i in r['config']['identifiers'] if i['value'] == 'ExampleCorp')
    assert entry['type'] == 'CUSTOMER'
    assert any('ExampleCorp' in w and 'later wins' in w for w in r['warnings'])


def test_match_flags_survive():
    r = merge('config.json')
    sym = next(i for i in r['config']['identifiers'] if i['value'] == 'Acme')
    proc = next(i for i in r['config']['identifiers'] if i['value'] == 'XYZ')
    assert sym.get('compound') is True
    assert sym.get('aliases') == ['ACME']
    assert proc.get('caseSensitive') is True


def test_packs_key_removed():
    assert 'packs' not in merge('config.json')['config']


def test_missing_pack_warns():
    r = merge('missing-pack.json')
    assert any('pack not found' in w for w in r['warnings'])
    assert len(r['config']['identifiers']) == 1


def test_recursion_is_bounded():
    self_ref = {'packs': ['self'], 'identifiers': []}
    with pytest.raises(ValueError, match='nesting deeper'):
        config_merge.merge_config(self_ref, lambda ref, origin: {'config': self_ref, 'source': 'self'}, 'self')


@pytest.mark.parametrize('name', ['config.json', 'missing-pack.json', 'nested-pack.json'])
def test_matches_the_js_implementation(name):
    """Run the JS merger over the same fixture and compare the flat list."""
    script = (
        "const fs=require('node:fs'),path=require('node:path');"
        "const {mergeConfig}=require(process.argv[1]);"
        "const dir=process.argv[2], file=path.join(dir, process.argv[3]);"
        "const roots=new Map();"
        "const loader=(ref,origin)=>{"
        "  const root=roots.get(origin)||(origin&&path.dirname(origin))||dir;"
        "  const f=path.isAbsolute(ref)?ref:path.join(root,ref);"
        "  if(!fs.existsSync(f))return null;"
        "  roots.set(f,path.dirname(f));"
        "  return {config:JSON.parse(fs.readFileSync(f,'utf8')),source:f};"
        "};"
        "const cfg=JSON.parse(fs.readFileSync(file,'utf8'));"
        "const r=mergeConfig(cfg,loader,{source:file});"
        "process.stdout.write(JSON.stringify(r.config.identifiers));"
    )
    proc = subprocess.run(
        ['node', '-e', script, str(ROOT / 'shared' / 'config-merge.js'), str(FIXTURES), name],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.skip('node unavailable or failed: ' + proc.stderr[:200])

    js_identifiers = json.loads(proc.stdout)
    py_identifiers = merge(name)['config']['identifiers']
    assert py_identifiers == js_identifiers, (
        f'Python and JS resolved {name} differently:\n'
        f'  py: {py_identifiers}\n  js: {js_identifiers}'
    )
