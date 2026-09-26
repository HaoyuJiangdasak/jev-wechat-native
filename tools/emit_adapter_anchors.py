"""Emit the adapter-facing anchor file for the installed Weixin build.

Takes the resolver output and adds what the adapter needs at runtime: the
prologue bytes of each function (so the script can still verify the code it is
about to call), the file hash and size, and the module geometry. The adapter
loads this file instead of carrying addresses in its source, so supporting a new
WeChat build means re-running the resolver, not editing the adapter.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'tool-libs'))
import pefile

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--resolved', required=True)
    ap.add_argument('--dll', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--version', default='')
    args = ap.parse_args()

    resolved = json.loads(Path(args.resolved).read_text(encoding='utf-8'))
    raw = Path(args.dll).read_bytes()
    pe = pefile.PE(data=raw, fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage

    def as_int(value):
        return int(value, 16) if isinstance(value, str) else int(value)

    def prologue(rva, n=24):
        section = pe.get_section_by_rva(rva)
        code = pe.get_data(rva, n)
        if section is None or code is None or len(code) != n:
            raise SystemExit(f'cannot read {n} bytes at {hex(rva)}')
        if not section.Characteristics & 0x20000000:
            raise SystemExit(f'{hex(rva)} is not in an executable section')
        return list(code)

    functions = {}
    for name, entry in resolved['functions'].items():
        rva = as_int(entry['newRva'])
        functions[name] = {'rva': rva, 'prologue': prologue(rva)}
    pe.close()

    out = {
        '_comment': [
            'Semantic anchors for the native WeChat adapter. WeChat replaces',
            'Weixin.dll through its own auto-updater, so no address here is permanent.',
            'Regenerate for a new build with the reanchor tooling in',
            'work/native-adapter-research:',
            '  resolve_anchors.py --dll <path> --out resolved.json',
            '  emit_adapter_anchors.py --resolved resolved.json --dll <path> --out native_anchors.json',
            'The adapter verifies dll_sha256 before using any value and fails closed',
            'on a mismatch, so a stale file cannot cause reads at wrong offsets.'
        ],
        'wechat_version': args.version,
        'dll_sha256': hashlib.sha256(raw).hexdigest(),
        'dll_size': len(raw),
        'image_base': image_base,
        'module_size': size_of_image,
        'resolution': resolved.get('provenance', {}),
        'functions': functions,
        'vtables': {k: as_int(v['newRva']) for k, v in resolved['vtables'].items()},
        'metaobjects': {k: as_int(v['newRva']) for k, v in resolved['metaobjects'].items()},
        'vtableProvenance': {k: {kk: vv for kk, vv in v.items() if kk != 'newRva'}
                             for k, v in resolved['vtables'].items()},
    }
    Path(args.out).write_text(json.dumps(out, indent=1), encoding='utf-8')
    print(f'functions : {len(functions)}')
    print(f'vtables   : {len(out["vtables"])}')
    print(f'metaobjects: {len(out["metaobjects"])}')
    print(f'sha256    : {out["dll_sha256"]}')
    print(f'written   : {args.out}')

if __name__ == '__main__':
    raise SystemExit(main())
