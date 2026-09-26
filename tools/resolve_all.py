"""Resolve every adapter anchor for a new Weixin.dll build.

Two passes:

1. Function pass. Every function present in the old disassembly records gets an
   instruction-shape signature; the new build is scanned for a matching
   function. Identity matches win, then longest prefix.
2. Vtable pass. The records also capture, for each constructor, which
   instruction site loads which vtable. Once the constructor is located, the new
   vtable is read from the new build at the same displacement. Results are
   sanity-checked against MSVC RTTI: a real vtable sits directly after a COL
   that points back at itself.

Positional correspondence is sound because a recompile moves a function but
does not reorder the loads inside it.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'tool-libs'))
import capstone
import pefile

DLL = Path(r'C:\Program Files\Tencent\Weixin\4.1.15.13\Weixin.dll')
B = 0x180000000
MAXINS = 20
SCAN = 160
MIN_INS = 4

_HEX = __import__('re').compile(r'0x[0-9a-f]+')
_WS = __import__('re').compile(r'\s+')
_MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_MD.detail = True


def collapse(text):
    def repl(m):
        return 'BIG' if int(m.group(0), 16) >= 0x10000 else m.group(0)
    # Records pad mnemonics with column spaces while capstone emits one, so
    # collapse runs of whitespace before comparing anything.
    return _HEX.sub(repl, _WS.sub(' ', text.strip().lower()))


def shape(insn):
    return collapse(insn.mnemonic + ' ' + insn.op_str)


def load_records():
    """old fn rva -> {'shape': [...], 'refs': [(site, target)]}"""
    fns = {}
    for path in sorted(HERE.glob('layout-disassembly-*.json')):
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            continue
        for rec in (payload if isinstance(payload, list) else [payload]):
            if not isinstance(rec, dict) or 'rva' not in rec:
                continue
            rva = int(str(rec['rva']), 16)
            shapes = []
            for line in rec.get('instructions', []):
                s = collapse(line.split(':', 1)[1] if ':' in line else line)
                if not s:
                    continue
                shapes.append(s)
                if s.startswith('ret'):
                    break
            shapes = shapes[:MAXINS]
            refs = [(int(str(r['from']), 16), int(str(r['rva']), 16))
                    for r in rec.get('references') or [] if r.get('from') and r.get('rva')]
            entry = fns.setdefault(rva, {'shape': [], 'refs': []})
            if len(shapes) > len(entry['shape']):
                entry['shape'] = shapes
            entry['refs'] += refs
    return fns


def main():
    records = load_records()
    raw = DLL.read_bytes()
    pe = pefile.PE(data=raw, fast_load=True)
    text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
    tva, tbytes = text.VirtualAddress, text.get_data()
    ex = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    edata = pe.get_data(ex.VirtualAddress, ex.Size)
    starts = sorted({a for a, b, _ in struct.iter_unpack('<III', edata) if a and b > a})
    pe.close()

    def shapes_at(rva):
        off = rva - tva
        if off < 0 or off + 4 > len(tbytes):
            return []
        return [shape(i) for i in _MD.disasm(tbytes[off:off + SCAN], B + rva)][:MAXINS]

    def plen(want, got):
        n = 0
        while n < len(want) and n < len(got) and want[n] == got[n]:
            n += 1
        return n

    # index by opening shape
    index = {}
    for rva, rec in records.items():
        if rec['shape']:
            index.setdefault(rec['shape'][0], []).append(rva)

    hits = {rva: [] for rva in records}
    # identity tier first
    for rva, rec in records.items():
        if rec['shape'] and plen(rec['shape'], shapes_at(rva)) == len(rec['shape']):
            hits[rva].append(('identity', len(rec['shape']), rva))
    # shape tier at recorded function starts
    for start in starts:
        off = start - tva
        if off < 0 or off + 4 > len(tbytes):
            continue
        head = next(_MD.disasm(tbytes[off:off + 16], B + start), None)
        if head is None:
            continue
        names = index.get(shape(head))
        if not names:
            continue
        got = shapes_at(start)
        for rva in names:
            want = records[rva]['shape']
            m = plen(want, got)
            if m >= min(MIN_INS, len(want)):
                hits[rva].append(('shape', m, start))

    rank = {'identity': 0, 'shape': 1}
    fn_map, fn_weak = {}, {}
    for rva in sorted(records):
        ranked = sorted(hits[rva], key=lambda x: (rank[x[0]], -x[1], x[2]))
        if not ranked:
            continue
        best = ranked[0]
        same = [x for x in ranked if x[0] == best[0] and x[1] == best[1]]
        distinct = {x[2] for x in same}
        if len(distinct) > 1:
            fn_weak[rva] = {'newRva': hex(best[2]), 'tier': best[0], 'matched': best[1],
                            'candidates': [hex(c) for c in sorted(distinct)[:5]]}
        else:
            fn_map[rva] = {'newRva': hex(best[2]), 'tier': best[0], 'matched': best[1]}

    # ---- vtable pass ----
    def rip_at(site):
        off = site - tva
        if off < 0 or off + 16 > len(tbytes):
            return None
        for insn in _MD.disasm(tbytes[off:off + 16], B + site):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    return op.mem.disp + insn.address + insn.size - B
            return None
        return None

    def valid_col(vt):
        for s in pe_sections:
            if s.VirtualAddress <= vt - 8 < s.VirtualAddress + s.SizeOfRawData:
                o = s.PointerToRawData + (vt - 8 - s.VirtualAddress)
                break
        else:
            return None
        col = struct.unpack_from('<Q', raw, o)[0] - B
        for s in pe_sections:
            if s.VirtualAddress <= col < s.VirtualAddress + s.SizeOfRawData:
                co = s.PointerToRawData + (col - s.VirtualAddress)
                break
        else:
            return None
        sig, off, pcd, ptd, pchd, self_r = struct.unpack_from('<IIIIII', raw, co)
        if sig != 1 or self_r != col:
            return None
        return off

    pe2 = pefile.PE(data=raw, fast_load=True)
    pe_sections = pe2.sections

    vtables, vt_weak = {}, {}
    for old_fn, rec in sorted(records.items()):
        if not rec['refs'] or old_fn not in fn_map:
            continue
        new_fn = int(fn_map[old_fn]['newRva'], 16)
        for site, target in rec['refs']:
            new_site = new_fn + (site - old_fn)
            got = rip_at(new_site)
            if got is None:
                continue
            entry = {'oldVtable': hex(target), 'newVtable': hex(got),
                     'delta': hex(got - target), 'rttiOffset': valid_col(got),
                     'via': f'{hex(old_fn)}->{hex(new_fn)} site {hex(site)}->{hex(new_site)}'}
            # A COL is only expected for real vtables, not Qt metaobject statics.
            if valid_col(got) is not None:
                vtables[hex(target)] = entry
            else:
                vt_weak.setdefault(hex(target), entry)

    out = {'dll': str(DLL), 'sha256': hashlib.sha256(raw).hexdigest(),
           'functions': {hex(k): v for k, v in sorted(fn_map.items())},
           'functionsWeak': {hex(k): v for k, v in sorted(fn_weak.items())},
           'vtables': vtables, 'vtablesNoCol': vt_weak}
    Path('resolved-anchors.json').write_text(json.dumps(out, indent=1), encoding='utf-8')

    idn = sum(1 for v in fn_map.values() if v['tier'] == 'identity')
    print(f'functions located : {len(fn_map)}/{len(records)}  (identity {idn})')
    print(f'functions weak    : {len(fn_weak)}')
    print(f'vtables w/ valid COL: {len(vtables)}')
    for old, e in sorted(vtables.items()):
        print(f'   {old:>12} -> {e["newVtable"]:>12}  delta {e["delta"]:>8}  rttiOff {e["rttiOffset"]}')
    print(f'vtables w/o COL   : {len(vt_weak)}')
    for old, e in sorted(vt_weak.items()):
        print(f'   {old:>12} -> {e["newVtable"]:>12}  delta {e["delta"]:>8}')
    print('written: resolved-anchors.json')


if __name__ == '__main__':
    raise SystemExit(main())
