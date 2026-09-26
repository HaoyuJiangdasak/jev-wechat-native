"""Relocate the adapter's vtable anchors across a Weixin.dll rebuild.

The old records document, for each constructor, the instruction site that loads
a given vtable (`references`: from -> rva). A recompile moves the constructor,
but the site keeps its displacement inside the function and keeps loading the
same slot, so the new target can be read from the new build at the same offset.

That positional correspondence is what this tool relies on, with an independent
RTTI sanity check on the result: a located vtable must have a valid MSVC COL
immediately before it, pointing back at itself.
"""
from __future__ import annotations

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

# old constructor RVA -> new constructor RVA, from reanchor.py's scan.
FUNCS = {
    0x3CFF540: 0x3D02580,   # binding ctor
    0x3CFFE90: 0x3D028C0,   # binding ctor variant (resolved below if wrong)
    0x3DE1A50: None,        # listener ctor family
    0x3DE5760: None,
    0x1A5B50: 0x1A5B50,     # message copy ctor (byte-identical)
    0xA58F00: 0xA5A150,     # UIMessage default ctor
    0x1BC8640: 0x1BCBD90,   # chat item view build ctor
    0x1E7A170: None,        # XTextView-side ctor
}

# old vtable RVA -> human name, from conversation-identity-static.json and friends.
WANTED = {
    0x956B278: 'bindingVtable',
    0x956B548: 'textInterfaceVtable',
    0x8D9C978: 'uiMessageVtable',
    0x95884E8: 'listenerVtable',
    0x9175D78: 'ownerVtable',
    0x91CFB08: 'labelVtable',
    0x8E9C418: 'recyclerMetaCast',
    0x8F1E978: 'scrollAreaMeta',
    0x91CD6B8: 'scrollBarMeta',
    0x956B1E8: 'bindingBase1',
    0x956B4D8: 'bindingBase3',
    0x956B518: 'bindingBase4',
}


def load_references():
    """old fn rva -> [(site rva, old target rva)] for the vtables we track."""
    out = {}
    for path in sorted(HERE.glob('layout-disassembly-*.json')):
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            continue
        for record in (payload if isinstance(payload, list) else [payload]):
            if not isinstance(record, dict) or 'rva' not in record:
                continue
            fn = int(str(record['rva']), 16)
            for ref in record.get('references') or []:
                target = int(str(ref.get('rva', '0')), 16)
                if target not in WANTED:
                    continue
                site = int(str(ref['from']), 16)
                out.setdefault(fn, []).append((site, target))
    return out


def main():
    refs = load_references()
    raw = DLL.read_bytes()
    pe = pefile.PE(data=raw, fast_load=True)
    text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
    tva, tbytes = text.VirtualAddress, text.get_data()

    def rva_ok(rva):
        return tva <= rva < tva + len(tbytes)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    def rip_target_at(site_rva):
        """Decode the first rip-relative lea/mov at site_rva; return its target."""
        offset = site_rva - tva
        if offset < 0 or offset + 8 > len(tbytes):
            return None
        for insn in md.disasm(tbytes[offset:offset + 16], B + site_rva):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    target = op.mem.disp + insn.address + insn.size - B
                    return target
            return None
        return None

    def has_valid_col(vt):
        """vtable must be preceded by an MSVC COL pointing back at itself."""
        o = None
        for s in pe.sections:
            if s.VirtualAddress <= vt - 8 < s.VirtualAddress + s.SizeOfRawData:
                o = s.PointerToRawData + (vt - 8 - s.VirtualAddress)
        if o is None or o + 32 > len(raw):
            return False
        col = struct.unpack_from('<Q', raw, o)[0] - B
        co = None
        for s in pe.sections:
            if s.VirtualAddress <= col < s.VirtualAddress + s.SizeOfRawData:
                co = s.PointerToRawData + (col - s.VirtualAddress)
        if co is None or co + 24 > len(raw):
            return False
        sig, off, pcd, ptd, pchd, self_r = struct.unpack_from('<IIIIII', raw, co)
        return sig == 1 and self_r == col

    results, problems = {}, []
    for old_fn, entries in sorted(refs.items()):
        new_fn = FUNCS.get(old_fn, old_fn)
        if new_fn is None:
            problems.append(f'no new RVA for ctor {hex(old_fn)}')
            continue
        for site, old_target in entries:
            delta = site - old_fn
            new_site = new_fn + delta
            target = rip_target_at(new_site)
            name = WANTED[old_target]
            if target is None:
                problems.append(f'{name}: no rip-relative operand at {hex(new_site)}')
                continue
            results[old_target] = {
                'name': name, 'oldVtable': hex(old_target), 'newVtable': hex(target),
                'via': f'ctor {hex(old_fn)} site {hex(site)} -> {hex(new_site)}',
                'delta': hex(target - old_target),
                'rttiColValid': has_valid_col(target),
            }

    print(f'{"name":24} {"old":>12} {"new":>12} {"delta":>9}  COL')
    for old in sorted(results):
        r = results[old]
        print(f'{r["name"]:24} {r["oldVtable"]:>12} {r["newVtable"]:>12} {r["delta"]:>9}  {r["rttiColValid"]}')
    for p in problems:
        print('  !', p)
    Path('vtable-anchors.json').write_text(json.dumps(
        {'dll': str(DLL), 'vtables': results, 'problems': problems}, indent=1), encoding='utf-8')
    print('written: vtable-anchors.json')
    pe.close()


if __name__ == '__main__':
    raise SystemExit(main())
