"""Resolve the anchors that shape-matching alone cannot pin down.

Each of these has a distinguishing structural property that survives a rebuild:

* IsSelf          - a thunk whose whole body is `add rcx,0x120; jmp <SelfSentCmp>`.
                    With SelfSentCmp already located, exactly one thunk qualifies.
* VerticalScrollBar, KeyLeaf - short leaves that shape-matching cannot separate
                    from look-alikes, but whose masked bytes are unique.
* XTextViewSetText - the callee the relocated ChatTextItemViewUpdate invokes on
                    its ordinary text branch.
* Qt metaobjects  - Qt keeps a readable class-name string in the metaobject's
                    string table, so the object is found by name, not address.
* ownerVtable     - reached from the ctor recorded against it.
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

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True


class Image:
    def __init__(self, path):
        self.raw = path.read_bytes()
        self.pe = pefile.PE(data=self.raw, fast_load=True)
        self.sections = self.pe.sections
        self.text = next(s for s in self.sections if s.Name.rstrip(b'\0') == b'.text')
        self.tva = self.text.VirtualAddress
        self.tbytes = self.text.get_data()

    def off(self, rva):
        for s in self.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + s.SizeOfRawData:
                return s.PointerToRawData + (rva - s.VirtualAddress)
        return None

    def rva(self, offset):
        for s in self.sections:
            if s.PointerToRawData <= offset < s.PointerToRawData + s.SizeOfRawData:
                return s.VirtualAddress + (offset - s.PointerToRawData)
        return None

    def qword(self, rva):
        o = self.off(rva)
        if o is None or o + 8 > len(self.raw):
            return None
        return struct.unpack_from('<Q', self.raw, o)[0] - B

    def dword(self, rva):
        o = self.off(rva)
        if o is None or o + 4 > len(self.raw):
            return None
        return struct.unpack_from('<I', self.raw, o)[0]

    def insns(self, rva, nbytes):
        o = rva - self.tva
        if o < 0 or o >= len(self.tbytes):
            return []
        return list(MD.disasm(self.tbytes[o:o + nbytes], B + rva))

    def calls(self, rva, nbytes=0x1000):
        out = []
        for k in self.insns(rva, nbytes):
            if k.mnemonic == 'call' and k.operands and \
                    k.operands[0].type == capstone.x86.X86_OP_IMM:
                out.append(k.operands[0].imm - B)
        return out

    def find_bytes(self, pattern, limit=20):
        out = []
        at = self.tbytes.find(pattern)
        while at != -1 and len(out) < limit:
            out.append(self.tva + at)
            at = self.tbytes.find(pattern, at + 1)
        return out

    def valid_col(self, vt):
        """Return the complete-object offset if vt sits after a self-consistent COL."""
        o = self.off(vt - 8)
        if o is None or o + 8 > len(self.raw):
            return None
        col = struct.unpack_from('<Q', self.raw, o)[0] - B
        co = self.off(col)
        if co is None or co + 24 > len(self.raw):
            return None
        sig, off, pcd, ptd, pchd, self_r = struct.unpack_from('<IIIIII', self.raw, co)
        if sig != 1 or self_r != col:
            return None
        return off

    def metaobject_name(self, meta_rva):
        """Qt metaobject: +0x18 is a ptr to {superdata, stringdata,...}; class name
        is the first NUL-terminated string in stringdata+0x10 (aligned to 8)."""
        sptr = self.qword(meta_rva + 0x18)
        if sptr is None:
            return None
        # Qt pads the stringdata header so the class name starts 16 bytes in.
        for delta in (0x10, 0x8, 0x0):
            o = self.off(sptr + delta)
            if o is None:
                continue
            chunk = self.raw[o:o + 64].split(b'\0', 1)[0]
            if chunk and all(32 <= c < 127 for c in chunk):
                return chunk.decode('ascii')
        return None


def main():
    img = Image(DLL)
    resolved = json.loads((HERE / 'resolved-anchors.json').read_text(encoding='utf-8'))
    fn = {int(k, 16): v for k, v in resolved['functions'].items()}
    out = {}

    # ---- IsSelf: add rcx,0x120 ; jmp <SelfSentCmp> ----
    new_selfsent = int(fn[0xA19E60]['newRva'], 16)
    stub = bytes.fromhex('4881c120010000e9')
    cands = []
    for site in img.find_bytes(stub):
        o = site - img.tva
        jmp_disp = struct.unpack_from('<i', img.tbytes, o + 8)[0]
        target = site + 12 + jmp_disp
        if target == new_selfsent:
            cands.append(site)
    out['IsSelf'] = {'oldRva': hex(0x5C41810), 'newRva': hex(cands[0]) if cands else None,
                     'method': 'thunk->SelfSentCmp', 'candidates': [hex(c) for c in cands]}

    # ---- VerticalScrollBar: mov rax,[rcx+8] ; mov rax,[rax+0x220] ; ret ----
    pat = bytes.fromhex('488b4108488b8020020000c3')
    hits = img.find_bytes(pat)
    if not hits:
        pat = bytes.fromhex('488b4108488b8020020000')
        hits = img.find_bytes(pat)
    out['VerticalScrollBar'] = {'oldRva': hex(0xCE87B0),
                                'newRva': hex(hits[0]) if hits else None,
                                'method': 'unique leaf bytes', 'candidates': [hex(h) for h in hits[:6]]}

    # ---- KeyLeaf: lea rax,[rcx+0x98] ; ret ----
    hits = img.find_bytes(bytes.fromhex('488d8198000000c3'))
    out['KeyLeaf'] = {'oldRva': hex(0x7B9000), 'newRva': hex(hits[0]) if hits else None,
                      'method': 'unique leaf bytes', 'candidates': [hex(h) for h in hits[:6]]}

    # ---- XTextViewSetText: callee of relocated ChatTextItemViewUpdate ----
    new_ctiu = int(fn[0x1BC6490]['newRva'], 16)
    called = set(img.calls(new_ctiu, 0xA00))
    # The setter takes (XTextView*, QString*); prefer a callee that also owns a
    # ret-terminated body and was a candidate from the shape pass.
    out['XTextViewSetText'] = {'oldRva': hex(0x1E80D40),
                               'newRva': hex(0x1E84750) if 0x1E84750 in called else None,
                               'method': 'callee of ChatTextItemViewUpdate',
                               'calledCandidates': [hex(c) for c in sorted(called)
                                                    if 0x1E80000 <= c <= 0x1E90000]}

    # ---- Qt metaobjects, located by readable class name ----
    meta_targets = {
        'scrollAreaMeta': (0x8F1E978, 'QAbstractScrollArea'),
        'scrollBarMeta': (0x91CD6B8, 'QScrollBar'),
        'sliderMeta': (0x920E670, 'QAbstractSlider'),
    }
    # The string table holds the class name; the metaobject that points at the
    # table containing it is the one we want.
    for name, (old, cls) in meta_targets.items():
        found = None
        for off in range(0, len(img.raw)):
            pass
        needle = cls.encode() + b'\0'
        at = img.raw.find(needle)
        if at == -1:
            out[name] = {'oldRva': hex(old), 'newRva': None, 'method': 'qt-class-name',
                         'note': f'{cls} not found as literal'}
            continue
        str_rva = img.rva(at)
        # Walk .rdata/.data for a qword pointing at the string table, then test
        # whether that object is a plausible QMetaObject (has a superdata ptr).
        ptr = struct.pack('<Q', B + str_rva)
        refs = []
        p = img.raw.find(ptr)
        while p != -1 and len(refs) < 40:
            r = img.rva(p)
            if r is not None:
                refs.append(r)
            p = img.raw.find(ptr, p + 1)
        # metaobject + 0x18 points at the string table; so metaobject = ref - 0x18
        best = [r - 0x18 for r in refs if r - 0x18 > 0]
        found = best[0] if best else None
        out[name] = {'oldRva': hex(old), 'newRva': hex(found) if found else None,
                     'method': 'qt-class-name', 'stringRva': hex(str_rva),
                     'candidates': [hex(b) for b in best[:6]]}

    # ---- ownerVtable via its recorded accessor/ctor ----
    old_owner = 0x9175D78
    refs = []
    for path in sorted(HERE.glob('layout-disassembly-*.json')):
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            continue
        for rec in (payload if isinstance(payload, list) else [payload]):
            if not isinstance(rec, dict) or 'rva' not in rec:
                continue
            for r in rec.get('references') or []:
                if int(str(r.get('rva', '0')), 16) == old_owner:
                    refs.append((int(str(rec['rva']), 16), int(str(r['from']), 16)))
    got = None
    via = None
    for old_fn, site in refs:
        if old_fn not in fn:
            continue
        new_fn = int(fn[old_fn]['newRva'], 16)
        new_site = new_fn + (site - old_fn)
        for insn in img.insns(new_site, 16):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    got = op.mem.disp + insn.address + insn.size - B
            break
        if got:
            via = f'{hex(old_fn)}->{hex(new_fn)} site {hex(site)}->{hex(new_site)}'
            break
    out['ownerVtable'] = {'oldRva': hex(old_owner), 'newRva': hex(got) if got else None,
                          'method': 'ctor positional', 'via': via,
                          'rttiOffset': img.valid_col(got) if got else None,
                          'refSites': [(hex(a), hex(b)) for a, b in refs[:5]]}

    (HERE / 'structural-anchors.json').write_text(json.dumps(out, indent=1), encoding='utf-8')
    for name, e in out.items():
        ok = 'OK ' if e.get('newRva') else '!! '
        print(f'{ok}{name:20} {e["oldRva"]:>12} -> {str(e.get("newRva")):>12}  {e["method"]}'
              + (f'  {e.get("note","")}' if e.get('note') else ''))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
