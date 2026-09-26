"""Resolve every native-adapter anchor for an arbitrary Weixin.dll build.

This is the canonical resolver. Weixin.dll is replaced silently by an
auto-updater, so nothing the adapter needs may be pinned to a frozen address or
hash. Everything is re-derived from a known-good record set here, and the result
is emitted as a semantic anchor map the adapter loads at startup.

Evidence tiers, strongest first. Each is tried independently; a stronger tier
always wins, and a tie inside a tier is reported ambiguous rather than guessed,
because a wrong anchor means the adapter silently reads the wrong memory.

  identity   same RVA, instruction shape still matches exactly
  bytes      masked machine code (address fields zeroed) found in .text
  shape      instruction-shape prefix at a recorded function start
  derived    produced from an already-resolved anchor by a structural relation
  vtable     read from a located constructor at the same site displacement
  qtmeta     Qt metaobject found through its moc string table

Requires: pefile, capstone (both in tool-libs).
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Disassembly records live in records/ so the tool directory stays readable.
# Fall back to the script's own directory for the original working layout.
RECORDS = HERE / 'records'
if not RECORDS.is_dir():
    RECORDS = HERE
sys.path.insert(0, str(HERE / 'tool-libs'))
import capstone
import pefile

B = 0x180000000
MAXINS = 20
SCAN = 192
BYTE_PREFIX = 64
MIN_INS = 4
BYTE_HIT_CAP = 4000
HEX = re.compile(r'0x[0-9a-f]+')
WS = re.compile(r'\s+')
MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True

# Semantic name -> old RVA. Names say what the adapter does with the site.
FUNCTIONS = {
    'fromUtf8': 0x27F80,
    'destroyQString': 0x14E0,
    'setText': 0x1E80D40,
    'widgetMetaCall': 0x5BBFC0,
    'rebindListener': 0x1BC6490,
    'isSelf': 0x5C41810,
    'metaCast': 0x28C390,
    'verticalScrollBar': 0xCE87B0,
    'sliderMetaCall': 0x20B4600,
    'setValue': 0x20B34A0,
    'buildCtor': 0x1BC8640,
    'qtDataFree': 0x38930,
    'qtDecode1': 0x2C4A00,
    'qtDecode2': 0x2C4AA0,
    'qtHelper': 0x27E30,
    'keyLeaf': 0x7B9000,
    'leafBinding120': 0x3B4DD0,
    'selfSentCmp': 0xA19E60,
    'textGetter': 0x3D00D20,
    'bindingCtor': 0x3CFF540,
    'uiMsgDefCtor': 0xA58F00,
    'baseUpdater': 0x5C3DE20,
    'textOverride': 0x3D01B40,
    'filterPred': 0x3E2B8E0,
    'listenerKeySetter': 0x3E28DE0,
    'convSwitchInit': 0x3DE5E90,
    'keyFormat': 0xA17360,
    'compositeKey': 0x227A000,
    'tsFlag': 0xA1D4F0,
    'msgCopyCtor': 0x1A5B50,
}

# vtables the adapter compares against, plus the Qt metaobjects it casts through.
VTABLES = {
    'bindingVtable': 0x956B278,
    'textInterfaceVtable': 0x956B548,
    'uiMessageVtable': 0x8D9C978,
    'listenerVtable': 0x95884E8,
    'ownerVtable': 0x9175D78,
    'labelVtable': 0x91CFB08,
}
METAOBJECTS = {
    'recyclerMeta': (0x8E9C418, 'mmui::RecyclerListView'),
    'scrollAreaMeta': (0x8F1E978, 'QAbstractScrollArea'),
    'scrollBarMeta': (0x91CD6B8, 'QScrollBar'),
}

# ChatTextItemView owns a Qt metaobject whose name is a readable string, which
# is what identifies its vtable here; MSVC RTTI names are absent from this build.
OWNER_CLASS = 'mmui::ChatTextItemView'


def collapse(text):
    def repl(m):
        return 'BIG' if int(m.group(0), 16) >= 0x10000 else m.group(0)
    return HEX.sub(repl, WS.sub(' ', text.strip().lower()))


def shape_of(insn):
    return collapse(insn.mnemonic + ' ' + insn.op_str)


class Image:
    def __init__(self, path):
        self.path = Path(path)
        self.raw = self.path.read_bytes()
        self.sha = hashlib.sha256(self.raw).hexdigest()
        self.pe = pefile.PE(data=self.raw, fast_load=True)
        self.sections = self.pe.sections
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.text = next(s for s in self.sections if s.Name.rstrip(b'\0') == b'.text')
        self.tva, self.tbytes = self.text.VirtualAddress, self.text.get_data()

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

    def q(self, rva):
        o = self.off(rva)
        return struct.unpack_from('<Q', self.raw, o)[0] - self.base if o is not None else None

    def in_image(self, rva):
        return 0 < rva < self.pe.OPTIONAL_HEADER.SizeOfImage

    def insns(self, rva, nbytes):
        o = rva - self.tva
        return list(MD.disasm(self.tbytes[o:o + nbytes], self.base + rva)) if 0 <= o < len(self.tbytes) else []

    def shapes(self, rva, nbytes=SCAN):
        return [shape_of(i) for i in self.insns(rva, nbytes)][:MAXINS]

    def calls(self, rva, nbytes):
        return [i.operands[0].imm - self.base for i in self.insns(rva, nbytes)
                if i.mnemonic == 'call' and i.operands and i.operands[0].type == capstone.x86.X86_OP_IMM]

    def start_points(self):
        ex = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        ed = self.pe.get_data(ex.VirtualAddress, ex.Size)
        return sorted({a for a, b, _ in struct.iter_unpack('<III', ed) if a and b > a})

    def find(self, pattern, limit=64):
        out, at = [], self.tbytes.find(pattern)
        while at != -1 and len(out) < limit:
            out.append(self.tva + at)
            at = self.tbytes.find(pattern, at + 1)
        return out

    def col_offset(self, vt):
        """Complete-object offset if vt sits after a self-consistent MSVC COL."""
        o = self.off(vt - 8)
        if o is None:
            return None
        col = struct.unpack_from('<Q', self.raw, o)[0] - self.base
        if not self.in_image(col):
            return None
        co = self.off(col)
        if co is None or co + 24 > len(self.raw):
            return None
        sig, offset, pcd, ptd, pchd, selfr = struct.unpack_from('<IIIIII', self.raw, co)
        return offset if (sig == 1 and selfr == col) else None

    def col_bases(self, vt):
        """Base-class count from the COL's class hierarchy descriptor, or None."""
        o = self.off(vt - 8)
        if o is None:
            return None
        col = struct.unpack_from('<Q', self.raw, o)[0] - self.base
        co = self.off(col)
        if co is None or co + 24 > len(self.raw):
            return None
        sig, offset, pcd, ptd, pchd, selfr = struct.unpack_from('<IIIIII', self.raw, co)
        if sig != 1 or selfr != col or not self.in_image(pchd):
            return None
        o2 = self.off(pchd)
        if o2 is None or o2 + 12 > len(self.raw):
            return None
        _, _attrs, count, _array = struct.unpack_from('<IIII', self.raw, o2)
        return count if 0 < count < 100 else None


def load_records():
    """old RVA -> {'shape': [...], 'refs': [(site, target)], 'src': bool}"""
    recs = {}
    for path in sorted(glob.glob(str(RECORDS / 'layout-disassembly-*.json'))):
        try:
            payload = json.loads(Path(path).read_text(encoding='utf-8'))
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
            entry = recs.setdefault(rva, {'shape': [], 'refs': []})
            if len(shapes) > len(entry['shape']):
                entry['shape'] = shapes[:MAXINS]
            entry['refs'] += [(int(str(r['from']), 16), int(str(r['rva']), 16))
                              for r in rec.get('references') or [] if r.get('from') and r.get('rva')]
    return recs


def load_asm_bytes():
    """old RVA -> masked raw bytes, from the `<addr> <bytes> <insn>` dumps."""
    out = {}
    for path in sorted(glob.glob(str(RECORDS / '*.asm.txt'))):
        match = re.search(r'0x([0-9a-f]{4,9})\.asm\.txt$', path)
        if not match:
            continue
        rva = int(match.group(1), 16)
        buf = bytearray()
        for line in Path(path).read_text(encoding='utf-8', errors='replace').splitlines():
            m = re.match(r'^([0-9a-f]{8})\s+((?:[0-9a-f]{2} ?)+)', line.strip())
            if m:
                buf += bytes.fromhex(m.group(2).replace(' ', ''))
            if len(buf) >= SCAN:
                break
        if buf:
            out[rva] = mask_bytes(bytes(buf), B + rva)[:BYTE_PREFIX]
    return out


def mask_bytes(code, base):
    """Zero call/jmp rel32 and rip-relative disp32, keeping the encodings around
    them: a recompile moves those fields but leaves everything else intact."""
    out = bytearray(code)
    for insn in MD.disasm(code, base):
        mnem = insn.mnemonic.split()[0]
        for op in insn.operands:
            size = 0
            if op.type == capstone.x86.X86_OP_IMM and op.size == 4 and mnem in (
                    'call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jle', 'jge',
                    'ja', 'jb', 'jbe', 'jae', 'js', 'jns', 'jo', 'jno', 'jp', 'jnp'):
                size = op.size
            elif op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                size = 4
            if size:
                start = insn.address - base + insn.size - size
                out[start:start + size] = b'\x00' * size
    return bytes(out)


def plen(want, got):
    n = 0
    while n < len(want) and n < len(got) and want[n] == got[n]:
        n += 1
    return n


def resolve_functions(img, records, asm_bytes):
    """Return (resolved, weak) keyed by old RVA."""
    # Some anchors only ever had a raw byte dump, not a disassembly record, so
    # seed the candidate map from both sources.
    hits = {rva: [] for rva in set(records) | set(asm_bytes)}
    by_shape = {}
    for rva, rec in records.items():
        if rec['shape']:
            by_shape.setdefault(rec['shape'][0], []).append(rva)

    # identity: same RVA, instruction shape or masked bytes unchanged
    for rva, rec in records.items():
        if rec['shape'] and plen(rec['shape'], img.shapes(rva)) == len(rec['shape']):
            hits[rva].append(('identity', len(rec['shape']), rva))
    for rva, want in asm_bytes.items():
        o = rva - img.tva
        if o < 0 or o + len(want) > len(img.tbytes):
            continue
        got = mask_bytes(img.tbytes[o:o + len(want)], B + rva)
        if got[:len(want)] == want:
            hits[rva].append(('identity', len(want), rva))
    # masked bytes, every offset: a rebuilt function need not land on a
    # recorded .pdata boundary at all. The probe is taken from the middle of
    # the signature rather than the start, because a masked prefix can begin
    # with several zero bytes and match almost anywhere. Candidate count is
    # capped: the mask/disassemble step is the expensive part, and a signature
    # with thousands of raw hits is not discriminating enough to trust anyway.
    for rva, want in asm_bytes.items():
        if rva not in hits or len(want) < 24:
            continue
        probe = want[8:24]
        at, seen = img.tbytes.find(probe), 0
        while at != -1 and seen < BYTE_HIT_CAP:
            seen += 1
            start = at - 8
            if start >= 0:
                masked = mask_bytes(img.tbytes[start:start + SCAN], B + img.tva + start)
                size = min(len(want), len(masked))
                if size >= 12 and masked[:size] == want[:size]:
                    hits[rva].append(('bytes', size, img.tva + start))
            at = img.tbytes.find(probe, at + 1)
    # shapes at function starts
    for start in img.start_points():
        if start - img.tva + 4 > len(img.tbytes):
            continue
        head = next(iter(img.insns(start, 16)), None)
        if head is None:
            continue
        names = by_shape.get(shape_of(head))
        if not names:
            continue
        got = img.shapes(start)
        for rva in names:
            want = records[rva]['shape']
            m = plen(want, got)
            if m >= min(MIN_INS, len(want)):
                hits[rva].append(('shape', m, start))

    rank = {'identity': 0, 'bytes': 1, 'shape': 2}
    resolved, weak = {}, {}
    for rva in hits:
        ranked = sorted(hits[rva], key=lambda x: (rank[x[0]], -x[1], x[2]))
        if not ranked:
            continue
        best = ranked[0]
        tied = {x[2] for x in ranked if x[0] == best[0] and x[1] == best[1]}
        entry = {'newRva': best[2], 'tier': best[0], 'matched': best[1],
                 'runnersUp': [f'{t}:{hex(r)}' for t, _, r in ranked[1:4]]}
        (weak if len(tied) > 1 else resolved)[rva] = entry | ({'candidates': [hex(c) for c in sorted(tied)[:6]]} if len(tied) > 1 else {})
    return resolved, weak


def derive_structural(img, fn, records, vtable_rvas):
    """The few anchors that shape alone cannot pin, each by a relation that
    survives a rebuild."""
    out = {}
    def rva_of(name):
        entry = fn.get(name)
        if not entry:
            return None
        value = entry.get('newRva')
        return int(value, 16) if isinstance(value, str) else value

    # isSelf: a thunk whose entire body forwards into selfSentCmp.
    tgt = rva_of('selfSentCmp')
    if tgt is not None:
        stub = bytes.fromhex('4881c120010000e9')
        cands = []
        for site in img.find(stub):
            o = site - img.tva
            disp = struct.unpack_from('<i', img.tbytes, o + 8)[0]
            if site + 12 + disp == tgt:
                cands.append(site)
        if len(cands) == 1:
            out['isSelf'] = {'newRva': hex(cands[0]), 'tier': 'derived',
                             'method': 'thunk -> selfSentCmp'}

    # verticalScrollBar / keyLeaf: short leaves whose masked bytes are unique.
    for name, pats in (('verticalScrollBar', ('488b4108488b8020020000c3', '488b4108488b8020020000')),
                       ('keyLeaf', ('488d8198000000c3', '488d8198000000'))):
        for pat in pats:
            hits = img.find(bytes.fromhex(pat), limit=4)
            if len(hits) == 1:
                out[name] = {'newRva': hex(hits[0]), 'tier': 'derived',
                             'method': 'unique leaf bytes'}
                break

    # setText: the ordinary text branch of the relocated rebind listener calls
    # into it. Several nearby callees exist, so pick the one whose instruction
    # shape best matches the recorded setter rather than the first in range.
    rebind = rva_of('rebindListener')
    want_shape = (records.get(0x1E80D40) or {}).get('shape') or []
    if rebind is not None:
        near = [c for c in img.calls(rebind, 0xA00) if 0x1E00000 <= c <= 0x1F00000]
        scored = []
        for cand in near:
            got = img.shapes(cand, 40)
            scored.append((plen(want_shape, got) if want_shape else 0, cand))
        scored.sort(key=lambda x: (-x[0], x[1]))
        if scored and (want_shape and scored[0][0] >= MIN_INS or len(near) == 1):
            out['setText'] = {'newRva': hex(scored[0][1]), 'tier': 'derived',
                              'method': f'callee of rebindListener (shape {scored[0][0]}/{len(want_shape)})',
                              'runnersUp': [f'{n}:{hex(c)}' for n, c in scored[1:4]]}

    # textGetter: slot +0x28 of the text interface vtable, which the dataflow
    # note records as the getter the binding calls to read message text.
    ti_rva = vtable_rvas.get('textInterfaceVtable')
    if ti_rva:
        slot = img.q(int(ti_rva, 16) + 0x28)
        if slot is not None and img.in_image(slot):
            out['textGetter'] = {'newRva': hex(slot), 'tier': 'derived',
                                 'method': 'text interface vtable +0x28'}
    return out


def resolve_vtables(img, records, fn):
    """Read each vtable from the located constructor that installs it."""
    resolved, weak = {}, {}
    for old_fn, rec in records.items():
        if not rec['refs'] or old_fn not in fn:
            continue
        new_fn = fn[old_fn]['newRva']
        for site, target in rec['refs']:
            new_site = new_fn + (site - old_fn)
            got = None
            for insn in img.insns(new_site, 16):
                for op in insn.operands:
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                        got = op.mem.disp + insn.address + insn.size - B
                break
            if got is None or not img.in_image(got):
                continue
            entry = {'newRva': got, 'oldRva': target,
                     'via': f'{hex(old_fn)}@{hex(site)} -> {hex(new_fn)}@{hex(new_site)}',
                     'colOffset': img.col_offset(got)}
            (resolved if img.col_offset(got) is not None else weak)[target] = entry
    return resolved, weak


def metaobject_by_class(img, cls):
    """Find a Qt metaobject by class name, through its moc string table.

    The table is an array of QByteArrayData (24 bytes: ref, length, alloc,
    reserved, offset-relative-to-entry) whose first entry is the class name.
    QMetaObject+0x08 points at that table.
    """
    needle = cls.encode() + b'\0'
    at = img.raw.find(needle)
    while at != -1:
        for hdr in range(max(0, at - 24000), at, 8):
            try:
                ref, length, alloc, _res, rel = struct.unpack_from('<iiIIq', img.raw, hdr)
            except Exception:
                continue
            if ref != -1 or length != len(cls) or alloc != 0 or hdr + rel != at:
                continue
            count = (at - hdr) // 24
            if count * 24 != at - hdr or count > 4000:
                continue
            strtab = img.rva(hdr)
            if strtab is None:
                break
            ptr = struct.pack('<Q', img.base + strtab)
            p = img.raw.find(ptr)
            metas = []
            while p != -1 and len(metas) < 8:
                r = img.rva(p)
                if r is not None:
                    metas.append(r - 8)
                p = img.raw.find(ptr, p + 1)
            if metas:
                return metas[0]
            break
        at = img.raw.find(needle, at + 1)
    return None


def metaobject_class(img, meta):
    """Read the class name a metaobject reports, or None."""
    sp = img.q(meta + 0x08)
    if sp is None or not img.in_image(sp):
        return None
    o = img.off(sp)
    if o is None:
        return None
    try:
        ref, length, alloc, _res, rel = struct.unpack_from('<iiIIq', img.raw, o)
    except Exception:
        return None
    if ref != -1 or not 0 <= length < 200:
        return None
    return img.raw[o + rel:o + rel + length].decode('utf-8', 'replace')


def find_owner_vtable(img):
    """ChatTextItemView's vtable, identified through Qt's own metadata.

    MSVC strips RTTI names from this build (the old records note the RTTI name
    is unreadable), and the class's MSVC base count is not distinctive either.
    Qt metadata survives though: the class keeps a metaobject whose name is a
    readable string, and slot 0 of the vtable is the metaObject() accessor that
    returns it. Templates deriving from the class inherit that same accessor, so
    among the vtables sharing it the base class is the one whose COL sits at
    offset 0 with the fewest bases.
    """
    meta = metaobject_by_class(img, OWNER_CLASS)
    if meta is None:
        return []
    # The accessor is the function that loads this metaobject: find the
    # rip-relative `lea` targeting it, vectorized over the whole section.
    import numpy as np
    a = np.frombuffer(img.tbytes, dtype=np.uint8)
    n = len(a) - 7
    if n <= 0:
        return []
    mask = (a[:n] == 0x48) & (a[1:n + 1] == 0x8D) & ((a[2:n + 2] & 0xC7) == 0x05)
    idx = np.nonzero(mask)[0]
    if not len(idx):
        return []
    disp = (a[idx + 3].astype(np.int64) | (a[idx + 4].astype(np.int64) << 8) |
            (a[idx + 5].astype(np.int64) << 16) | (a[idx + 6].astype(np.int64) << 24))
    disp = np.where(disp >= 2 ** 31, disp - 2 ** 32, disp)
    sites = (img.tva + idx).astype(np.int64)
    targets = sites + 7 + disp
    sel = np.nonzero(targets == meta)[0]
    if not len(sel):
        return []
    # The accessor is the function containing such a lea. Its vtable slot points
    # at some offset inside that function, not necessarily at its .pdata start
    # (identical-code folding can merge the prologue), so collect every address
    # in the containing function's span and match all of them at once.
    starts = img.start_points()
    import bisect
    spans = []
    for i in sel:
        site = int(sites[i])
        j = bisect.bisect_right(starts, site) - 1
        if j >= 0:
            spans.append((starts[j], starts[j] + 0x400))
    if not spans:
        return []

    # Vectorized: find 8-byte-aligned slot values landing in any accessor span.
    slots = []
    for section in img.sections:
        if section.Name.rstrip(b'\0') not in (b'.rdata', b'.data'):
            continue
        blob = section.get_data()
        values = np.frombuffer(blob[:len(blob) // 8 * 8], dtype='<u8')
        lo = np.array([img.base + a for a, _ in spans], dtype=np.uint64)
        hi = np.array([img.base + b for _, b in spans], dtype=np.uint64)
        seen = np.zeros(len(values), dtype=bool)
        for l, h in zip(lo, hi):
            seen |= (values >= l) & (values < h)
        for i in np.nonzero(seen)[0]:
            vt = section.VirtualAddress + 8 * int(i)
            slots.append((vt, int(values[i]) - img.base))

    cands = []
    for vt, slot in slots:
        col_off = img.col_offset(vt)
        bases = img.col_bases(vt)
        if col_off is not None and bases is not None:
            cands.append({'newRva': vt, 'colOffset': col_off, 'bases': bases,
                          'metaobject': meta, 'slot0': slot})
    # The class itself is the least-derived of its own vtables, and its COL sits
    # at offset 0; templates deriving from it carry an inherited offset.
    cands.sort(key=lambda c: (c['colOffset'], c['bases'], c['newRva']))
    return cands


def resolve_metaobjects(img):
    """Qt metaobjects, found through the moc string table that names the class.

    QMetaObject+0x08 points at the string table; the table is an array of
    QByteArrayData (24 bytes: ref, length, alloc, capacity/reserved, offset)
    whose first entry is the class name itself.
    """
    out = {}
    for name, (old, cls) in METAOBJECTS.items():
        needle = cls.encode() + b'\0'
        found, at = None, img.raw.find(needle)
        while at != -1 and found is None:
            for hdr in range(max(0, at - 24000), at, 8):
                try:
                    ref, length, alloc, _cap, rel = struct.unpack_from('<iiIIq', img.raw, hdr)
                except Exception:
                    continue
                if ref != -1 or length != len(cls) or alloc != 0 or hdr + rel != at:
                    continue
                count = (at - hdr) // 24
                if count * 24 != at - hdr or count > 4000:
                    continue
                strtab = img.rva(hdr)
                ptr = struct.pack('<Q', img.base + strtab)
                p = img.raw.find(ptr)
                metas = []
                while p != -1 and len(metas) < 8:
                    r = img.rva(p)
                    if r is not None:
                        metas.append(r - 8)
                    p = img.raw.find(ptr, p + 1)
                if metas:
                    found = {'oldRva': old, 'newRva': metas[0], 'tier': 'qtmeta',
                             'stringTable': strtab, 'className': cls,
                             'candidates': [hex(m) for m in metas]}
                break
            at = img.raw.find(needle, at + 1)
        if found:
            out[name] = found
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dll', required=True)
    ap.add_argument('--out')
    args = ap.parse_args()

    img = Image(args.dll)
    records = load_records()
    asm_bytes = load_asm_bytes()
    print(f'sections       : {len(img.sections)}; .text 0x{img.tva:x}+0x{len(img.tbytes):x}')
    print(f'record set     : {len(records)} functions, {len(asm_bytes)} byte dumps')

    fn_raw, fn_weak_raw = resolve_functions(img, records, asm_bytes)
    fn = {k: v for k, v in fn_raw.items()}

    # map semantic names onto resolved RVAs
    funcs, missing = {}, []
    for name, old in FUNCTIONS.items():
        if old in fn:
            funcs[name] = {'newRva': hex(fn[old]['newRva']), 'tier': fn[old]['tier'],
                           'matched': fn[old]['matched'], 'oldRva': hex(old)}
            if fn[old]['tier'] == 'bytes':
                funcs[name]['byteMatched'] = fn[old]['matched']
        elif old in fn_weak_raw:
            funcs[name] = {'newRva': hex(fn_weak_raw[old]['newRva']), 'tier': 'weak',
                           'oldRva': hex(old), 'candidates': fn_weak_raw[old].get('candidates')}
        else:
            missing.append((name, old))

    # vtables first: the derived pass reads textGetter out of a vtable slot.
    vt_raw, vt_weak_raw = resolve_vtables(img, records, fn)
    vtables, vt_missing = {}, []
    for name, old in VTABLES.items():
        if old in vt_raw:
            vtables[name] = {'newRva': hex(vt_raw[old]['newRva']), 'oldRva': hex(old),
                             'colOffset': vt_raw[old]['colOffset'], 'via': vt_raw[old]['via']}
        else:
            vt_missing.append((name, old))

    # derived pass for whatever the shape/byte tiers could not pin down
    derived = derive_structural(img, {n: v for n, v in funcs.items()}, records,
                                {n: v['newRva'] for n, v in vtables.items()})
    for name, entry in derived.items():
        funcs[name] = entry
        missing = [m for m in missing if m[0] != name]

    if 'ownerVtable' in [n for n, _ in vt_missing]:
        hits = find_owner_vtable(img)
        if hits:
            best = hits[0]
            vtables['ownerVtable'] = {
                'newRva': hex(best['newRva']), 'oldRva': hex(0x9175D78),
                'colOffset': best['colOffset'],
                'method': f"metaObject slot0 -> {OWNER_CLASS} metaobject "
                          f"(COL offset {best['colOffset']}, {best['bases']} bases)",
                'candidates': [f"{hex(c['newRva'])}/off{c['colOffset']}" for c in hits[:6]],
            }
            vt_missing = [m for m in vt_missing if m[0] != 'ownerVtable']

    metas = resolve_metaobjects(img)

    result = {
        'dll': str(img.path), 'sha256': img.sha, 'size': len(img.raw),
        'functions': funcs, 'vtables': vtables, 'metaobjects': metas,
        'unresolvedFunctions': [[n, hex(o)] for n, o in missing],
        'unresolvedVtables': [[n, hex(o)] for n, o in vt_missing],
        'provenance': {'records': len(records), 'byteDumps': len(asm_bytes)},
    }
    out = Path(args.out or f'anchors-{img.sha[:8]}.json')
    out.write_text(json.dumps(result, indent=1), encoding='utf-8')

    print()
    print(f'functions  {len(funcs)}/{len(FUNCTIONS)}')
    for n, v in sorted(funcs.items()):
        old = v.get('oldRva', hex(FUNCTIONS.get(n, 0)))
        print(f'   {n:20} {old:>12} -> {v["newRva"]:>12}  [{v["tier"]}]')
    print(f'vtables    {len(vtables)}/{len(VTABLES)}')
    for n, v in sorted(vtables.items()):
        old = v.get('oldRva', hex(VTABLES.get(n, 0)))
        print(f'   {n:20} {old:>12} -> {v["newRva"]:>12}  COL={v.get("colOffset")}')
    print(f'metaobjects {len(metas)}/{len(METAOBJECTS)}')
    for n, v in sorted(metas.items()):
        old = v.get('oldRva', hex(METAOBJECTS.get(n, (0,))[0]))
        print(f'   {n:20} {old:>12} -> {v["newRva"]:>12}')
    if missing:
        print(f'UNRESOLVED functions: {[(n, hex(o)) for n, o in missing]}')
    if vt_missing:
        print(f'UNRESOLVED vtables  : {[(n, hex(o)) for n, o in vt_missing]}')
    print(f'written: {out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
