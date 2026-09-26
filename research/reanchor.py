"""Version-adaptive re-anchoring for the WeChat native adapter.

Weixin.dll is replaced without warning, so the adapter must not depend on a
frozen SHA-256 and hand-copied RVAs. This tool derives a signature for every
semantic anchor from a known-good disassembly record and relocates those
anchors in an arbitrary new build.

Two signature tiers, strongest first:

* masked bytes  - the old raw machine code with every address-bearing field
  zeroed (call/jmp rel32 and rip-relative disp32). A recompile moves those
  fields but leaves the surrounding encodings intact, so this survives a
  rebuild while staying far more specific than instruction shapes.
* instruction shape - mnemonic plus operands, with large immediates collapsed
  to BIG and small ones kept, since frame sizes and struct offsets are stable
  across a rebuild but call targets are not.

Candidates are ranked by tier, then by how many leading instructions match.
Anything still tied at the top is reported ambiguous rather than guessed at:
a wrong anchor is worse than a known gap, because the adapter would attach to
an unrelated function and silently read the wrong memory.
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
sys.path.insert(0, str(HERE / 'tool-libs'))
import capstone
import pefile
from capstone.x86_const import X86_REG_RIP

MAXINS = 16
SCAN_BYTES = 128
BYTE_PREFIX = 64
MIN_INS = 3          # floor for shape matches
DLL_BASE = 0x180000000

# Semantic anchors: the name says what the adapter does with the site, so the
# mapping stays meaningful after re-anchoring.
ANCHORS = {
    'QtFromUtf8': 0x27F80,
    'QtDestroyQString': 0x14E0,
    'XTextViewSetText': 0x1E80D40,
    'WidgetMetaCall': 0x5BBFC0,
    'ChatTextItemViewUpdate': 0x1BC6490,
    'IsSelf': 0x5C41810,
    'MetaCast': 0x28C390,
    'VerticalScrollBar': 0xCE87B0,
    'SliderMetaCall': 0x20B4600,
    'SetValue': 0x20B34A0,
    'BuildCtor': 0x1BC8640,
    'QtDecode1': 0x2C4A00,
    'QtDecode2': 0x2C4AA0,
    'QtDataFree': 0x38930,
    'QtHelper': 0x27E30,
    'BindingCtor': 0x3CFF540,
    'CtorLvl2': 0x5C7D4A0,
    'CtorLvl3': 0x5C3C210,
    'UIMsgDefCtor': 0xA58F00,
    'BaseUpdater': 0x5C3DE20,
    'TextOverride': 0x3D01B40,
    'FieldCopy': 0xA2BDC0,
    'ListenerSave': 0x3CF0E40,
    'ListenerNotify': 0x3CF2250,
    'FilterPred': 0x3E2B8E0,
    'FilterPredB': 0x3E2BAB0,
    'MsgCopyCtor': 0x1A5B50,
    'ListenerKeySetter': 0x3E28DE0,
    'ConvSwitchInit': 0x3DE5E90,
    'QQMailCmp': 0xB9D850,
    'NotifyCmp': 0xB9E2A0,
    'NewsAppCmp': 0xB9D4A0,
    'KeyLeaf': 0x7B9000,
    'CompositeKey': 0x227A000,
    'KeyFormat': 0xA17360,
    'TsForward': 0xA17160,
    'TsFlag': 0xA1D4F0,
    'SelfSentCmp': 0xA19E60,
    'AcctId': 0x45D10,
    'LeafBinding120': 0x3B4DD0,
    'TextGetter': 0x3D00D20,
    'BindingSource1': 0x1BC5590,
    'DynamicCastSite': 0x1BC5E20,
    'XTextViewAlt': 0x1E80CB0,
}

_HEX = re.compile(r'0x[0-9a-f]+')
_MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_MD.detail = True


def collapse(text: str) -> str:
    """Normalize one instruction line to a recompile-stable shape."""
    def repl(match):
        return 'BIG' if int(match.group(0), 16) >= 0x10000 else match.group(0)
    return _HEX.sub(repl, re.sub(r'\s+', ' ', text.strip().lower()))


def shape_of(insn) -> str:
    return collapse(insn.mnemonic + ' ' + insn.op_str)


def mask_bytes(code: bytes, base: int) -> bytes:
    """Zero every address-bearing field, keeping the surrounding encoding.

    A recompile relocates call targets and rip-relative data, but the opcode,
    ModRM and small displacements around them are unchanged. Masking exactly
    those fields yields a signature that spans a new build.
    """
    out = bytearray(code)
    for insn in _MD.disasm(code, base):
        rel = []
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_IMM and op.size == 4 and \
                    insn.mnemonic.split()[0] in ('call', 'jmp', 'je', 'jne', 'jz', 'jnz',
                                                 'jg', 'jl', 'jle', 'jge', 'ja', 'jb',
                                                 'jbe', 'jae', 'js', 'jns', 'jo', 'jno',
                                                 'jp', 'jnp'):
                rel.append(op.size)
            elif op.type == capstone.x86.X86_OP_MEM and op.mem.base == X86_REG_RIP:
                rel.append(4)
        for size in rel:
            start = insn.address - base + insn.size - size
            out[start:start + size] = b'\x00' * size
    return bytes(out)


def read_asm_bytes(path: Path, limit: int):
    """Parse `<hex offset>  <hex bytes...>  <mnemonic>` lines from an asm dump."""
    out = bytearray()
    for line in path.read_text(encoding='utf-8', errors='replace').splitlines():
        match = re.match(r'^([0-9a-f]{8})\s+((?:[0-9a-f]{2} ?)+)', line.strip())
        if match:
            out += bytes.fromhex(match.group(2).replace(' ', ''))
        if len(out) >= limit:
            break
    return bytes(out[:limit])


def build_signatures():
    """Derive byte and shape signatures for every anchor we have records for."""
    shape_records = {}
    for path in sorted(glob.glob(str(HERE / 'layout-disassembly-*.json'))):
        try:
            payload = json.loads(Path(path).read_text(encoding='utf-8'))
        except Exception:
            continue
        for record in (payload if isinstance(payload, list) else [payload]):
            if not isinstance(record, dict) or 'rva' not in record:
                continue
            rva = int(str(record['rva']), 16)
            shapes = []
            for line in record.get('instructions', []):
                shape = collapse(line.split(':', 1)[1] if ':' in line else line)
                if not shape:
                    continue
                shapes.append(shape)
                # Stop at the first ret: records sometimes splice a cold tail
                # after the terminator, and that tail is not contiguous in the
                # rebuilt function, so keeping it would defeat full matches.
                if shape.startswith('ret'):
                    break
            shapes = shapes[:MAXINS]
            if shapes and len(shapes) > len(shape_records.get(rva, ())):
                shape_records[rva] = shapes

    byte_records = {}
    for path in sorted(glob.glob(str(HERE / '*.asm.txt'))):
        match = re.search(r'0x([0-9a-f]{4,9})\.asm\.txt$', path)
        if not match:
            continue
        rva = int(match.group(1), 16)
        raw = read_asm_bytes(Path(path), SCAN_BYTES)
        if raw:
            byte_records[rva] = mask_bytes(raw, DLL_BASE + rva)[:BYTE_PREFIX]

    anchors, missing = {}, []
    for name, rva in sorted(ANCHORS.items()):
        entry = {'oldRva': hex(rva)}
        if rva in byte_records:
            entry['bytes'] = byte_records[rva].hex()
        if rva in shape_records:
            entry['shape'] = shape_records[rva]
        if 'bytes' in entry or 'shape' in entry:
            anchors[name] = entry
        else:
            missing.append([name, hex(rva)])
    return anchors, missing


def cmd_build_sig(args):
    anchors, missing = build_signatures()
    nbytes = sum(1 for a in anchors.values() if 'bytes' in a)
    nshape = sum(1 for a in anchors.values() if 'shape' in a)
    Path(args.out).write_text(json.dumps(
        {'maxins': MAXINS, 'bytePrefix': BYTE_PREFIX, 'anchors': anchors,
         'missing': missing}, indent=1), encoding='utf-8')
    print(f'anchors with byte signature : {nbytes}')
    print(f'anchors with shape signature: {nshape}')
    print(f'no record at all            : {len(missing)} {missing if missing else ""}')
    print(f'written                     : {args.out}')


def cmd_scan(args):
    db = json.loads(Path(args.signatures).read_text(encoding='utf-8'))['anchors']
    raw = Path(args.dll).read_bytes()
    pe = pefile.PE(data=raw, fast_load=True)
    text = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.text')
    tva, tbytes = text.VirtualAddress, text.get_data()
    exception = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    edata = pe.get_data(exception.VirtualAddress, exception.Size)
    pe.close()
    starts = sorted({a for a, b, _ in struct.iter_unpack('<III', edata) if a and b > a})
    print(f'PE function starts: {len(starts)}')

    def shapes_at(rva):
        offset = rva - tva
        if offset < 0 or offset + 4 > len(tbytes):
            return []
        return [shape_of(i) for i in _MD.disasm(tbytes[offset:offset + SCAN_BYTES],
                                                DLL_BASE + rva)][:MAXINS]

    def prefix_len(want, got):
        matched = 0
        while matched < len(want) and matched < len(got) and want[matched] == got[matched]:
            matched += 1
        return matched

    # Index the shape tier by opening mnemonic so most functions are rejected on
    # a single decode. The byte tier runs separately against the whole section.
    shape_index = {}
    for name, anchor in db.items():
        if 'shape' in anchor:
            shape_index.setdefault(anchor['shape'][0], []).append(name)

    hits = {name: [] for name in db}

    # Tier 0: identity. Many Qt-level helpers keep both their address and their
    # bytes across a rebuild, so test the old RVA before searching anywhere.
    for name, anchor in db.items():
        want = anchor.get('shape') or []
        if not want:
            continue
        got = shapes_at(int(anchor['oldRva'], 16))
        matched = prefix_len(want, got)
        if matched == len(want):
            hits[name].append(('identity', matched, int(anchor['oldRva'], 16)))

    # Tier 1: masked bytes, searched at every offset because a rebuilt function
    # need not land on the old .pdata boundary or on any recorded one.
    for name, anchor in db.items():
        if 'bytes' not in anchor:
            continue
        want = bytes.fromhex(anchor['bytes'])
        probe = want[:8]
        at = tbytes.find(probe)
        while at != -1:
            rva = tva + at
            masked = mask_bytes(tbytes[at:at + SCAN_BYTES], DLL_BASE + rva)
            size = min(len(want), len(masked))
            if size >= 12 and masked[:size] == want[:size]:
                hits[name].append(('bytes', size, rva))
            at = tbytes.find(probe, at + 1)

    # Tier 2: instruction shapes at recorded function starts.
    for rva in starts:
        offset = rva - tva
        if offset < 0 or offset + 4 > len(tbytes):
            continue
        head = next(_MD.disasm(tbytes[offset:offset + 16], DLL_BASE + rva), None)
        if head is None:
            continue
        names = shape_index.get(shape_of(head))
        if not names:
            continue
        got = shapes_at(rva)
        for name in names:
            want = db[name]['shape']
            matched = prefix_len(want, got)
            if matched >= min(MIN_INS, len(want)):
                hits[name].append(('shape', matched, rva))

    tier_rank = {'identity': 0, 'bytes': 1, 'shape': 2}
    resolved, ambiguous, unresolved = {}, {}, []
    for name in sorted(db):
        ranked = sorted(hits[name], key=lambda x: (tier_rank[x[0]], -x[1], x[2]))
        if not ranked:
            unresolved.append(name)
            continue
        best = ranked[0]
        # Only same-tier, same-strength hits compete; a strong tier always wins.
        same = [x for x in ranked if x[0] == best[0] and x[1] == best[1]]
        entry = {'oldRva': db[name]['oldRva'], 'newRva': hex(best[2]),
                 'tier': best[0], 'matched': best[1],
                 'runnersUp': [f'{t}:{hex(r)}' for t, _, r in ranked[1:4]]}
        if len({x[2] for x in same}) > 1:
            ambiguous[name] = entry | {'distinctCandidates': len({x[2] for x in same}),
                                       'candidates': [hex(x[2]) for x in same[:6]]}
        else:
            resolved[name] = entry

    sha = hashlib.sha256(raw).hexdigest()
    out = Path(args.out or f'anchors-{sha[:8]}.json')
    out.write_text(json.dumps(
        {'dll': str(args.dll), 'sha256': sha, 'size': len(raw),
         'resolved': resolved, 'ambiguous': ambiguous, 'unresolved': unresolved},
        indent=1), encoding='utf-8')
    counts = {}
    for value in resolved.values():
        counts[value['tier']] = counts.get(value['tier'], 0) + 1
    print(f'resolved         : {len(resolved)}/{len(db)}  {counts}')
    print(f'ambiguous        : {len(ambiguous)} {sorted(ambiguous)}')
    print(f'unresolved       : {len(unresolved)} {unresolved}')
    print(f'written          : {out}')


def hits_any(hits):
    return any(hits.values())


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd', required=True)
    build = sub.add_parser('build-sig')
    build.add_argument('--out', default='anchor-signatures.json')
    build.set_defaults(func=cmd_build_sig)
    scan = sub.add_parser('scan')
    scan.add_argument('--dll', required=True)
    scan.add_argument('--signatures', default='anchor-signatures.json')
    scan.add_argument('--out')
    scan.set_defaults(func=cmd_scan)
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
