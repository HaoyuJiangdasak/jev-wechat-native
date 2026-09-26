"""Read-only PE analysis. Never attaches to WeChat or calls located addresses.

Uses published RevokeHook string anchors as research hypotheses. Results are
static candidates, not a supported adapter or proof of call/argument safety.
"""
from pathlib import Path
import bisect
import hashlib
import json
import re
import struct
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'tool-libs'))
import capstone
import pefile

IMAGE = Path(r'C:\Program Files\Tencent\Weixin\4.1.15.11\Weixin.dll')


def main():
    data = IMAGE.read_bytes()
    pe = pefile.PE(data=data, fast_load=True)
    sections = {s.Name.rstrip(b'\0').decode(): s for s in pe.sections}
    text, rdata, pdata = (sections[n] for n in ('.text', '.rdata', '.pdata'))
    exception_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    unwind_records = pe.get_data(exception_dir.VirtualAddress, exception_dir.Size)
    ranges = sorted((a, b) for a, b, _ in struct.iter_unpack('<III', unwind_records) if a < b)
    starts = [r[0] for r in ranges]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    cache = {}

    def function_at(rva):
        i = bisect.bisect_right(starts, rva) - 1
        return ranges[i] if i >= 0 and rva < ranges[i][1] else None

    def instructions(start):
        if start not in cache:
            bounds = function_at(start)
            if not bounds or bounds[0] != start:
                cache[start] = []
            else:
                cache[start] = list(md.disasm(pe.get_data(start, bounds[1]-start), start))
        return cache[start]

    def calls(start):
        return [(i.address, i.operands[0].imm) for i in instructions(start)
                if i.mnemonic == 'call' and len(i.operands) == 1
                and i.operands[0].type == capstone.CS_OP_IMM]

    def path_to(start, target, depth=3, seen=(), min_root=0, require_zero_r8=False):
        if depth <= 0 or start in seen:
            return None
        for location, dest in calls(start):
            if location <= min_root:
                continue
            if require_zero_r8:
                preceding = [i for i in instructions(start) if location-24 <= i.address < location]
                if not any(i.mnemonic == 'xor' and i.op_str == 'r8d, r8d' for i in preceding):
                    continue
            step = {'call_rva': hex(location), 'caller_rva': hex(start), 'target_rva': hex(dest)}
            if dest == target:
                return [step]
            child = path_to(dest, target, depth-1, seen+(start,))
            if child:
                return [step] + child
        return None

    config = json.loads((HERE / 'source-notes/revokehook-config3.json').read_text(encoding='utf-8-sig'))
    anchors = {}
    matches = []
    names = {'sig1': 'CoReplaceOriginMessageByRevoke', 'sig2': 'DeleteMessages', 'sig3': 'CoAddMessageToDB'}
    rb = rdata.get_data()
    for version, sigs in config.items():
        for key, sig in sigs.items():
            needle = bytes.fromhex(sig)
            pos = rb.find(needle)
            offsets = []
            while pos >= 0:
                rva = rdata.VirtualAddress + pos
                offsets.append(hex(rva))
                anchors.setdefault(rva, []).append({'version': version, 'name': names[key]})
                pos = rb.find(needle, pos+1)
            matches.append({'version': version, 'name': names[key], 'string_rvas': offsets})
    candidates = []
    for hit in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', text.get_data()):
        p = hit.start()
        rva = text.VirtualAddress+p
        disp = struct.unpack_from('<i', data, text.PointerToRawData+p+3)[0]
        target = rva+7+disp
        if target not in anchors:
            continue
        bounds = function_at(rva)
        if not bounds:
            continue
        insn = next((i for i in instructions(bounds[0]) if i.address == rva), None)
        if not insn or insn.mnemonic != 'lea':
            continue
        for anchor in anchors[target]:
            candidates.append(dict(anchor, string_rva=hex(target), lea_rva=hex(rva),
                                   function_rva=hex(bounds[0]), end_rva=hex(bounds[1]),
                                   instruction=insn.mnemonic+' '+insn.op_str))
    candidates = list({(c['name'],c['function_rva']):c for c in reversed(candidates)}.values())
    chains = []
    for origin in candidates:
        if origin['name'] != names['sig1']:
            continue
        for target in candidates:
            if target['name'] == names['sig1']:
                continue
            path = path_to(int(origin['function_rva'],16), int(target['function_rva'],16))
            if path:
                chains.append({'origin': origin['function_rva'], 'target_name':target['name'],
                               'target':target['function_rva'], 'calls':path})
    selected_chains = []
    by_name = {c['name']:int(c['function_rva'],16) for c in candidates}
    if len(by_name) == 3:
        origin = by_name[names['sig1']]
        deletion = path_to(origin, by_name[names['sig2']], require_zero_r8=True)
        if deletion:
            insertion = path_to(origin, by_name[names['sig3']], min_root=int(deletion[0]['call_rva'],16))
            if insertion:
                selected_chains = [{'name':'zero_argument_delete_path','calls':deletion},
                                   {'name':'subsequent_add_path','calls':insertion}]
    report = {'status':'static_research_only_not_callable', 'path':str(IMAGE),
              'sha256':hashlib.sha256(data).hexdigest(), 'machine':hex(pe.FILE_HEADER.Machine),
              'image_base':hex(pe.OPTIONAL_HEADER.ImageBase), 'signature_matches':matches,
              'candidates':candidates, 'call_chains':chains, 'selected_chains':selected_chains}
    out = HERE/'native-storage-candidates.json'
    out.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('status','sha256','candidates','selected_chains')},ensure_ascii=False,indent=2))
    for candidate in candidates:
        start = int(candidate['function_rva'],16)
        path = HERE/(candidate['name']+'-'+hex(start)+'.asm.txt')
        path.write_text('\n'.join(f'{i.address:08x}  {i.bytes.hex():<30} {i.mnemonic} {i.op_str}'
                                  for i in instructions(start)),encoding='utf-8')


if __name__ == '__main__':
    main()
