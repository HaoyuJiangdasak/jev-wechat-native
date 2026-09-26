"""Locate on-disk byte-field writes at displacement 0x1c4; no process access."""
import bisect
import json
from pathlib import Path
import re
import struct
import sys

import pefile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "tool-libs"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM

pe = pefile.PE(r"C:\Program Files\Tencent\Weixin\4.1.15.11\Weixin.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
section = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
data = section.get_data()
directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
functions = list(struct.iter_unpack("<III", pe.get_data(directory.VirtualAddress, directory.Size)))
starts = [x[0] for x in functions]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
candidates = set()
for match in re.finditer(b"\xc4\x01\x00\x00", data):
    for offset in range(max(0, match.start()-8), match.start()):
        instruction = next(md.disasm(data[offset:offset+16], section.VirtualAddress+offset, 1), None)
        if instruction is None or not instruction.operands:
            continue
        target = instruction.operands[0]
        if (target.type == X86_OP_MEM and target.size == 1 and target.mem.disp == 0x1C4
                and instruction.mnemonic in ("mov", "sete", "setne", "seta", "setb", "and", "or", "xor")):
            index = bisect.bisect_right(starts, instruction.address) - 1
            if index >= 0 and functions[index][0] <= instruction.address < functions[index][1]:
                candidates.add(functions[index][:2])
results = []
for begin,end in sorted(candidates):
    instructions = list(md.disasm(pe.get_data(begin, end-begin), begin))
    for i,ins in enumerate(instructions):
        if not ins.operands:
            continue
        target = ins.operands[0]
        if (target.type == X86_OP_MEM and target.size == 1 and target.mem.disp == 0x1C4
                and ins.mnemonic in ("mov", "sete", "setne", "seta", "setb", "and", "or", "xor")):
            results.append({"function":hex(begin),"end":hex(end), "writer":hex(ins.address),
                            "instruction":ins.mnemonic+" "+ins.op_str,
                            "context":[f"{n.address:08x} {n.mnemonic} {n.op_str}" for n in instructions[max(0,i-8):i+5]]})
(ROOT/'sender-flag-writers.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
print(json.dumps(results,indent=2))
