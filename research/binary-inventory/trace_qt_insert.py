"""Disassemble an identified Qt slot on disk; no DLL loading or invocation."""
import bisect
import json
from pathlib import Path
import struct
import sys

import pefile

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "tool-libs"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

DLL = Path(r"C:\Program Files\Tencent\Weixin\4.1.15.11\Weixin.dll")
pe = pefile.PE(str(DLL), fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
runtime_functions = list(struct.iter_unpack("<III", pe.get_data(directory.VirtualAddress, directory.Size)))
begins = [row[0] for row in runtime_functions]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def function(rva):
    index = bisect.bisect_right(begins, rva) - 1
    begin, end, unwind = runtime_functions[index]
    if not begin <= rva < end:
        raise ValueError("RVA does not resolve to a runtime function")
    instructions = []
    references = []
    for ins in md.disasm(pe.get_data(begin, end - begin), base + begin):
        line = f"{ins.address-base:08x}: {ins.mnemonic:8} {ins.op_str}"
        instructions.append(line)
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                address = ins.address + ins.size + op.mem.disp
                target = address - base
                if 0 <= target < pe.OPTIONAL_HEADER.SizeOfImage:
                    sample = pe.get_data(target, 200)
                    text = sample.split(b"\0", 1)[0]
                    text = text.decode("ascii") if len(text) >= 5 and all(32 <= c <= 126 for c in text) else None
                    references.append({"from_rva": hex(ins.address-base), "to_rva": hex(target), "ascii": text})
    return {"begin": hex(begin), "end": hex(end), "disassembly": instructions, "references": references}


if __name__ == "__main__":
    report = function(0x1BF9EE0)
    (ROOT / "qt-insert-slot.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / "qt-insert-slot.txt").write_text("\n".join(report["disassembly"]), encoding="utf-8")
    print(json.dumps({k:v for k,v in report.items() if k != "disassembly"}, ensure_ascii=False))
    print("\n".join(report["disassembly"]))
