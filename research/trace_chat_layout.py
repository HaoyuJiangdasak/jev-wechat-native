"""Static disassembly of selected rendering functions; never invokes target code."""
import bisect
import json
from pathlib import Path
import struct
import sys

from parse_qt_chat_meta import Image

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tool-libs"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


def main():
    image = Image()
    pe = image.unpack("I", 0x3c)[0]
    rva, size = image.unpack("II", pe + 24 + 112 + 3 * 8)
    start = image.off(image.base + rva)
    functions = list(struct.iter_unpack("<III", image.data[start:start + size]))
    starts = [row[0] for row in functions]
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    targets = [int(value, 0) for value in sys.argv[1:]] or [0x8890e0, 0x889820, 0x8f9950]
    results = []
    for target in targets:
        begin, end, unwind = functions[bisect.bisect_right(starts, target) - 1]
        leaf = not begin <= target < end
        if leaf:
            # Small leaf thunks have no unwind entry. Bound their linear decode
            # at the first terminal instruction; do not spill into their neighbor.
            begin, end = target, target + 128
        file_offset = image.off(image.base + begin)
        rows, refs = [], []
        for ins in disassembler.disasm(image.data[file_offset:file_offset + end - begin], image.base + begin):
            rows.append(f"{ins.address - image.base:08x}: {ins.mnemonic:8} {ins.op_str}")
            for op in ins.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    address = ins.address + ins.size + op.mem.disp
                    try:
                        off = image.off(address)
                    except ValueError:
                        continue
                    snippet = image.data[off:off + 140].split(b"\0", 1)[0]
                    text = snippet.decode("ascii") if len(snippet) > 4 and all(32 <= n < 127 for n in snippet) else None
                    refs.append({"from": hex(ins.address - image.base), "rva": hex(address - image.base), "ascii": text})
            if leaf and ins.mnemonic in ("ret", "jmp", "int3"):
                end = ins.address + ins.size - image.base
                break
        result = {"rva": hex(begin), "end": hex(end), "leaf_boundary_inferred": leaf,
                  "instructions": rows, "references": refs}
        results.append(result)
        print(json.dumps({"rva": hex(begin), "end": hex(end), "instructions": len(rows), "references": refs}, ensure_ascii=True))
        print("\n".join(rows))
    tag = "-".join(f"{target:x}" for target in targets)
    (ROOT / f"layout-disassembly-{tag}.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
