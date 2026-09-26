"""Read-only disassembly of identified wrapper functions; never loads the DLL."""
from pathlib import Path
import bisect
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tool-libs"))
import capstone
import pefile


def main():
    evidence = json.loads((ROOT / "native-storage-candidates.json").read_text(encoding="utf-8"))
    data = Path(evidence["path"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != evidence["sha256"]:
        raise RuntimeError("DLL changed since the candidate analysis; refusing stale RVAs")
    pe = pefile.PE(data=data, fast_load=True)
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    entries = pe.get_data(directory.VirtualAddress, directory.Size)
    ranges = sorted((a, b) for a, b, _ in struct.iter_unpack("<III", entries) if a < b)
    starts = [a for a, _ in ranges]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    targets = [int(value, 0) for value in sys.argv[1:]] or [0x180e350, 0x3965ef0, 0xa54240]
    for target in targets:
        index = bisect.bisect_right(starts, target) - 1
        if index < 0 or not ranges[index][0] <= target < ranges[index][1]:
            raise ValueError(f"No .pdata function for {target:#x}")
        start, end = ranges[index]
        instructions = list(md.disasm(pe.get_data(start, end - start), start))
        rendered = "\n".join(f"{insn.address:08x}  {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}"
                             for insn in instructions)
        output = ROOT / f"storage-wrapper-{start:#x}.asm.txt"
        output.write_text(rendered, encoding="utf-8")
        print(f"{start:#x}..{end:#x}: {len(instructions)} instructions -> {output.name}")


if __name__ == "__main__":
    main()
