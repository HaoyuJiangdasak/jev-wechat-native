"""Read-only direct CALL references for native chat text dataflow research."""
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
    raw = Path(evidence["path"]).read_bytes()
    if hashlib.sha256(raw).hexdigest() != evidence["sha256"]:
        raise RuntimeError("Target DLL changed")
    pe = pefile.PE(data=raw, fast_load=True)
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    ranges = sorted((a, b) for a, b, _ in struct.iter_unpack("<III", pe.get_data(directory.VirtualAddress, directory.Size)) if a < b)
    starts = [a for a, _ in ranges]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    targets = {int(arg, 0) for arg in sys.argv[1:]} or {0x1bc6490, 0x1bc5e20}
    refs = {hex(target): [] for target in targets}
    cache = {}
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        blob = section.get_data()
        at = blob.find(b"\xe8")
        while at >= 0 and at + 5 <= len(blob):
            address = section.VirtualAddress + at
            target = address + 5 + struct.unpack_from("<i", blob, at + 1)[0]
            if target in targets:
                index = bisect.bisect_right(starts, address) - 1
                if index >= 0 and ranges[index][0] <= address < ranges[index][1]:
                    begin, end = ranges[index]
                    if begin not in cache:
                        cache[begin] = list(md.disasm(pe.get_data(begin, end - begin), begin))
                    insns = cache[begin]
                    for n, ins in enumerate(insns):
                        if ins.address == address and ins.mnemonic == "call":
                            refs[hex(target)].append({"function": hex(begin), "call": hex(address), "context": [f"{i.address:08x}: {i.mnemonic} {i.op_str}" for i in insns[max(0, n - 14):n + 4]]})
                            break
            at = blob.find(b"\xe8", at + 1)
    out = ROOT / ("text-dataflow-calls-" + "-".join(f"{i:x}" for i in sorted(targets)) + ".json")
    out.write_text(json.dumps(refs, indent=2), encoding="utf-8")
    print(json.dumps(refs, indent=2))


if __name__ == "__main__":
    main()
