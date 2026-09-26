"""Read-only, bounded displacement references in chat-related native code."""
from pathlib import Path
import bisect
import json
import struct
import sys
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tool-libs'))
import capstone
from capstone.x86_const import X86_OP_MEM, X86_REG_RBP, X86_REG_RSP, X86_REG_RIP
import pefile

field = int(sys.argv[1], 0)
low = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x1b00000
high = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x3f00000
pe = pefile.PE(r'C:\Program Files\Tencent\Weixin\4.1.15.11\Weixin.dll', fast_load=True)
d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
ranges = sorted((a, b) for a, b, _ in struct.iter_unpack('<III', pe.get_data(d.VirtualAddress, d.Size)) if a < b)
starts = [a for a, b in ranges]
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
functions = set()
needle = struct.pack('<i', field)
for section in pe.sections:
    if not section.Characteristics & 0x20000000:
        continue
    blob = section.get_data()
    pos = blob.find(needle)
    while pos >= 0:
        address = section.VirtualAddress + pos
        if low <= address < high:
            index = bisect.bisect_right(starts, address) - 1
            if index >= 0 and address < ranges[index][1]:
                functions.add(ranges[index])
        pos = blob.find(needle, pos + 1)
rows = []
for begin, end in sorted(functions):
    instructions = list(md.disasm(pe.get_data(begin, end - begin), begin))
    for n, ins in enumerate(instructions):
        matching = [op for op in ins.operands if op.type == X86_OP_MEM and op.mem.disp == field and op.mem.base not in (X86_REG_RBP, X86_REG_RSP, X86_REG_RIP)]
        if matching:
            rows.append({'function': hex(begin), 'address': hex(ins.address), 'write': any(op.access & capstone.CS_AC_WRITE for op in matching), 'context': [f'{i.address:08x}: {i.mnemonic} {i.op_str}' for i in instructions[max(0, n-7):n+4]]})
out = ROOT / f'chat-field-{field:x}-{low:x}-{high:x}.json'
out.write_text(json.dumps(rows, indent=2), encoding='utf-8')
print(json.dumps([row for row in rows if row['write']], indent=2))
print(f'{len(rows)} references saved to {out.name}')
