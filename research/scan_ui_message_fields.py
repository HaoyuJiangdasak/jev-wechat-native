"""Bounded read-only field use scan, including x86 disp8 encodings."""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tool-libs'))
import capstone
from capstone.x86_const import X86_OP_MEM, X86_REG_RBP, X86_REG_RSP, X86_REG_RIP
import pefile

low = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0xa10000
high = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0xa40000
fields = {int(x, 0) for x in sys.argv[3:]} or {0x10, 0x30, 0x50, 0x70}
evidence = json.loads((ROOT / 'native-storage-candidates.json').read_text())
raw = Path(evidence['path']).read_bytes()
assert hashlib.sha256(raw).hexdigest() == evidence['sha256']
pe = pefile.PE(data=raw, fast_load=True)
directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
ranges = sorted((a, b) for a, b, _ in struct.iter_unpack('<III', pe.get_data(directory.VirtualAddress, directory.Size)) if low <= a < high and a < b)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
rows = []
for begin, end in ranges:
    insns = list(md.disasm(pe.get_data(begin, end-begin), begin))
    matches = []
    for n, ins in enumerate(insns):
        ops = [op for op in ins.operands if op.type == X86_OP_MEM and op.mem.disp in fields and op.mem.base not in (X86_REG_RBP, X86_REG_RSP, X86_REG_RIP)]
        if ops:
            matches.append({'field': [hex(op.mem.disp) for op in ops], 'write': any(op.access & capstone.CS_AC_WRITE for op in ops), 'address': hex(ins.address), 'context': [f'{i.address:08x}: {i.mnemonic} {i.op_str}' for i in insns[max(0,n-3):n+5]]})
    if matches:
        rows.append({'function':hex(begin), 'end':hex(end), 'instructions':len(insns), 'matches':matches})
out = ROOT / f'ui-message-fields-{low:x}-{high:x}.json'
out.write_text(json.dumps(rows, indent=2)+'\n',encoding='utf-8')
print(json.dumps([{'function': r['function'], 'instructions':r['instructions'], 'fields':sorted(set(f for m in r['matches'] for f in m['field']))} for r in rows],indent=2))
