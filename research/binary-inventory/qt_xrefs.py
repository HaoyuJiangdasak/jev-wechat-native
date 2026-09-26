"""Find static code references to the identified Qt InsertMessage signal/slot."""
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

pe = pefile.PE(r"C:\Program Files\Tencent\Weixin\4.1.15.11\Weixin.dll", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
code_section = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = code_section.get_data()
start_rva = code_section.VirtualAddress
directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
functions = list(struct.iter_unpack("<III", pe.get_data(directory.VirtualAddress, directory.Size)))
begins = [f[0] for f in functions]
targets = {0x1BF9EE0: "ChatInputView::InsertMessage slot",
           0x88DFA0: "MessageView::InsertMessage signal",
           0x3D9DDB0: "slot delegated routine"}
md = Cs(CS_ARCH_X86, CS_MODE_64)
references = []
for pattern, length, operand_offset in [(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", 7, 3),
                                        (rb"[\xe8\xe9]", 5, 1)]:
    for match in re.finditer(pattern, code):
        offset = match.start()
        if offset + length > len(code):
            continue
        here = start_rva + offset
        destination = here + length + struct.unpack_from("<i", code, offset + operand_offset)[0]
        if destination not in targets:
            continue
        instruction = next(md.disasm(code[offset:offset+length], base+here, 1), None)
        if instruction is None or instruction.size != length:
            continue
        i = bisect.bisect_right(begins, here) - 1
        function = functions[i] if i >= 0 and functions[i][0] <= here < functions[i][1] else None
        references.append({"from_rva": hex(here), "to_rva": hex(destination),
                           "label": targets[destination],
                           "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                           "containing_function": [hex(v) for v in function[:2]] if function else None})
(ROOT / "qt-insert-xrefs.json").write_text(json.dumps(references, indent=2), encoding="utf-8")
print(json.dumps(references, indent=2))
