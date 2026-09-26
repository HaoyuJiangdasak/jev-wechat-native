"""Decode static Qt 5 moc string tables and metaobjects without loading the DLL."""
import json
from pathlib import Path
import struct
import sys

import pefile

ROOT = Path(__file__).resolve().parent
DLL = Path(r"C:\Program Files\Tencent\Weixin\4.1.15.11\Weixin.dll")
data = DLL.read_bytes()
pe = pefile.PE(str(DLL), fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
targets = ["mmui::ChatInputView", "mmui::MessageView", "mmui::ChatMessagePage",
           "mmui::ChatBotSystemMessageItemView"]
results = []


def rva(offset):
    return pe.get_rva_from_offset(offset)


for target in targets:
    text = target.encode()
    position = data.find(text + b"\0", 0xA000000)
    found = {"class": target, "string_offset": hex(position), "string_rva": hex(rva(position))}
    for header in range(max(0, position - 24000), position, 8):
        ref, length, alloc, pad, relative = struct.unpack_from("<iiIIq", data, header)
        if ref == -1 and length == len(text) and alloc == 0 and header + relative == position:
            count = (position - header) // 24
            if count * 24 != position - header:
                continue
            strings = []
            for index in range(count):
                offset = header + index * 24
                ref, length, alloc, pad, relative = struct.unpack_from("<iiIIq", data, offset)
                if ref != -1 or alloc or not 0 <= length < 10000:
                    break
                start = offset + relative
                strings.append(data[start:start+length].decode("utf-8", "replace"))
            else:
                found.update(string_table_offset=hex(header), string_table_rva=hex(rva(header)), strings=strings)
                address = base + rva(header)
                pointer = struct.pack("<Q", address)
                metaobjects = []
                start = 0
                while True:
                    pointer_at = data.find(pointer, start)
                    if pointer_at < 0:
                        break
                    start = pointer_at + 8
                    object_offset = pointer_at - 8
                    fields = struct.unpack_from("<6Q", data, object_offset)
                    item = {"offset": hex(object_offset), "rva": hex(rva(object_offset)),
                            "fields": [hex(x) for x in fields]}
                    if base <= fields[2] < base + pe.OPTIONAL_HEADER.SizeOfImage:
                        try:
                            table = pe.get_offset_from_rva(fields[2] - base)
                            head = list(struct.unpack_from("<14I", data, table))
                            item["metadata_header"] = head
                            if head[0] <= 10 and head[1] < count and head[4] < 200:
                                methods = []
                                for method in range(head[4]):
                                    row = list(struct.unpack_from("<5I", data, table + (head[5] + method*5) * 4))
                                    name, argc, params, tag, flags = row
                                    values = list(struct.unpack_from("<"+"I"*(1+2*argc), data, table+params*4))
                                    def typename(v):
                                        return strings[v & 0x7FFFFFFF] if v & 0x80000000 and (v & 0x7FFFFFFF) < count else v
                                    methods.append({"index": method, "name": strings[name] if name < count else name,
                                                    "argc": argc, "flags": hex(flags), "row": row,
                                                    "return_and_parameter_types": [typename(v) for v in values[:1+argc]],
                                                    "parameter_names": [strings[v] if v < count else v for v in values[1+argc:]]})
                                item["methods"] = methods
                        except Exception as error:
                            item["decode_error"] = str(error)
                    metaobjects.append(item)
                found["metaobjects"] = metaobjects
                break
    results.append(found)

text = json.dumps(results, ensure_ascii=False, indent=2)
(ROOT / "qt-metadata.json").write_text(text, encoding="utf-8")
sys.stdout.reconfigure(encoding="utf-8")
print(text)
