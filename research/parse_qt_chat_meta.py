"""Parse Qt 5 metadata from installed DLL bytes, never from process memory."""
from pathlib import Path
import json
import re
import struct

PATH = Path("C:/Program Files/Tencent/Weixin/4.1.15.11/Weixin.dll")
TARGETS = ["mmui::ChatItemView", "mmui::ChatTextItemView", "mmui::ChatBubbleFrame",
           "mmui::ChatBubbleItemView", "mmui::ChatSystemInfoItemView", "mmui::ChatDetailView",
           "mmui::XRecyclerTableView", "mmui::XTextView", "mmui::XView"]
TYPES = {0: "Unknown", 1: "bool", 2: "int", 3: "uint", 6: "double", 10: "QString",
         11: "QStringList", 12: "QByteArray", 19: "QRect", 20: "QRectF", 21: "QSize",
         22: "QSizeF", 25: "QPoint", 26: "QPointF", 38: "float", 43: "void",
         67: "QColor"}


class Image:
    def __init__(self):
        self.data = PATH.read_bytes()
        pe = self.unpack("I", 0x3c)[0]
        count, optional_size = self.unpack("H", pe + 6)[0], self.unpack("H", pe + 20)[0]
        optional = pe + 24
        assert self.unpack("H", optional)[0] == 0x20b
        self.base = self.unpack("Q", optional + 24)[0]
        self.sections = [self.unpack("8sIIIIIIHHI", optional + optional_size + i * 40) for i in range(count)]

    def unpack(self, fmt, offset):
        return struct.unpack_from("<" + fmt, self.data, offset)

    def va(self, offset):
        for section in self.sections:
            if section[4] <= offset < section[4] + section[3]:
                return self.base + section[2] + offset - section[4]
        raise ValueError("unmapped file offset")

    def off(self, va):
        rva = va - self.base
        for section in self.sections:
            if section[2] <= rva < section[2] + section[3]:
                return section[4] + rva - section[2]
        raise ValueError("unmapped virtual address")

    def string(self, table, index):
        entry = table + index * 24
        ref, size, alloc, _, offset = self.unpack("iiiIq", entry)
        assert ref == -1 and 0 <= size < 10000 and alloc == 0
        return self.data[entry + offset:entry + offset + size].decode("utf-8")

    def metadata(self, at):
        parent, strings, info, call, related, extra = self.unpack("6Q", at)
        table, info = self.off(strings), self.off(info)
        fields = self.unpack("14I", info)
        assert fields[0] == 8 and fields[1] == 0 and fields[4] < 1000 and fields[6] < 1000
        class_name = self.string(table, 0)

        def type_name(number):
            return self.string(table, number & 0x7fffffff) if number & 0x80000000 else TYPES.get(number, "QMetaType#" + str(number))

        methods = []
        for index in range(fields[4]):
            name, argc, parameters, tag, flags = self.unpack("5I", info + (fields[5] + index * 5) * 4)
            params = self.unpack("I" * (1 + 2 * argc), info + parameters * 4)
            arguments = [{"type": type_name(params[1 + i]), "name": self.string(table, params[1 + argc + i])} for i in range(argc)]
            methods.append({"local_index": index, "name": self.string(table, name), "arguments": arguments,
                            "return": type_name(params[0]), "kind": {0: "method", 4: "signal", 8: "slot", 12: "constructor"}.get(flags & 12),
                            "access": {0: "private", 1: "protected", 2: "public"}.get(flags & 3), "flags": hex(flags)})
        properties = []
        for index in range(fields[6]):
            name, type_id, flags = self.unpack("3I", info + (fields[7] + index * 3) * 4)
            properties.append({"local_index": index, "name": self.string(table, name), "type": type_name(type_id),
                               "readable": bool(flags & 1), "writable": bool(flags & 2), "flags": hex(flags)})
        return {"class": class_name, "static_metaobject_rva": hex(self.va(at) - self.base),
                "string_table_rva": hex(strings - self.base), "metadata_rva": hex(self.va(info) - self.base),
                "static_metacall_rva": hex(call - self.base) if call else None,
                "parent_metaobject_rva": hex(parent - self.base) if parent else None,
                "own_methods": methods, "own_properties": properties}

    def find_meta(self, name):
        target = name.encode("utf-8")
        needle = struct.pack("<ii", -1, len(target))
        for match in re.finditer(re.escape(needle), self.data):
            table = match.start()
            try:
                if self.string(table, 0) != name:
                    continue
                pointer = struct.pack("<Q", self.va(table))
                for ref in re.finditer(re.escape(pointer), self.data):
                    at = ref.start() - 8
                    try:
                        result = self.metadata(at)
                        if result["class"] == name:
                            return result
                    except (ValueError, AssertionError, UnicodeError, struct.error):
                        pass
            except (ValueError, AssertionError, UnicodeError, struct.error):
                pass
        return None


def main():
    image = Image()
    classes = {}
    for name in TARGETS:
        current = image.find_meta(name)
        while current and current["class"] not in classes:
            classes[current["class"]] = current
            parent = current["parent_metaobject_rva"]
            current = image.metadata(image.off(image.base + int(parent, 16))) if parent else None
    output = {"target": str(PATH), "image_base": hex(image.base), "classes": classes,
              "limitations": "Only Qt MOC-exposed members are enumerated; ordinary C++ methods, fields, inheritance beyond Qt metaobjects and live widget instances are not resolved."}
    out = Path(__file__).with_name("qt-chat-meta.json")
    out.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for name, meta in classes.items():
        methods = meta["own_methods"]
        properties = meta["own_properties"]
        if name not in TARGETS:
            methods = [m for m in methods if re.search("text|layout|update|refresh|size|height|child|objectName|delete", m["name"], re.I)]
            properties = [p for p in properties if re.search("text|layout|size|height|objectName", p["name"], re.I)]
        print(json.dumps({"class": name, "static_metaobject_rva": meta["static_metaobject_rva"],
                          "static_metacall_rva": meta["static_metacall_rva"],
                          "own_methods": methods, "own_properties": properties}, ensure_ascii=True))


if __name__ == "__main__":
    main()
