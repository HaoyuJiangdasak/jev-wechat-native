"""Read installed program files only; do not load DLLs or inspect processes."""
import collections
import hashlib
import json
import mmap
from pathlib import Path
import re
import sys
import zipfile

import pefile

ROOT = Path(r"C:\Program Files\Tencent\Weixin\4.1.15.11")
OUT = Path(__file__).resolve().parent
sys.stdout.reconfigure(encoding="utf-8")

TARGET = re.compile(
    rb"AddLocalMsg|InsertLocalMsg|AddSysMsg|InsertSysMsg|AddLocalMessage|InsertLocalMessage|"
    rb"LocalMessage|LocalMsg|SysMsg|SystemMessage|SystemMsg|"
    rb"QQml|QQuick|Qt[56](?:Core|Gui|Widgets|Qml)|qrc:/|:/qml/|\.qml(?:\x00|$)|"
    rb"MessageListModel|ChatMessageModel|MessageBubble|ChatHistory|AddMsg|InsertMsg",
    re.I,
)
STRING = re.compile(rb"[\x20-\x7e]{5,600}")
WIDE_NEEDLES = [s.encode("utf-16-le") for s in (
    "AddLocalMsg", "InsertLocalMsg", "InsertSysMsg", "AddSysMsg", "LocalMessage",
    "SystemMessage", "QQml", "QQuick", "Qt6Core", "Qt5Core", "qrc:/",
)]
CN_NEEDLES = ["插入系统消息", "插入本地消息", "添加本地消息", "系统消息", "本地消息", "消息列表"]


def decode(value):
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def resource_tree(entry, path=()):
    result = []
    for child in getattr(entry, "entries", []):
        name = str(child.name) if child.name is not None else str(child.id)
        key = path + (name,)
        if hasattr(child, "directory"):
            result.extend(resource_tree(child.directory, key))
        elif hasattr(child, "data"):
            result.append({"path": "/".join(key), "rva": child.data.struct.OffsetToData,
                           "size": child.data.struct.Size})
    return result


def inspect(path):
    info = {"name": path.name, "size": path.stat().st_size}
    with path.open("rb") as file:
        info["sha256"] = hashlib.file_digest(file, "sha256").hexdigest()
        file.seek(0)
        info["magic_hex"] = file.read(16).hex()
    pe = None
    if info["magic_hex"].startswith("4d5a"):
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
        ])
        info.update(machine=hex(pe.FILE_HEADER.Machine),
                    architecture={0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(pe.FILE_HEADER.Machine, "other"),
                    image_base=hex(pe.OPTIONAL_HEADER.ImageBase),
                    entrypoint_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    sections=[{"name": decode(s.Name.rstrip(b"\0")),
                               "raw_offset": s.PointerToRawData, "raw_size": s.SizeOfRawData,
                               "rva": s.VirtualAddress, "virtual_size": s.Misc_VirtualSize}
                              for s in pe.sections])
        info["imports"] = [{"dll": decode(item.dll), "symbols": [
            decode(symbol.name) if symbol.name else f"ordinal:{symbol.ordinal}"
            for symbol in item.imports]}
            for item in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        info["delay_imports"] = [{"dll": decode(item.dll), "symbols": [
            decode(symbol.name) if symbol.name else f"ordinal:{symbol.ordinal}"
            for symbol in item.imports]}
            for item in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])]
        info["exports"] = [{"name": decode(symbol.name) if symbol.name else None,
                            "ordinal": symbol.ordinal, "rva": hex(symbol.address),
                            "forwarder": decode(symbol.forwarder) if symbol.forwarder else None}
                           for symbol in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])]
        info["resources"] = resource_tree(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None))
        info["debug"] = []
        for debug in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            data = pe.get_data(debug.struct.AddressOfRawData, debug.struct.SizeOfData)
            info["debug"].append({"type": debug.struct.Type,
                                  "size": debug.struct.SizeOfData,
                                  "pdb": decode(data[24:].rstrip(b"\0")) if data.startswith(b"RSDS") else None})
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            info["zip_entries"] = [{"name": i.filename, "size": i.file_size} for i in z.infolist()]

    hits = []
    with path.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for match in STRING.finditer(data):
            value = match.group()
            if TARGET.search(value):
                hits.append({"encoding": "ascii", "offset": hex(match.start()), "text": decode(value)})
        for needle in WIDE_NEEDLES:
            start = 0
            for _ in range(100):
                position = data.find(needle, start)
                if position < 0:
                    break
                # Extract a bounded, printable UTF-16 string around this exact symbol.
                lo = position
                while lo >= 2 and position - lo < 160 and 32 <= int.from_bytes(data[lo-2:lo], "little") <= 126:
                    lo -= 2
                hi = position + len(needle)
                while hi + 2 <= len(data) and hi - lo < 600 and 32 <= int.from_bytes(data[hi:hi+2], "little") <= 126:
                    hi += 2
                hits.append({"encoding": "utf16le", "offset": hex(lo), "text": data[lo:hi].decode("utf-16-le", "replace")})
                start = position + len(needle)
        for text in CN_NEEDLES:
            for encoding in ("utf-8", "utf-16-le"):
                needle = text.encode(encoding)
                positions = []
                start = 0
                for _ in range(30):
                    position = data.find(needle, start)
                    if position < 0:
                        break
                    positions.append(hex(position))
                    start = position + len(needle)
                if positions:
                    hits.append({"encoding": encoding, "text": text, "offsets": positions})
    if pe:
        for hit in hits:
            if "offset" in hit:
                try:
                    hit["rva"] = hex(pe.get_rva_from_offset(int(hit["offset"], 16)))
                except Exception:
                    pass
        pe.close()
    info["string_hits"] = hits
    return info


items = []
for path in sorted(ROOT.iterdir()):
    if not path.is_file() or not path.stat().st_size:
        continue
    try:
        item = inspect(path)
    except Exception as error:
        item = {"name": path.name, "error": type(error).__name__ + ": " + str(error)}
    items.append(item)
    print(json.dumps({"file": item["name"], "architecture": item.get("architecture"),
                      "exports": len(item.get("exports", [])),
                      "string_hits": len(item.get("string_hits", [])),
                      "error": item.get("error")}, ensure_ascii=False), flush=True)
(OUT / "inventory.json").write_text(json.dumps({"root": str(ROOT), "files": items},
    ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps({"complete": True, "files": len(items)}), flush=True)
