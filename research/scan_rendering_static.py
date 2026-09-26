"""Read-only disk evidence; never loads WeChat DLLs or opens a process/database."""
import hashlib
import json
import mmap
from pathlib import Path
import re


INSTALL = Path("C:/Program Files/Tencent/Weixin/4.1.15.11")
TARGET = INSTALL / "Weixin.dll"
OUT = Path(__file__).with_name("rendering-static-evidence.json")
TERMS = [
    "5.15.14", "QtCore", "QWidget", "QAbstractItemModel",
    "mmui::ChatDetailView", "mmui::ChatItemView", "mmui::ChatTextItemView",
    "mmui::ChatBubbleFrame", "mmui::ChatBubbleItemView",
    "mmui::ChatSystemInfoItemView", "mmui::XRecyclerTableView",
    "mmui::XSkiaWidegetBase", "chat_message_list",
    "BaseChatItemViewModel", "<XVBoxView", "qt_plugin_instance",
    "QtQuick", "QQml", "QQmlExtensionPlugin", ".qml", "qrc:/", "cef_",
]


def main():
    with TARGET.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            found = {}
            for term in TERMS:
                offsets = [match.start() for match in re.finditer(re.escape(term.encode("ascii")), data)]
                found[term] = {"count": len(offsets), "first_file_offsets_hex": [hex(x) for x in offsets[:4]]}
    report = {
        "scope": "Static bytes of installed files only; no process memory, DB, injection or binary execution",
        "target": str(TARGET), "file_size": TARGET.stat().st_size, "sha256": digest,
        "terms_ascii_only": found,
        "plugin_info_ini": (INSTALL / "plugin_info.ini").read_text(encoding="utf-8-sig").strip(),
        "installed_filenames": sorted(path.name for path in INSTALL.iterdir() if path.is_file()),
        "limitations": [
            "Absence of an ASCII marker does not prove absence from compressed, obfuscated, UTF-16 or dynamically loaded code.",
            "Type-name/string presence is a locator, not proof of its runtime calling convention or a supported external API.",
            "File offsets are not process addresses and are not patch instructions.",
        ],
    }
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(OUT), "sha256": digest, "term_count": len(found)}))


if __name__ == "__main__":
    main()
