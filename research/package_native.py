"""Build the reviewed local native adapter package; never start a host or tray.

Default: outputs/JevDialogueNative/app, reusing the existing Python 3.11 runtime.
--copy-runtime copies that installed runtime, without downloads or package installs.
--install-shortcut adds a new desktop link only; no autostart registration.
Existing output directories and shortcuts are never overwritten or removed.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parent.parent
DEFAULT_OUTPUT = WORKSPACE / "outputs" / "JevDialogueNative"
DEFAULT_RUNTIME = WORKSPACE / "outputs" / "JevDialogue" / "runtime"
ENGINE_SOURCE = ROOT.parent / "jev-chat-windows-v019"
APP_FILES = (
    "native_host.py", "native_analysis.py", "native_adapter.js", "native_geometry.js",
    "native_follow_tail.js", "native_tray.py", "probe_native_views.py",
    "text-binding-static-candidates.json",
)
VENDOR_FILES = ("frida", "pefile.py", "peutils.py", "ordlookup")
CONFIG = {
    "relationship": "通用沟通：朋友、同事、客户等；根据上下文判断，不预设亲密关系",
    "context": 12,
    "analysis_only": True,
    "jev_provider": "typesafe",
    "jev_model": "jev-latest",
    "check_update": False,
    "reply_target": False,
    "thinking": False,
    "style": "",
}
README = """# Jev 微信原生分析：本机适配包

基于 jev-chat-windows（https://github.com/jev-chat/jev-chat-windows）判断内核进行本地适配。
原生显示适配和托盘入口为本地新增功能，不代表原项目作者出品或背书。

此包构建完成不代表已通过微信现场验收。构建过程不会启动服务、调用 API、操作微信或读取密钥。
manifest.json 初始记录构建状态；真实连接、显示、恢复和切换聊天测试需要单独记录。

入口为 app/native_tray.py，使用 manifest.json 指定的 Python 3.11 运行环境。
托盘提供暂停、继续和退出；退出先请求恢复原聊天显示。不会注册开机启动。
默认复用既有本地 runtime；只有构建时指定 --copy-runtime，runtime 才会放入此目录。
引用运行环境的包依赖该原目录，不是独立可搬运的分发包。

设置位于 app/engine/config.json：通用沟通、TypeSafe 官方接口、jev-latest、仅分析。
API 密钥不包含在包内；运行时沿用既有 Windows 用户环境配置。
源聊天、数据库、账号凭据、运行快照和 API 返回内容均不属于打包输入。

来源和许可证见 NOTICE.md、app/engine/LICENSE、app/engine/NOTICE，
以及 app/tool-libs 的各 dist-info/licenses 或 LICENSE、运行环境中的许可证目录。
微信程序和 DLL 不在包内；兼容性仍由原生 host 的本机路径、版本和哈希检查决定。
"""
NOTICE = """# 来源与许可证

- 判断内核与设置模块：jev-chat/jev-chat-windows v0.1.9 的本地修改版本，
  https://github.com/jev-chat/jev-chat-windows 。保留其 LICENSE 和 NOTICE，位于 app/engine/。
  其上游为 https://github.com/jev-chat/jev-chat-jarvis ，原作者归属以保留的 NOTICE 为准。
- 原生显示适配、调度、托盘和打包脚本：本工作区的本地新增代码。
  本包不声称获得微信、TypeSafe 或上游作者的认证和背书。
- Frida：从本机已安装的官方 Python 发行包复制，https://frida.re ，
  保留 frida-*.dist-info 的元数据及 licenses/COPYING。
- pefile：从本机已安装发行包复制，https://github.com/erocarrera/pefile ，
  保留 pefile-*.dist-info/LICENSE 及元数据。
- Python、PySide6、TypeSafe SDK 及运行环境其余依赖：复用本机已准备好的 Python 3.11 环境；
  来源记录、锁定版本和 Python 许可证复制于 licenses/runtime/。
  若选择复制运行环境，各包原有 dist-info 和许可证随 Lib 一并保留。

manifest.json 列出实际复制文件的 SHA-256、上游 revision 和运行环境模式。
上游 NOTICE 中关于原发布包的说明原样保留；本地打包方式和包含组件以此包清单为准。
"""


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_file(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Required regular file missing: {path}")
    return path


def copy_item(source, destination):
    """Copy allowlisted input; omit caches and refuse linked input trees."""
    if source.is_symlink():
        raise ValueError(f"Linked input is not allowed: {source}")
    if source.is_dir():
        for directory, names, files in os.walk(source, followlinks=False):
            for name in names + files:
                if (Path(directory) / name).is_symlink():
                    raise ValueError(f"Linked input is not allowed: {Path(directory) / name}")
        shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"))
    else:
        require_file(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def dist_info(vendor, name):
    matches = list(vendor.glob(name + "-*.dist-info"))
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {name} distribution")
    require_file(matches[0] / "METADATA")
    return matches[0]


def distribution_version(directory):
    for line in (directory / "METADATA").read_text(encoding="utf-8").splitlines():
        if line.startswith("Version: "):
            return line.partition(": ")[2]
    raise ValueError("Distribution version missing")


def git_revision(source):
    try:
        return subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL, text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def build_package(output, runtime, copy_runtime=False):
    output, runtime = output.resolve(), runtime.resolve()
    if output.exists():
        raise FileExistsError("Output already exists; choose a new --output directory")
    if output == runtime or runtime.is_relative_to(output) or output.is_relative_to(runtime):
        raise ValueError("Output and runtime directories must be separate")
    if output == ROOT or ROOT.is_relative_to(output) or output.is_relative_to(ROOT):
        raise ValueError("Package output must not contain or be inside adapter source")
    required_runtime = (
        "python.exe", "pythonw.exe", "python311.dll", "LICENSE.txt",
        "Lib/site-packages/PySide6/QtWidgets.pyd",
        "Lib/site-packages/typesafe_sdk/__init__.py",
        "requirements-lock.txt", "runtime-provenance.json",
    )
    for name in required_runtime:
        require_file(runtime / name)
    for name in APP_FILES:
        require_file(ROOT / name)
    require_file(ENGINE_SOURCE / "app" / "settings.py")
    for name in ("LICENSE", "NOTICE"):
        require_file(ENGINE_SOURCE / name)
    core_files = sorted((ENGINE_SOURCE / "core").glob("*.py"))
    for name in ("engine.py", "insights.py", "jev_client.py", "providers.py", "questions.py"):
        require_file(ENGINE_SOURCE / "core" / name)
    vendor = ROOT / "tool-libs"
    metadata = [dist_info(vendor, "frida"), dist_info(vendor, "pefile")]
    for name in VENDOR_FILES:
        if not (vendor / name).exists():
            raise ValueError(f"Missing existing native dependency: {name}")

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = output.with_name(output.name + ".staging-" + secrets.token_hex(6))
    staging.mkdir()
    # Deliberately retain a staging directory if a build fails, rather than use
    # recursive deletion against paths calculated by a packaging command.
    app = staging / "app"
    app.mkdir()
    for name in APP_FILES:
        copy_item(ROOT / name, app / name)
    engine = app / "engine"
    (engine / "core").mkdir(parents=True)
    (engine / "app").mkdir()
    for path in core_files:
        copy_item(path, engine / "core" / path.name)
    for package in ("core", "app"):
        initializer = ENGINE_SOURCE / package / "__init__.py"
        if initializer.is_file():
            if not (engine / package / "__init__.py").exists():
                copy_item(initializer, engine / package / "__init__.py")
        else:
            (engine / package / "__init__.py").write_text("", encoding="utf-8")
    copy_item(ENGINE_SOURCE / "app" / "settings.py", engine / "app" / "settings.py")
    for name in ("LICENSE", "NOTICE"):
        copy_item(ENGINE_SOURCE / name, engine / name)
    (engine / "config.json").write_text(json.dumps(CONFIG, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (app / "tool-libs").mkdir()
    for name in VENDOR_FILES:
        copy_item(vendor / name, app / "tool-libs" / name)
    for directory in metadata:
        copy_item(directory, app / "tool-libs" / directory.name)

    runtime_destination = staging / "runtime" if copy_runtime else runtime
    if copy_runtime:
        runtime_destination.mkdir()
        for name in ("DLLs", "Lib", "python.exe", "pythonw.exe", "python3.dll", "python311.dll",
                     "vcruntime140.dll", "vcruntime140_1.dll", "LICENSE.txt",
                     "requirements-lock.txt", "runtime-provenance.json"):
            copy_item(runtime / name, runtime_destination / name)
    for name in ("LICENSE.txt", "requirements-lock.txt", "runtime-provenance.json"):
        copy_item(runtime / name, staging / "licenses" / "runtime" / name)
    (staging / "README.md").write_text(README, encoding="utf-8")
    (staging / "NOTICE.md").write_text(NOTICE, encoding="utf-8")
    # Compile source text only: no app imports, key reads, API requests or launches.
    for path in app.rglob("*.py"):
        if "tool-libs" not in path.parts:
            compile(path.read_bytes(), str(path.relative_to(staging)), "exec")
    files = {
        str(path.relative_to(staging)).replace("\\", "/"): {"sha256": sha256(path), "size": path.stat().st_size}
        for path in sorted(staging.rglob("*")) if path.is_file()
    }
    manifest = {
        "schema": 1,
        "kind": "local_native_adapter_package",
        "built_utc": datetime.now(timezone.utc).isoformat(),
        "validation": "built_not_started_or_end_to_end_validated",
        "entrypoint": "app/native_tray.py",
        "runtime": {"mode": "copied" if copy_runtime else "existing_local_reference",
                    "path": "runtime" if copy_runtime else str(runtime),
                    "python_exe_sha256": sha256(runtime / "python.exe"),
                    "pythonw_exe_sha256": sha256(runtime / "pythonw.exe")},
        "engine": {"upstream": "https://github.com/jev-chat/jev-chat-windows", "version": "v0.1.9",
                   "revision": git_revision(ENGINE_SOURCE), "local_modifications": True,
                   "config": "app/engine/config.json"},
        "native_dependencies": {directory.name.split("-", 1)[0]: distribution_version(directory) for directory in metadata},
        "api_provider": "typesafe",
        "analysis_only": True,
        "secrets_copied": False,
        "autostart_registered": False,
        "files": files,
    }
    (staging / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # rename refuses an existing destination on Windows; there is no overwrite.
    staging.rename(output)
    return output, (output / "runtime" if copy_runtime else runtime)


def install_shortcut(output, runtime):
    """Explicit opt-in: create a new desktop link, without launching it."""
    if os.name != "nt":
        raise OSError("Shortcut creation requires Windows")
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    if ctypes.windll.shell32.SHGetFolderPathW(None, 0x10, None, 0, buffer) != 0:
        raise OSError("Desktop folder unavailable")
    shortcut = Path(buffer.value) / "Jev 微信原生分析.lnk"
    if shortcut.exists():
        raise FileExistsError("Desktop shortcut already exists; it was not changed")
    quote = lambda text: "'" + str(text).replace("'", "''") + "'"
    script = (
        "$ErrorActionPreference='Stop'\n"
        "$w=New-Object -ComObject WScript.Shell\n"
        f"$s=$w.CreateShortcut({quote(shortcut)})\n"
        f"$s.TargetPath={quote(runtime / 'pythonw.exe')}\n"
        f"$s.Arguments={quote(chr(34) + str(output / 'app' / 'native_tray.py') + chr(34))}\n"
        f"$s.WorkingDirectory={quote(output / 'app')}\n"
        "$s.WindowStyle=7\n"
        "$s.Description='Jev 本机微信沟通分析'\n"
        "$s.Save()\n"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                   check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    return shortcut


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--copy-runtime", action="store_true")
    parser.add_argument("--install-shortcut", action="store_true")
    args = parser.parse_args(argv)
    try:
        output, runtime = build_package(args.output, args.runtime, args.copy_runtime)
        print(f"Package built; not started: {output}")
        if args.install_shortcut:
            print(f"Shortcut created; not launched: {install_shortcut(output, runtime)}")
    except (OSError, ValueError, SyntaxError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Build failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
