"""Windows tray launcher; importing this module never starts Qt or the host.

The host remains responsible for compatibility checks, attachment and restoration.
--smoke-test SECONDS initializes only the tray and exits without starting a host.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
RETRY_SECONDS = 10
STOP_WAIT_SECONDS = 12
PHASE_LABELS = {
    "tray_initializing": "正在初始化托盘",
    "tray_ready": "托盘已就绪 · 等待启动服务",
    "host_starting": "正在启动原生服务",
    "created": "正在启动",
    "attaching": "正在连接微信",
    "initializing": "正在初始化原生显示",
    "running": "已连接微信 · 自动分析已开启",
    "observing": "已连接微信 · 仅观察",
    "restoring": "正在恢复原聊天显示",
    "stopped": "原生服务已停止",
    "stopped_before_attach": "原生服务已停止",
    "restore_failed": "恢复原显示未获确认",
    "failed": "原生服务已停止，请检查状态",
    "startup_failed": "原生服务启动失败",
}
TRAY_ERROR_CODES = {
    "TrayInitializationError", "TrayHostLaunchError", "TrayLoopError",
    "HostExitedBeforeState",
}


def tray_state_path():
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise OSError("Local application data unavailable")
    return (Path(local) / "JevDialogue" / "NativeTray" / "state.json").resolve()


def write_tray_metadata(path, phase, error=None, returncode=None, os_error=None):
    """Write fixed startup metadata; never serialize exception strings or locals."""
    if phase not in PHASE_LABELS or (error is not None and error not in TRAY_ERROR_CODES):
        raise ValueError("Unsupported tray metadata")
    counts = {}
    if type(returncode) is int and -(2**31) <= returncode < 2**32:
        counts["hostExitCode"] = returncode
    if type(os_error) is int and 0 <= os_error < 2**31:
        counts["trayOsError"] = os_error
    data = {"phase": phase, "counts": counts, "error_types": [error] if error else []}
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("tray-state-" + str(os.getpid()) + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=True), encoding="utf-8")
    os.replace(temporary, path)


def launch_failure_code(exc):
    # A bounded errno helps distinguish an inaccessible executable/path without
    # exposing the error message, which can contain arbitrary process details.
    value = getattr(exc, "winerror", None)
    if type(value) is not int:
        value = getattr(exc, "errno", None)
    return value if type(value) is int and 0 <= value < 2**31 else None


def exit_policy(returncode, state):
    """Only fixed metadata codes become user-visible status, never raw errors."""
    errors = set(state.get("error_types", [])) if isinstance(state, dict) else set()
    if "CompatibilityError" in errors:
        return False, "微信版本需适配 · 已停止自动重试"
    if returncode == 2:
        return False, "已有原生服务 · 可稍后点继续重试"
    if "MissingKeyError" in errors:
        return False, "请先配置官方 Jev API 密钥"
    if "TargetSelectionError" in errors:
        return True, "等待微信窗口 · 每 10 秒检查"
    if "NativeSessionDetached" in errors:
        return True, "微信连接已断开 · 等待重新连接"
    if state.get("phase") == "restore_failed" or "RestoreConfirmationError" in errors:
        return False, "恢复原显示未获确认 · 请检查微信"
    if returncode == 0:
        return True, "原生服务已停止 · 等待重新连接"
    return False, "原生服务启动或运行失败 · 点继续重试"


def read_metadata(path):
    """Discard arbitrary payload fields and bound the state-file read."""
    try:
        if path.stat().st_size > 65536:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        phase = data.get("phase")
        errors = data.get("error_types")
        return {
            "phase": phase if phase in PHASE_LABELS else "unknown",
            "error_types": [x for x in errors if isinstance(x, str) and len(x) <= 80]
            if isinstance(errors, list) else [],
        }
    except (OSError, ValueError, TypeError):
        return {}


class TraySingleton:
    """A crashed tray automatically relinquishes its kernel mutex."""
    def __init__(self):
        self.handle = None
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        self.kernel.CreateMutexW.restype = wintypes.HANDLE
        self.kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]

    def acquire(self):
        ctypes.set_last_error(0)
        handle = self.kernel.CreateMutexW(None, True, r"Local\JevDialogueNativeTray.v1")
        if not handle:
            raise OSError("Tray mutex unavailable")
        if ctypes.get_last_error() == 183:
            self.kernel.CloseHandle(handle)
            return False
        self.handle = handle
        return True

    def close(self):
        if self.handle:
            self.kernel.ReleaseMutex(self.handle)
            self.kernel.CloseHandle(self.handle)
            self.handle = None


MISSING_DEPENDENCY_HINT = (
    "缺少依赖：{name}。\n"
    "请先安装运行依赖，然后重新运行：\n"
    "    pip install -r requirements.txt\n"
)


def run_tray(smoke_seconds=None):
    initial_state_file = None if smoke_seconds is not None else tray_state_path()
    if initial_state_file is not None:
        write_tray_metadata(initial_state_file, "tray_initializing")
    try:
        from PySide6.QtCore import QTimer, Qt
        from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPixmap
        from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon
    except ImportError as exc:
        # The tray is the only entry point; without Qt there is nothing to show
        # the user except this line, so make it say what to actually do.
        print(MISSING_DEPENDENCY_HINT.format(name=exc.name or "PySide6"), file=sys.stderr)
        return 4

    app = QApplication([sys.argv[0]])
    app.setApplicationName("Jev 微信原生分析")
    app.setQuitOnLastWindowClosed(False)
    if not QSystemTrayIcon.isSystemTrayAvailable():
        if initial_state_file is not None:
            write_tray_metadata(initial_state_file, "startup_failed", "TrayInitializationError")
        return 3

    class Controller:
        def __init__(self):
            self.child = None
            self.paused = False
            self.quitting = False
            self.stop_deadline = None
            self.exit_wait_finished = False
            self.next_start = time.monotonic()
            self.state = {}
            self.baseline = None
            self.last_signature = None
            self.output_dir = None
            self.stop_file = None
            self.state_file = None
            self.marker_name = "host-" + str(os.getpid()) + "-" + secrets.token_hex(12) + ".stop"
            if smoke_seconds is None:
                self.output_dir = initial_state_file.parent
                self.output_dir.mkdir(parents=True, exist_ok=True)
                self.stop_file = self.output_dir / self.marker_name
                self.state_file = initial_state_file

            pixmap = QPixmap(32, 32)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setBrush(QColor("#2877C7"))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(1, 1, 30, 30, 8, 8)
            painter.setPen(QColor("white"))
            painter.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "J")
            painter.end()
            self.tray = QSystemTrayIcon(QIcon(pixmap), app)
            self.menu = QMenu()
            self.status_action = QAction("正在启动", self.menu)
            self.status_action.setEnabled(False)
            self.menu.addAction(self.status_action)
            self.menu.addSeparator()
            self.pause_action = self.menu.addAction("暂停")
            self.resume_action = self.menu.addAction("继续")
            self.menu.addSeparator()
            self.exit_action = self.menu.addAction("退出")
            self.pause_action.triggered.connect(self.pause)
            self.resume_action.triggered.connect(self.resume)
            self.exit_action.triggered.connect(self.quit)
            self.tray.setContextMenu(self.menu)
            self.tray.show()
            self.timer = QTimer(app)
            self.timer.timeout.connect(self.tick)
            self.timer.start(500)
            if self.state_file is not None:
                write_tray_metadata(self.state_file, "tray_ready")
            self.set_status("托盘初始化测试 · 未启动分析服务" if smoke_seconds else "正在启动")
            if smoke_seconds is not None:
                self.pause_action.setEnabled(False)
                self.resume_action.setEnabled(False)
                QTimer.singleShot(max(1, int(smoke_seconds * 1000)), self.quit)

        def set_status(self, text):
            self.tray.setToolTip("Jev 微信原生分析\n" + text)
            self.status_action.setText(text)
            self.pause_action.setEnabled(not self.paused and not self.quitting and smoke_seconds is None)
            self.resume_action.setEnabled(self.paused and self.child is None and not self.quitting and smoke_seconds is None)
            self.exit_action.setEnabled(not self.quitting)

        def owned_marker(self):
            if self.stop_file is None or self.output_dir is None:
                raise OSError("No owned stop marker")
            resolved = self.stop_file.resolve()
            if resolved.parent != self.output_dir or resolved.name != self.marker_name:
                raise OSError("Stop marker ownership mismatch")
            return resolved

        def signal_stop(self):
            # Only the unique marker for this tray run is ever created/deleted.
            self.owned_marker().write_text("stop\n", encoding="ascii")

        def signature(self):
            try:
                if self.state_file.resolve().parent != self.output_dir:
                    return None
                stat = self.state_file.stat()
                return stat.st_mtime_ns, stat.st_size
            except OSError:
                return None

        def update_state(self):
            signature = self.signature()
            if signature is not None and signature != self.baseline and signature != self.last_signature:
                metadata = read_metadata(self.state_file)
                if metadata:
                    self.state = metadata
                    self.last_signature = signature

        def start_host(self):
            if self.child is not None or self.paused or self.quitting:
                return
            try:
                host = ROOT / "native_host.py"
                if not host.is_file():
                    raise OSError("Host file unavailable")
                marker = self.owned_marker()
                if marker.exists():
                    marker.unlink()
                write_tray_metadata(self.state_file, "host_starting")
                self.baseline = self.signature()
                self.last_signature = None
                self.state = {}
                self.child = subprocess.Popen(
                    [sys.executable, str(host), "--stop-file", str(marker),
                     "--state-file", str(self.state_file)],
                    cwd=str(ROOT), stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                self.set_status("正在连接微信")
            except (OSError, ValueError) as exc:
                self.paused = True
                self.record_failure("TrayHostLaunchError", os_error=launch_failure_code(exc))
                self.set_status("原生服务无法启动 · 点继续重试")

        def record_failure(self, error, returncode=None, os_error=None):
            self.state = {"phase": "startup_failed", "error_types": [error]}
            try:
                write_tray_metadata(self.state_file, "startup_failed", error, returncode, os_error)
            except OSError:
                pass  # Tray status still reports failure when the disk is unavailable.

        def pause(self):
            if smoke_seconds is not None:
                return
            self.paused = True
            self.begin_stop()

        def resume(self):
            if self.quitting or self.child is not None or smoke_seconds is not None:
                return
            self.paused = False
            self.stop_deadline = None
            self.next_start = time.monotonic()
            self.set_status("准备重新连接微信")

        def quit(self):
            if self.quitting:
                return
            self.quitting = True
            self.paused = True
            self.begin_stop()

        def begin_stop(self):
            if self.child is None:
                self.set_status("已暂停")
                if self.quitting:
                    app.quit()
                return
            try:
                self.signal_stop()
                self.stop_deadline = time.monotonic() + STOP_WAIT_SECONDS
                self.set_status("正在恢复原聊天显示并停止")
            except OSError:
                self.stop_deadline = time.monotonic() + STOP_WAIT_SECONDS
                self.set_status("停止请求未写入 · 原生服务尚未确认停止")

        def tick(self):
            try:
                self._tick()
            except Exception:
                # Exceptions from Qt slots are otherwise only printed to stderr,
                # which does not exist when launched with pythonw.exe.
                self.paused = True
                if self.child is None:
                    self.record_failure("TrayLoopError")
                    self.set_status("托盘状态更新失败 · 点继续重试")
                else:
                    self.begin_stop()

        def _tick(self):
            if smoke_seconds is not None:
                return
            now = time.monotonic()
            if self.child is not None:
                self.update_state()
                code = self.child.poll()
                if code is not None:
                    self.child = None
                    self.stop_deadline = None
                    if not self.state:
                        self.record_failure("HostExitedBeforeState", code)
                    if self.quitting:
                        self.exit_wait_finished = True
                        app.quit()
                        return
                    if self.paused:
                        status = ("已暂停 · 恢复原显示未获确认" if self.state.get("phase") == "restore_failed"
                                  else "已暂停")
                        self.set_status(status)
                    else:
                        retry, status = exit_policy(code, self.state)
                        self.paused = not retry
                        self.next_start = now + RETRY_SECONDS
                        self.set_status(status)
                elif self.stop_deadline is not None:
                    if now >= self.stop_deadline:
                        self.stop_deadline = None
                        self.set_status("原生服务仍在退出 · 尚未确认恢复")
                        if self.quitting:
                            self.exit_wait_finished = True
                            self.tray.showMessage("Jev", "退出请求已保留，原生服务尚未确认停止。", QSystemTrayIcon.MessageIcon.Warning)
                            app.quit()
                elif not self.paused and not self.quitting:
                    self.set_status(PHASE_LABELS.get(self.state.get("phase"), "正在连接微信"))
            if self.child is None and not self.paused and not self.quitting and now >= self.next_start:
                self.start_host()

        def shutdown_fallback(self):
            self.timer.stop()
            if self.child is not None and self.child.poll() is None:
                try:
                    self.signal_stop()
                    if not self.exit_wait_finished:
                        self.child.wait(timeout=STOP_WAIT_SECONDS)
                except (OSError, subprocess.TimeoutExpired):
                    pass  # Leave the stop marker; never terminate the host or WeChat.
            self.tray.hide()

    controller = Controller()
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: controller.quit())
    try:
        return app.exec()
    finally:
        controller.shutdown_fallback()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--smoke-test", type=float, metavar="SECONDS")
    args = parser.parse_args(argv)
    if args.smoke_test is not None and not 0 < args.smoke_test <= 60:
        parser.error("--smoke-test must be between 0 and 60 seconds")
    if os.name != "nt":
        parser.error("This tray launcher requires Windows")
    mutex = TraySingleton()
    try:
        if not mutex.acquire():
            # A smoke test must not claim initialization when an existing tray
            # prevented this process from creating one.
            return 2 if args.smoke_test is not None else 0
        try:
            return run_tray(args.smoke_test)
        except Exception:
            if args.smoke_test is None:
                try:
                    write_tray_metadata(tray_state_path(), "startup_failed", "TrayInitializationError")
                except OSError:
                    pass
            return 4
    finally:
        mutex.close()


if __name__ == "__main__":
    raise SystemExit(main())
