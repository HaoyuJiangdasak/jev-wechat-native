"""Guarded, headless native adapter host. Importing this file never attaches.

Run explicitly; the default is resident, --seconds bounds its active period.
Creating --stop-file requests restoration and exit. Existing stop files are
respected before attach. Normal cleanup waits for stopped(unresolved=0), with
three bounded stop attempts, then unloads/detaches even when restoration fails.

Snapshots and analysis text stay in memory. The state file has only fixed phases,
integer counters and fixed error codes; no request/response bodies or chat data.
No startup/install registration, UI input, window activation, or process killing.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
import signal
import sys
import threading
import time

from native_analysis import NativeAnalysis, engine_root

ROOT = Path(__file__).resolve().parent
FUNCTION_RVAS = (0x27F80, 0x14E0, 0x1E80D40, 0x5BBFC0, 0x1BC6490, 0x5C41810,
                 0x28C390, 0xCE87B0, 0x20B4600, 0x20B34A0)
NATIVE_COUNT_KEYS = {"bindings", "applied", "restored", "staleSkipped", "errors",
                     "visibleViews", "chatEpoch", "identityMatches", "identityRejected",
                     "remoteViews", "selfViews", "conversationChanges"}
MAX_COUNT = 2**53 - 1
NATIVE_COUNT_KEYS.update({'tailStage','tailArea','tailBar','tailMin','tailMax','tailValue','tailOrientation','tailDown'})
NATIVE_COUNT_KEYS.update({'tailCaptured','tailRestored','tailChanged','tailPositionChanged','tailFailed'})
NATIVE_COUNT_KEYS.update('tailAncestor'+str(i) for i in range(24))
NATIVE_COUNT_KEYS.update('tailGuard'+name for name in ('StartValue','StartMax','LastValue','LastMax',
    'SeenValue','SeenMax','SeenMin','SeenDown','AfterValue','AfterMax','ElapsedMs','Steps','Writes','ReasonNumber','InputChanged'))


class AlreadyRunningError(RuntimeError):
    pass


class CompatibilityError(RuntimeError):
    pass


class TargetSelectionError(RuntimeError):
    pass


class MissingKeyError(RuntimeError):
    pass


class WindowsSingleton:
    """Kernel releases the owned mutex if the host process crashes."""
    def __init__(self, name=r"Local\JevDialogueNativeHost.v1"):
        self.name = name
        self.handle = None

    def __enter__(self):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [w.LPVOID, w.BOOL, w.LPCWSTR]
        self.kernel.CreateMutexW.restype = w.HANDLE
        self.kernel.ReleaseMutex.argtypes = [w.HANDLE]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        ctypes.set_last_error(0)
        self.handle = self.kernel.CreateMutexW(None, True, self.name)
        if not self.handle:
            raise OSError("Mutex creation failed")
        if ctypes.get_last_error() == 183:
            self.kernel.CloseHandle(self.handle)
            self.handle = None
            raise AlreadyRunningError()
        return self

    def __exit__(self, *_):
        if self.handle:
            self.kernel.ReleaseMutex(self.handle)
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def _count(value):
    return value if type(value) is int and 0 <= value <= MAX_COUNT else None


def safe_stats(raw):
    if not isinstance(raw, dict):
        return {}
    return {key: raw[key] for key in NATIVE_COUNT_KEYS if key in raw and _count(raw[key]) is not None}


class StateFile:
    def __init__(self, path):
        self.path = Path(path)

    def __call__(self, state):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text(json.dumps(state, ensure_ascii=True, indent=2), encoding="utf-8")
        os.replace(temporary, self.path)


def select_window(candidates, pid=None, hwnd=None):
    """Pure selection: candidate rows contain no window/chat titles."""
    rows = [item for item in candidates if (pid is None or item["pid"] == pid)
            and (hwnd is None or item["hwnd"] == hwnd)]
    if not rows or len({item["pid"] for item in rows}) != 1:
        raise TargetSelectionError()
    rows.sort(key=lambda item: ("mainwindow" in item["class"].casefold(), item["area"]), reverse=True)
    if len(rows) > 1 and ("mainwindow" in rows[0]["class"].casefold(), rows[0]["area"]) == (
            "mainwindow" in rows[1]["class"].casefold(), rows[1]["area"]):
        raise TargetSelectionError()
    return rows[0]["pid"], rows[0]["hwnd"]


def discover_window(expected_exe, process_path, pid=None, hwnd=None):
    """Read-only Win32 enumeration. Never reads titles or changes window state."""
    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
    user.EnumWindows.argtypes = [callback_type, w.LPARAM]
    user.EnumWindows.restype = w.BOOL
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetWindowThreadProcessId.restype = w.DWORD
    user.IsWindowVisible.argtypes = [w.HWND]
    user.IsWindowVisible.restype = w.BOOL
    user.GetWindow.argtypes = [w.HWND, w.UINT]
    user.GetWindow.restype = w.HWND
    user.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
    user.GetClassNameW.restype = ctypes.c_int
    user.GetWindowRect.argtypes = [w.HWND, ctypes.POINTER(w.RECT)]
    user.GetWindowRect.restype = w.BOOL
    rows, paths = [], {}
    expected = os.path.normcase(os.path.abspath(expected_exe))

    @callback_type
    def visit(window, _):
        try:
            identifier = int(window)
            if hwnd is not None and identifier != hwnd:
                return True
            if not user.IsWindowVisible(window) or user.GetWindow(window, 4):
                return True
            owner = w.DWORD()
            if not user.GetWindowThreadProcessId(window, ctypes.byref(owner)):
                return True
            if pid is not None and owner.value != pid:
                return True
            if owner.value not in paths:
                paths[owner.value] = os.path.normcase(os.path.abspath(process_path(owner.value)))
            if paths[owner.value] != expected:
                return True
            class_name, rect = ctypes.create_unicode_buffer(256), w.RECT()
            if not user.GetClassNameW(window, class_name, len(class_name)) or not user.GetWindowRect(window, ctypes.byref(rect)):
                return True
            area = max(0, rect.right - rect.left) * max(0, rect.bottom - rect.top)
            rows.append({"pid": owner.value, "hwnd": identifier, "class": class_name.value, "area": area})
        except Exception:
            pass  # Inaccessible unrelated processes are not diagnostic payloads.
        return True

    if not user.EnumWindows(visit, 0):
        raise TargetSelectionError()
    return select_window(rows, pid, hwnd)


def verified_config(pid=None, hwnd=None):
    """Reuse the original process-path and image-hash guards; verify all call sites."""
    library_path = str(ROOT / "tool-libs")
    if library_path not in sys.path:
        sys.path.insert(0, library_path)
    from probe_native_views import DLL, EXE, EXPECTED_SHA, process_path
    import pefile
    target_pid, target_hwnd = discover_window(EXE, process_path, pid, hwnd)
    if process_path(target_pid).casefold() != EXE.casefold():
        raise CompatibilityError()
    raw = DLL.read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA:
        raise CompatibilityError()
    pe = pefile.PE(data=raw, fast_load=True)
    try:
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise CompatibilityError()
        functions = []
        for rva in FUNCTION_RVAS:
            section = pe.get_section_by_rva(rva)
            code = pe.get_data(rva, 24)
            if section is None or not section.Characteristics & 0x20000000 or len(code) != 24:
                raise CompatibilityError()
            functions.append({"rva": rva, "bytes": list(code)})
    finally:
        pe.close()
    entries = json.loads((ROOT / "text-binding-static-candidates.json").read_text(encoding="utf-8"))["candidates"]
    bindings = [entry["binding_vtable_rva"] for entry in entries]
    return {"pid": target_pid, "hwnd": target_hwnd, "dllPath": str(DLL),
            "nonce": secrets.token_hex(12), "functions": functions, "bindingVtables": bindings}


def ensure_local_key():
    source = str(engine_root())
    if source not in sys.path:
        sys.path.insert(0, source)
    from app import settings
    if not settings.has_jev_key():
        raise MissingKeyError()


class NativeHost:
    """Dependency-injected lifecycle. No attachment until run() is called."""
    def __init__(self, config, source, attach, *, state_sink, stop_requested=lambda: False,
                 seconds=None, scheduler_factory=NativeAnalysis, clock=time.monotonic,
                 wait=time.sleep, ready_timeout=10, restore_wait=2, observe_only=False):
        self.config, self.source, self.attach = config, source, attach
        self.state_sink, self.stop_requested, self.seconds = state_sink, stop_requested, seconds
        self.scheduler_factory, self.clock, self.wait = scheduler_factory, clock, wait
        self.ready_timeout, self.restore_wait = ready_timeout, restore_wait
        self.observe_only = observe_only
        self.counts = {"snapshots": 0, "resultsQueued": 0, "resultsRejected": 0,
                       "resultsApplied": 0, "deliveryTimeouts": 0, "staleAcks": 0,
                       "requestsStarted": 0, "requestsCompleted": 0,
                       "heartbeats": 0, "restoreConfirmed": 0, "unloaded": 0,
                       "detached": 0, "fullChainValidated": 0}
        self.error_types = []
        self.phase = "created"
        self._events = queue.Queue(maxsize=64)
        self._snapshots = queue.Queue(maxsize=1)
        self._fatal = threading.Event()
        self._ready = self._stopped = self._stopping = False
        self._last_write = -float("inf")
        self._deliveries = {}
        self._delivery_nonce = secrets.token_hex(12)
        self._delivery_serial = 0
        self.session = self.script = self.scheduler = None

    def _error(self, code):
        if code not in self.error_types:
            self.error_types.append(code)

    def _write(self, force=False):
        if force or self.clock() - self._last_write >= 1:
            try:
                request_counts = getattr(self.scheduler, "request_counts", {})
                if isinstance(request_counts, dict):
                    for name in ("requestsStarted", "requestsCompleted"):
                        value = _count(request_counts.get(name))
                        if value is not None:
                            self.counts[name] = value
                self.state_sink({"phase": self.phase, "counts": dict(self.counts),
                                 "error_types": list(self.error_types)})
            except Exception:
                # Disk/reporting failure must never bypass restoration and detach.
                self._error("StateWriteError")
            self._last_write = self.clock()

    def _phase(self, value):
        self.phase = value
        self._write(True)

    @staticmethod
    def _latest(queue_, value):
        while True:
            try:
                queue_.put_nowait(value)
                return
            except queue.Full:
                try:
                    queue_.get_nowait()
                except queue.Empty:
                    pass

    def _message(self, message, _data):
        # Runs on Frida's delivery thread. Only snapshots enter the private latest slot.
        if message.get("type") != "send" or not isinstance(message.get("payload"), dict):
            self._fatal.set()
            self._latest(self._events, ("error", "NativeScriptError"))
            return
        payload = message["payload"]
        event = payload.get("event")
        if event == "snapshot":
            snapshot = payload.get("snapshot")
            if isinstance(snapshot, dict):
                self._latest(self._snapshots, snapshot)
            else:
                self._fatal.set()
                self._latest(self._events, ("error", "SnapshotContractError"))
        elif event == "ready":
            self._latest(self._events, ("ready", None))
        elif event == "annotation_result":
            token, applied = payload.get("deliveryId"), payload.get("applied")
            if isinstance(token, str) and len(token) <= 128 and type(applied) is bool:
                self._latest(self._events, ("annotation_result", (token, applied)))
        elif event in ("stats", "stopped", "stop_pending"):
            self._latest(self._events, (event, (safe_stats(payload.get("stats")), _count(payload.get("unresolved")))))
        elif event == "operation_error":
            self._fatal.set()
            self._latest(self._events, ("error", "NativeOperationError"))
        # Unknown payloads, error messages, stack traces and arbitrary stats are discarded.

    def _session_detached(self, *_):
        if not self._stopping:
            self._fatal.set()
            self._latest(self._events, ("error", "NativeSessionDetached"))

    def _drain(self, snapshots=True):
        while True:
            try:
                kind, value = self._events.get_nowait()
            except queue.Empty:
                break
            if kind == "ready":
                self._ready = True
            elif kind == "error":
                self._error(value)
            elif kind == "annotation_result":
                token, applied = value
                delivery = self._deliveries.pop(token, None)
                if delivery is None or self.scheduler is None or self._stopping:
                    self.counts["staleAcks"] += 1
                else:
                    identifier, generation, receipt, _ = delivery
                    if self.scheduler.mark_applied(identifier, generation, receipt, applied=applied):
                        self.counts["resultsApplied" if applied else "resultsRejected"] += 1
                    else:
                        self.counts["staleAcks"] += 1
            else:
                stats, unresolved = value
                self.counts.update(stats)
                if unresolved is not None:
                    self.counts["unresolved"] = unresolved
                if kind == "stopped":
                    self._stopped = True
                    if unresolved == 0:
                        self.counts["restoreConfirmed"] = 1
                    else:
                        self._error("RestoreUnresolvedError")
        self._expire_deliveries()
        if snapshots and self._ready and not self._stopping and not self._fatal.is_set():
            try:
                snapshot = self._snapshots.get_nowait()
            except queue.Empty:
                return
            if not self.observe_only:
                self.scheduler.on_snapshot(snapshot)
            self.counts["snapshots"] += 1
            messages = snapshot.get("messages")
            if isinstance(messages, list):
                self.counts["snapshotMessages"] = len(messages)

    def _result(self, identifier, generation, text):
        if self._stopping or self._fatal.is_set() or not self._ready or self._stopped:
            return False
        receipt = self.scheduler.delivery_receipt(identifier, generation)
        if receipt is None:
            return False
        self._expire_deliveries()
        if len(self._deliveries) >= 8 or any(delivery[:2] == (identifier, generation)
                                            for delivery in self._deliveries.values()):
            return False
        self._delivery_serial += 1
        token = self._delivery_nonce + ":" + str(self._delivery_serial)
        self._deliveries[token] = (identifier, generation, receipt, self.clock() + 5)
        self.scheduler.defer_delivery(identifier, generation, receipt, seconds=5)
        queued = self.script.exports_sync.annotate(identifier, generation, text, token)
        self.counts["resultsQueued" if queued is True else "resultsRejected"] += 1
        if queued is not True:
            self._deliveries.pop(token, None)
            self.scheduler.mark_applied(identifier, generation, receipt, applied=False)
        return False

    def _expire_deliveries(self):
        for token, (identifier, generation, receipt, deadline) in list(self._deliveries.items()):
            if self.clock() >= deadline:
                del self._deliveries[token]
                self.counts["deliveryTimeouts"] += 1
                if self.scheduler is not None and not self._stopping:
                    self.scheduler.mark_applied(identifier, generation, receipt, applied=False)

    def _restore(self):
        if self.scheduler is not None:
            try:
                self.scheduler.close()
            except Exception:
                self._error("SchedulerCloseError")
        self._stopping = True
        self._deliveries.clear()
        self._phase("restoring")
        if self.script is not None:
            for _ in range(3):
                if self.counts["restoreConfirmed"]:
                    break
                try:
                    # Return value is not restoration proof; only stopped(unresolved=0) is.
                    self.script.exports_sync.stop()
                except Exception:
                    self._error("StopRpcError")
                deadline = self.clock() + self.restore_wait
                while self.clock() < deadline and not self.counts["restoreConfirmed"]:
                    self._drain(False)
                    if not self.counts["restoreConfirmed"]:
                        self.wait(min(.2, max(0, deadline - self.clock())))
                self._drain(False)
            if not self.counts["restoreConfirmed"]:
                self._error("RestoreConfirmationError")
            try:
                self.script.unload()
                self.counts["unloaded"] = 1
            except Exception:
                self._error("ScriptUnloadError")
        if self.session is not None:
            try:
                self.session.detach()
                self.counts["detached"] = 1
            except Exception:
                self._error("SessionDetachError")

    def run(self):
        try:
            if self.stop_requested():
                self._phase("stopped_before_attach")
                return 0
            self._phase("attaching")
            self.session = self.attach(self.config["pid"])
            self.session.on("detached", self._session_detached)
            self.script = self.session.create_script("const CONFIG=" + json.dumps(self.config) + ";\n" + self.source)
            self.script.on("message", self._message)
            if not self.observe_only:
                self.scheduler = self.scheduler_factory(self._result)
            self.script.load()
            self._phase("initializing")
            ready_deadline = self.clock() + self.ready_timeout
            while not self._ready and not self._fatal.is_set() and self.clock() < ready_deadline:
                self._drain(False)
                if not self._ready:
                    self.wait(.2)
            if not self._ready or self._fatal.is_set():
                self._error("AdapterInitializationError")
                return 1
            self._phase("observing" if self.observe_only else "running")
            started = self.clock()
            next_heartbeat = started
            while not self.stop_requested() and not self._fatal.is_set():
                if self.seconds is not None and self.clock() - started >= self.seconds:
                    break
                self._drain()
                if self._stopped:
                    break
                if self.scheduler is not None:
                    self.scheduler.tick()
                if self.clock() >= next_heartbeat:
                    self.script.exports_sync.heartbeat()
                    self.counts["heartbeats"] += 1
                    next_heartbeat = self.clock() + 2
                self._write()
                self.wait(.2)
            self._drain(False)
        except KeyboardInterrupt:
            pass
        except Exception:
            self._error("HostRuntimeError")
        finally:
            if self.session is not None or self.script is not None:
                try:
                    self._restore()
                except Exception:
                    self._error("HostCleanupError")
                self._phase("restore_failed" if self.script is not None and not self.counts["restoreConfirmed"]
                            else "failed" if self.error_types else "stopped")
        return 1 if self.error_types else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int)
    parser.add_argument("--hwnd", type=lambda value: int(value, 0))
    parser.add_argument("--seconds", type=float, help="Optional active duration; restoration follows")
    parser.add_argument("--observe-only", action="store_true", help="Count snapshots without creating an API scheduler")
    parser.add_argument("--stop-file", type=Path, default=ROOT / "native-host.stop")
    parser.add_argument("--state-file", type=Path, default=ROOT / "native-host-state.json")
    args = parser.parse_args(argv)
    if args.seconds is not None and (not 0 < args.seconds <= 86400):
        parser.error("--seconds must be between 0 and 86400")
    sink = StateFile(args.state_file)
    interrupt = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: interrupt.set())
    signal.signal(signal.SIGTERM, lambda *_: interrupt.set())
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, lambda *_: interrupt.set())
    stop_requested = lambda: interrupt.is_set() or args.stop_file.exists()
    try:
        with WindowsSingleton():
            if stop_requested():
                sink({"phase": "stopped_before_attach", "counts": {"fullChainValidated": 0}, "error_types": []})
                return 0
            if not args.observe_only:
                ensure_local_key()
            config = verified_config(args.pid, args.hwnd)
            config['diagnostics'] = args.observe_only
            import frida
            source = ((ROOT / "native_geometry.js").read_text(encoding="utf-8") + "\n" +
                      (ROOT / "native_follow_tail.js").read_text(encoding="utf-8") + "\n" +
                      (ROOT / "native_adapter.js").read_text(encoding="utf-8"))
            host = NativeHost(config, source, frida.attach, state_sink=sink,
                              stop_requested=stop_requested, seconds=args.seconds,
                              observe_only=args.observe_only)
            return host.run()
    except AlreadyRunningError:
        # Do not overwrite the active instance's state file.
        return 2
    except Exception as exc:
        allowed = {CompatibilityError: "CompatibilityError", TargetSelectionError: "TargetSelectionError",
                   MissingKeyError: "MissingKeyError"}
        sink({"phase": "startup_failed", "counts": {"fullChainValidated": 0},
              "error_types": [allowed.get(type(exc), "HostStartupError")]})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
