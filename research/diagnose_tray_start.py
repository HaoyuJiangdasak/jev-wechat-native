"""Bounded Qt startup diagnostic with a fake host; never starts native_host.py."""
from pathlib import Path
import subprocess
import sys
import json


def main():
    root = Path(__file__).resolve().parent
    trace = root / "tray-startup-stack.txt"
    if "--child" in sys.argv:
        import faulthandler
        import native_tray
        import os
        import traceback
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        os.environ["LOCALAPPDATA"] = str(root / "tray-test-data")
        events = []
        class FakeChild:
            def poll(self):
                return 1
            def wait(self, timeout=None):
                return 1
        def fake_popen(*args, **kwargs):
            events.append({"event": "host_start_attempt", "cwd_matches": kwargs.get("cwd") == str(root)})
            return FakeChild()
        native_tray.subprocess.Popen = fake_popen
        def trace_calls(frame, event, arg):
            if event == "call" and frame.f_code.co_filename == native_tray.__file__:
                name = frame.f_code.co_name
                if name in ("tick", "start_host", "set_status"):
                    events.append({"event": name})
                if name == "tick" and not any(x["event"] == "quit_scheduled" for x in events):
                    events.append({"event": "quit_scheduled"})
                    QTimer.singleShot(1500, QApplication.instance().quit)
            return trace_calls
        with trace.open("w", encoding="utf-8") as stream:
            faulthandler.enable(file=stream)
            faulthandler.dump_traceback_later(8, repeat=True, file=stream)
            sys.excepthook = lambda kind, value, tb: traceback.print_exception(kind, value, tb, file=stream)
            sys.settrace(trace_calls)
            try:
                # Existing production mutex is intentionally untouched. The
                # regular timer path uses an isolated metadata directory and a
                # fake Popen, so it cannot create or attach a native host.
                return native_tray.run_tray()
            finally:
                sys.settrace(None)
                faulthandler.cancel_dump_traceback_later()
                (root / "tray-startup-events.json").write_text(json.dumps(events, indent=2), encoding="utf-8")
    runtime = root.parents[1] / "outputs" / "JevDialogue" / "runtime" / "python.exe"
    try:
        result = subprocess.run(
            [str(runtime), str(Path(__file__).resolve()), "--child"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=24,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        print(json.dumps({"returncode": result.returncode,
                          "stderr": result.stderr.decode("utf-8", errors="replace"),
                          "trace": str(trace)}, ensure_ascii=False))
    except subprocess.TimeoutExpired:
        print(json.dumps({"smoke_timeout_seconds": 24, "trace": str(trace)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
