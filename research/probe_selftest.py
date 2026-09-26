"""Exercise Frida only against a temporary child created by this script.

The child only sleeps. The JavaScript reads architecture, pointer size, and
module count; it does not read memory or call any native function.
"""
import json
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tool-libs"))
import frida

HOST_PYTHON = r"C:\Users\Public\miniconda3\python.exe"
JAVASCRIPT = """
send({
    arch: Process.arch,
    pointerSize: Process.pointerSize,
    moduleCount: Process.enumerateModules().length
});
"""


def main():
    started = time.monotonic()
    received = threading.Event()
    messages = []
    child = session = script = None
    report = {"frida_version": frida.__version__, "host_python": HOST_PYTHON,
              "target_kind": "new temporary child process",
              "attached": False, "loaded": False, "unloaded": False,
              "detached": False, "child_reaped": False, "passed": False}

    def on_message(message, _data):
        messages.append(message)
        received.set()

    try:
        child = subprocess.Popen(
            [HOST_PYTHON, "-I", "-c", "import time; time.sleep(40)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        report["child_pid"] = child.pid
        # The only PID passed to Frida comes directly from the process above.
        session = frida.attach(child.pid)
        report["attached"] = True
        script = session.create_script(JAVASCRIPT)
        script.on("message", on_message)
        script.load()
        report["loaded"] = True
        if not received.wait(12):
            raise TimeoutError("No self-test payload received within 12 seconds")
        message = messages[0]
        if message.get("type") != "send":
            raise RuntimeError("The self-test script did not return a send payload")
        payload = message["payload"]
        if payload.get("arch") != "x64" or payload.get("pointerSize") != 8:
            raise RuntimeError("Unexpected architecture or pointer size")
        if not isinstance(payload.get("moduleCount"), int) or payload["moduleCount"] < 1:
            raise RuntimeError("Invalid module count")
        report["payload"] = payload
        script.unload()
        report["unloaded"] = True
        script = None
        session.detach()
        report["detached"] = True
        session = None
        report["passed"] = True
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
    finally:
        if script is not None:
            try:
                script.unload()
                report["unloaded"] = True
            except Exception as error:
                report["cleanup_script_error"] = type(error).__name__
        if session is not None:
            try:
                session.detach()
                report["detached"] = True
            except Exception as error:
                report["cleanup_session_error"] = type(error).__name__
        if child is not None:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            report["child_reaped"] = child.poll() is not None
            report["child_exit_code"] = child.returncode
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["passed"] = bool(report["passed"] and report["unloaded"]
                                and report["detached"] and report["child_reaped"])
        (ROOT / "probe-selftest-result.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
