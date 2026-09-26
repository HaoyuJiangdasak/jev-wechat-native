"""Guarded, ten-second diagnostic probe; use --self-test before a real target.

For a real target --pid and --hwnd are required. The only intercepted function
is that verified window's WndProc, and only registered diagnostic messages are
counted. No WeChat native function, chat text, database, or UI editing is used.
"""
import argparse
import ctypes
from ctypes import wintypes as w
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tool-libs'))
import frida
import pefile
from probe_native_views import DLL, EXE, EXPECTED_SHA, BUILD_RVA, process_path

MAX_SECONDS = 10
HOST_PYTHON = r'C:\Users\Public\miniconda3\python.exe'


def child_window():
    """Create an invisible message-only window in this newly spawned process."""
    user = ctypes.WinDLL('user32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

    class WNDCLASS(ctypes.Structure):
        _fields_ = [('style', w.UINT), ('lpfnWndProc', WNDPROC), ('cbClsExtra', ctypes.c_int),
                    ('cbWndExtra', ctypes.c_int), ('hInstance', w.HINSTANCE),
                    ('hIcon', w.HICON), ('hCursor', w.HANDLE), ('hbrBackground', w.HBRUSH),
                    ('lpszMenuName', w.LPCWSTR), ('lpszClassName', w.LPCWSTR)]

    user.DefWindowProcW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
    user.DefWindowProcW.restype = ctypes.c_ssize_t
    user.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASS)]
    user.RegisterClassW.restype = w.ATOM
    user.CreateWindowExW.argtypes = [w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD,
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, w.HWND, w.HMENU, w.HINSTANCE, w.LPVOID]
    user.CreateWindowExW.restype = w.HWND
    user.GetMessageW.argtypes = [ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT]
    user.GetMessageW.restype = w.BOOL
    user.DispatchMessageW.argtypes = [ctypes.POINTER(w.MSG)]
    user.DispatchMessageW.restype = ctypes.c_ssize_t
    user.TranslateMessage.argtypes = [ctypes.POINTER(w.MSG)]
    user.SetTimer.argtypes = [w.HWND, ctypes.c_size_t, w.UINT, w.LPVOID]
    user.SetTimer.restype = ctypes.c_size_t
    user.DestroyWindow.argtypes = [w.HWND]
    user.UnregisterClassW.argtypes = [w.LPCWSTR, w.HINSTANCE]
    kernel.GetModuleHandleW.argtypes = [w.LPCWSTR]
    kernel.GetModuleHandleW.restype = w.HMODULE
    kernel.GetCurrentProcessId.restype = w.DWORD

    @WNDPROC
    def procedure(hwnd, message, wp, lp):
        if message == 0x0113:  # The self-test's 40-second process lifetime timer.
            user.PostQuitMessage(0)
            return 0
        return user.DefWindowProcW(hwnd, message, wp, lp)

    instance = kernel.GetModuleHandleW(None)
    class_name = 'Jev.GuiBridge.SelfTest.' + str(kernel.GetCurrentProcessId())
    window_class = WNDCLASS(0, procedure, 0, 0, instance, None, None, None, None, class_name)
    if not user.RegisterClassW(ctypes.byref(window_class)):
        raise ctypes.WinError(ctypes.get_last_error())
    hwnd = user.CreateWindowExW(0, class_name, '', 0, 0, 0, 0, 0,
                                ctypes.c_void_p(-3), None, instance, None)  # HWND_MESSAGE
    if not hwnd:
        raise ctypes.WinError(ctypes.get_last_error())
    user.SetTimer(hwnd, 1, 40000, None)
    print(json.dumps({'pid': kernel.GetCurrentProcessId(), 'hwnd': hex(hwnd)}), flush=True)
    msg = w.MSG()
    try:
        while True:
            result = user.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if result == -1:
                raise ctypes.WinError(ctypes.get_last_error())
            if result == 0:
                break
            user.TranslateMessage(ctypes.byref(msg))
            user.DispatchMessageW(ctypes.byref(msg))
    finally:
        user.DestroyWindow(hwnd)
        user.UnregisterClassW(class_name, instance)


def verify_window(pid, hwnd):
    user = ctypes.WinDLL('user32', use_last_error=True)
    user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    user.GetWindowThreadProcessId.restype = w.DWORD
    actual_pid = w.DWORD()
    thread_id = user.GetWindowThreadProcessId(w.HWND(hwnd), ctypes.byref(actual_pid))
    if not thread_id or actual_pid.value != pid:
        raise RuntimeError('HWND does not belong to the requested PID')
    return thread_id


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int)
    parser.add_argument('--hwnd', type=lambda text: int(text, 0))
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--child-window', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child_window:
        child_window()
        return 0
    if args.self_test and (args.pid is not None or args.hwnd is not None):
        parser.error('--self-test creates its own target; do not supply pid or hwnd')
    if not args.self_test and (args.pid is None or args.hwnd is None):
        parser.error('supply both --pid and --hwnd, or use --self-test')

    child = session = script = None
    started = time.monotonic()
    report = {'mode': 'self_test' if args.self_test else 'wechat_gui_thread_diagnostic',
              'frida_version': frida.__version__, 'max_seconds': MAX_SECONDS,
              'attached': False, 'unloaded': False, 'detached': False, 'passed': False}
    events = []
    errors = []
    finished = threading.Event()

    def on_message(message, _data):
        if message.get('type') == 'send':
            payload = message['payload']
            events.append(payload)
            if payload.get('event') == 'done':
                finished.set()
        else:
            errors.append({'type': message.get('type'), 'description': message.get('description', '')})
            finished.set()

    try:
        if args.self_test:
            child = subprocess.Popen([HOST_PYTHON, str(Path(__file__).resolve()), '--child-window'],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            lines = queue.Queue()
            threading.Thread(target=lambda: lines.put(child.stdout.readline()), daemon=True).start()
            initial = json.loads(lines.get(timeout=3))
            if initial['pid'] != child.pid:
                raise RuntimeError('Self-test target is not the new child process')
            args.pid, args.hwnd = child.pid, int(initial['hwnd'], 0)
            expected_exe = HOST_PYTHON
            dll = Path(HOST_PYTHON)
            raw = dll.read_bytes()
            expected_sha = hashlib.sha256(raw).hexdigest()
            pe = pefile.PE(data=raw, fast_load=True)
            build_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        else:
            expected_exe, dll, expected_sha, build_rva = EXE, DLL, EXPECTED_SHA, BUILD_RVA
            raw = dll.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected_sha:
                raise RuntimeError('DLL changed; static compatibility analysis must be rerun')
            pe = pefile.PE(data=raw, fast_load=True)
        if process_path(args.pid).lower() != expected_exe.lower():
            raise RuntimeError('PID does not match the verified executable path')
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20B:
            raise RuntimeError('Verified module must be PE32+ x64')
        gui_thread = verify_window(args.pid, args.hwnd)
        prologue = list(pe.get_data(build_rva, 24))
        if len(prologue) != 24:
            raise RuntimeError('Invalid verified code range')
        pe.close()
        config = {'pid': args.pid, 'hwnd': hex(args.hwnd), 'selfTest': args.self_test,
                  'dllPath': str(dll), 'moduleName': dll.name,
                  'buildRva': build_rva, 'prologue': prologue,
                  'messageName': 'Jev.NativeGuiBridge.Probe.' + uuid.uuid4().hex,
                  'nonce': uuid.uuid4().int & 0x7fffffff}
        report.update(target_pid=args.pid, hwnd=hex(args.hwnd), gui_thread_id=gui_thread,
                      dll_sha256=expected_sha, module=str(dll))
        session = frida.attach(args.pid)
        report['attached'] = True
        source = 'const CONFIG=' + json.dumps(config) + ';\n' + (ROOT / 'gui_bridge_probe.js').read_text(encoding='utf-8')
        script = session.create_script(source)
        script.on('message', on_message)
        script.load()
        remaining = max(0, MAX_SECONDS - (time.monotonic() - started))
        if not finished.wait(remaining):
            raise TimeoutError('GUI bridge did not complete within ten seconds')
        if errors:
            raise RuntimeError('GUI bridge initialization or script failed')
        done = next((event for event in reversed(events) if event.get('event') == 'done'), None)
        report['result'] = done
        report['passed'] = bool(done and done.get('passed') and done['expectedGuiThreadId'] == gui_thread)
    except Exception as error:
        report['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if script is not None:
            try:
                if not any(event.get('event') == 'done' for event in events):
                    report['stop_result'] = script.exports_sync.stop()
            except Exception as error:
                report['stop_error'] = type(error).__name__
            try:
                script.unload()
                report['unloaded'] = True
            except Exception as error:
                report['unload_error'] = type(error).__name__
        if session is not None:
            try:
                session.detach()
                report['detached'] = True
            except Exception as error:
                report['detach_error'] = type(error).__name__
        if child is not None:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
            report['child_reaped'] = child.poll() is not None
        report['events'] = events
        report['script_errors'] = errors
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['passed'] = bool(report['passed'] and report['unloaded'] and report['detached']
                                and report.get('child_reaped', True))
        name = 'gui-bridge-selftest.json' if args.self_test else 'gui-bridge-probe.json'
        (ROOT / name).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
