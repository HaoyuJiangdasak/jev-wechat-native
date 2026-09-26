"""Bounded observation of native view construction; no text or database writes.

The opt-in watch mode installs a temporary Frida function observer. It only
reports counters and object vtable offsets. It never reads message text,
credentials, or databases and never calls an application function.
"""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'tool-libs'))
import frida
import pefile

DLL = Path(r'C:\Program Files\Tencent\Weixin\4.1.15.11\Weixin.dll')
EXE = r'C:\Program Files\Tencent\Weixin\Weixin.exe'
EXPECTED_SHA = '7d056cf7fb834b5558d6646bfb4e0036aae93568e3f9a04cf1dfc5e79032bcac'
BUILD_RVA = 0x1bc8640


def process_path(pid):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), 'Cannot query target process')
    try:
        length = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(length.value)
        if not kernel.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
            raise OSError(ctypes.get_last_error(), 'Cannot verify process image')
        return buffer.value
    finally:
        kernel.CloseHandle(handle)


JS = r'''
const mod = Process.getModuleByName('Weixin.dll');
if (mod.path.toLowerCase() !== CONFIG.dllPath.toLowerCase()) throw Error('Unexpected DLL path');
if (Process.arch !== 'x64' || Process.pointerSize !== 8) throw Error('Architecture mismatch');
const expected = CONFIG.prologue;
const address = mod.base.add(CONFIG.buildRva);
const actual = Array.from(new Uint8Array(address.readByteArray(expected.length)));
if (!actual.every((v,i) => v === expected[i])) throw Error('Function bytes do not match verified disk image');
let stats = {mode:CONFIG.watch ? 'observe_view_creation' : 'module_check', builds:0,
  validNativeViews:0, rejectedObjects:0, errors:0, textVtableRvas:[], uniqueViews:0,
  textSetters:0, ownedTextSetters:0, ownerVtables:[], callerRvas:[], textLengths:[]};
const seen = new Set();
let listener = null;
let setterListener = null;
if (CONFIG.watch) {
  setterListener = Interceptor.attach(mod.base.add(0x1e80d40), {
    onEnter(args) {
      stats.textSetters++;
      try {
        const label = args[0];
        if (!label.readPointer().equals(mod.base.add(0x91cfb08))) return;
        const owner = label.add(0x410).readPointer();
        if (owner.isNull() || !owner.add(0x508).readPointer().equals(label)) return;
        stats.ownedTextSetters++;
        const vt = owner.readPointer().sub(mod.base).toString();
        if(!stats.ownerVtables.includes(vt))stats.ownerVtables.push(vt);
        const caller = this.returnAddress.sub(mod.base).toString();
        if(!stats.callerRvas.includes(caller))stats.callerRvas.push(caller);
        const n = args[1].readPointer().add(4).readS32();
        if(n >= 0 && n <= 16384 && stats.textLengths.length < 20)stats.textLengths.push(n);
        seen.add(owner.toString()); stats.uniqueViews = seen.size;
      } catch(_) { stats.errors++; }
    }
  });
  listener = Interceptor.attach(address, {
    onEnter(args) { this.view = args[0]; },
    onLeave() {
      stats.builds++;
      try {
        const box = this.view.add(0x500).readPointer();
        const label = this.view.add(0x508).readPointer();
        if (box.isNull() || label.isNull()) { stats.rejectedObjects++; return; }
        const vt = label.readPointer();
        if (vt.compare(mod.base) < 0 || vt.compare(mod.base.add(mod.size)) >= 0) {
          stats.rejectedObjects++; return;
        }
        const relative = vt.sub(mod.base).toString();
        if (!stats.textVtableRvas.includes(relative)) stats.textVtableRvas.push(relative);
        if (relative !== '0x91cfb08') { stats.rejectedObjects++; return; }
        stats.validNativeViews++;
        seen.add(this.view.toString());
        stats.uniqueViews = seen.size;
      } catch (_) { stats.errors++; }
    }
  });
}
send({event:'ready', ...stats});
const timer = setInterval(() => send({event:'counters', ...stats}), 1000);
rpc.exports = {snapshot() { return stats; }, stop() { clearInterval(timer); if(listener)listener.detach(); if(setterListener)setterListener.detach(); return stats; }};
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--watch', action='store_true')
    parser.add_argument('--seconds', type=int, default=2, choices=range(1, 181))
    args = parser.parse_args()
    if process_path(args.pid).lower() != EXE.lower():
        raise RuntimeError('PID is not the verified WeChat executable')
    raw = DLL.read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA:
        raise RuntimeError('DLL changed; static compatibility analysis must be rerun')
    pe = pefile.PE(data=raw,fast_load=True)
    config = {'dllPath':str(DLL),'buildRva':BUILD_RVA,
              'prologue':list(pe.get_data(BUILD_RVA,24)),'watch':args.watch}
    ready = threading.Event()
    latest = {}
    failures = []
    report = {'target_pid':args.pid,'dll_sha256':EXPECTED_SHA,'frida_version':frida.__version__,
              'mode':'observe_view_creation' if args.watch else 'module_check',
              'attached':False,'detached':False,'unloaded':False,'passed':False}
    session = script = None

    def message(msg, _data):
        if msg.get('type') == 'send':
            latest.update(msg['payload'])
            if args.watch:
                (ROOT/'native-probe-live.json').write_text(json.dumps(latest),encoding='utf-8')
            if latest.get('event') == 'ready':
                ready.set()
                print(json.dumps({'event':'ready','mode':report['mode']}),flush=True)
        else:
            failures.append({'type':msg.get('type'),'description':msg.get('description','')})
            ready.set()

    try:
        session = frida.attach(args.pid)
        report['attached'] = True
        script = session.create_script('const CONFIG='+json.dumps(config)+';\n'+JS)
        script.on('message',message)
        script.load()
        if not ready.wait(10) or failures:
            raise RuntimeError('Native observer could not initialize')
        deadline = time.monotonic()+args.seconds
        while time.monotonic() < deadline:
            time.sleep(min(.25,max(0,deadline-time.monotonic())))
        report['counters'] = script.exports_sync.stop()
        report['passed'] = not failures
    except Exception as exc:
        report['error'] = {'type':type(exc).__name__,'message':str(exc)}
    finally:
        if script:
            try:
                script.unload()
                report['unloaded'] = True
            except Exception as exc:
                report['unload_error'] = type(exc).__name__
        if session:
            try:
                session.detach()
                report['detached'] = True
            except Exception as exc:
                report['detach_error'] = type(exc).__name__
        report['script_errors'] = failures
        report['passed'] = report['passed'] and report['unloaded'] and report['detached']
        suffix = 'watch' if args.watch else 'module'
        (ROOT/f'native-probe-{suffix}.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report,indent=2),flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
