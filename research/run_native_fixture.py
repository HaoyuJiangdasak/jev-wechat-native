"""Run a bounded, clearly marked local native-display test and restore it."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import sys
import threading
import time

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'tool-libs'))
import frida
import pefile
from probe_native_views import DLL, EXE, EXPECTED_SHA, process_path


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--pid',type=int,required=True)
    ap.add_argument('--hwnd',type=int,required=True)
    ap.add_argument('--seconds',type=int,default=120,choices=range(10,181))
    ap.add_argument('--hold',type=int,default=35,choices=range(5,61))
    args=ap.parse_args()
    if process_path(args.pid).lower()!=EXE.lower():raise RuntimeError('Unexpected process')
    raw=DLL.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=EXPECTED_SHA:raise RuntimeError('Unverified WeChat version')
    pe=pefile.PE(data=raw,fast_load=True)
    config={'dllPath':str(DLL),'pid':args.pid,'hwnd':args.hwnd,'nonce':secrets.token_hex(12),
            'bindingVtables':[entry['binding_vtable_rva'] for entry in json.loads(
                (ROOT/'text-binding-static-candidates.json').read_text(encoding='utf-8'))['candidates']],
            'functions':[{'rva':rva,'bytes':list(pe.get_data(rva,24))}
                         for rva in (0x27f80,0x14e0,0x1e80d40,0x5bbfc0,0x1bc6490)]}
    received={};ready=threading.Event();done=threading.Event();stopped_event=threading.Event();errors=[]
    last_binding=0.0;applied_at=0.0
    report={'kind':'temporary_local_native_view_fixture','pid':args.pid,'dll_sha256':EXPECTED_SHA,
            'attached':False,'unloaded':False,'detached':False,'restore_confirmed':False}
    session=script=None

    def on_message(message,_data):
        nonlocal last_binding,applied_at
        if message.get('type')!='send':
            errors.append({'type':message.get('type'),'description':message.get('description','')})
            ready.set();done.set();return
        payload=message['payload'];event=payload.get('event','unknown')
        received[event]=payload
        if event=='ready':ready.set()
        if event=='bindings':last_binding=time.monotonic()
        if event=='fixture_applied':applied_at=time.monotonic()
        if event in ('stopped','operation_error'):done.set()
        if event=='stopped':
            report['restore_confirmed']=payload.get('unresolved',1)==0
            stopped_event.set()
        if event!='bindings':print(json.dumps(payload,ensure_ascii=True),flush=True)
        # Only counters/geometry reach disk; chat text remains inside the process.
        (ROOT/'native-fixture-live.json').write_text(json.dumps(received,indent=2),encoding='utf-8')

    try:
        session=frida.attach(args.pid);report['attached']=True
        script=session.create_script('const CONFIG='+json.dumps(config)+';\n'+(ROOT/'native_view_fixture.js').read_text(encoding='utf-8'))
        script.on('message',on_message);script.load()
        if not ready.wait(10) or errors:raise RuntimeError('Fixture adapter did not initialize')
        script.exports_sync.check_qstring()
        deadline=time.monotonic()+args.seconds
        requested=False;restore_requested=False;request_at=0.0
        while time.monotonic()<deadline and not done.is_set():
            now=time.monotonic()
            if ('qstring_checked' in received and last_binding and now-last_binding>.6
                    and not requested):
                received.pop('no_view',None);received.pop('animation_busy',None)
                script.exports_sync.apply_fixture();requested=True;request_at=now
            if requested and not applied_at and now-request_at>2 and (
                    'no_view' in received or 'animation_busy' in received):
                requested=False
            if applied_at and now-applied_at>=args.hold and not restore_requested:
                script.exports_sync.restore();restore_requested=True
            if restore_requested and 'restored' in received:
                break
            if 'operation_error' in received:break
            time.sleep(.2)
        for _ in range(3):
            script.exports_sync.stop()
            if stopped_event.wait(2):break
        report['stats']=script.exports_sync.snapshot()
        report['write_restore_passed']=bool(report['stats']['applied']==1 and report['stats']['restored']==1
                                            and report['stats']['errors']==0 and report['restore_confirmed'])
        geometry={item['stage']:item for item in report['stats']['measured']}
        before,after=geometry.get('before',{}),geometry.get('after',{})
        report['geometry_grew']=bool(before.get('label') and after.get('label')
            and before.get('owner') and after.get('owner')
            and after['label']['height']>before['label']['height']
            and after['owner']['height']>before['owner']['height'])
        report['visual_review']='pending: inspect message placement, overlap and restoration'
        report['passed']=report['write_restore_passed'] and report['geometry_grew']
    except Exception as exc:
        report['error']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if script:
            if not report['restore_confirmed']:
                try:
                    script.exports_sync.stop();stopped_event.wait(3)
                except Exception:pass
            try:script.unload();report['unloaded']=True
            except Exception as exc:report['unload_error']=type(exc).__name__
        if session:
            try:session.detach();report['detached']=True
            except Exception as exc:report['detach_error']=type(exc).__name__
        report['script_errors']=errors
        report['passed']=bool(report.get('passed') and report['unloaded'] and report['detached'])
        (ROOT/'native-fixture-result.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
