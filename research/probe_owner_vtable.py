"""Read-only runtime probe that recovers the object vtable RVAs the adapter
compares against, and validates the statically-resolved ones.

`ownerVtable` (mmui::ChatTextItemView) has no static cross-reference: the class
name is stripped from RTTI and its vtable holds no distinctive slot, so it can
only be read from a live object graph. This attaches a single bounded observer
to the text setter, walks the label -> owner relation the adapter itself uses,
and reports which vtables the real objects carry. Nothing is written, no text
is read, no database is touched.

Usage: probe_owner_vtable.py --pid <pid> --seconds 20
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP = Path(__file__).resolve().parent.parent / 'app'
sys.path.insert(0, str(APP / 'tool-libs'))
import frida

# Statically resolved for 4.1.15.13; verified here against live objects.
ANCHORS = {
    'setText': 0x1E84750,
    'labelVtable': 0x91D1C08,
    'bindingVtable': 0x956D338,
    'uiMessageVtable': 0x8D9E9A8,
    'listenerVtable': 0x958A5A8,
}

JS = r'''
const base = Process.getModuleByName('Weixin.dll').base;
const A = CONFIG.anchors;
const rva = p => p.sub(base).toString();
const seen = {ownerVtables:{}, bindingVtables:{}, uiMessageVtables:{},
              listenerVtables:{}, samples:0, setterCalls:0, matchedLabels:0, errors:0};
function bump(bucket,key){ seen[bucket][key]=(seen[bucket][key]||0)+1; }
const setter = Interceptor.attach(base.add(A.setText), {
  onEnter(args){
    if(seen.samples>4000)return;
    seen.setterCalls++;
    try{
      const label = args[0];
      // Only labels whose vtable is the verified XTextView vtable.
      if(!label.readPointer().equals(base.add(A.labelVtable)))return;
      seen.matchedLabels++;
      const owner = label.add(0x410).readPointer();
      if(owner.isNull())return;
      // The adapter's own invariant: the widget and its label point at each other.
      if(!owner.add(0x508).readPointer().equals(label))return;
      bump('ownerVtables', rva(owner.readPointer()));
      const binding = owner.add(0x250).readPointer();
      if(binding.isNull())return;
      bump('bindingVtables', rva(binding.readPointer()));
      const uiMessage = binding.add(0x120);
      bump('uiMessageVtables', rva(uiMessage.readPointer()));
      const listener = binding.add(0xd0).readPointer();
      if(!listener.isNull()) bump('listenerVtables', rva(listener.readPointer()));
      seen.samples++;
    }catch(_){ seen.errors++; }
  }
});
send({event:'ready'});
const timer = setInterval(()=>send({event:'counters',...seen}), 1000);
rpc.exports = {stop(){clearInterval(timer);setter.detach();return seen;}};
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--seconds', type=int, default=20, choices=range(3, 181))
    args = parser.parse_args()

    latest = {}
    failures = []
    done = threading.Event()

    def on_message(message, _data):
        if message.get('type') == 'send':
            latest.update(message['payload'])
            if latest.get('event') == 'ready':
                done.set()
        else:
            failures.append(message)

    session = frida.attach(args.pid)
    script = session.create_script('const CONFIG=' + json.dumps({'anchors': ANCHORS}) + ';\n' + JS)
    script.on('message', on_message)
    script.load()
    done.wait(10)

    deadline = time.monotonic() + args.seconds
    while time.monotonic() < deadline:
        time.sleep(0.5)
        counters = latest
        if counters.get('samples', 0) > 0 and counters.get('event') == 'counters':
            # Enough evidence once we have several owner vtables agreeing.
            if len(counters.get('ownerVtables', {})) >= 1 and counters.get('samples', 0) >= 8:
                break

    report = script.exports_sync.stop()
    script.unload()
    session.detach()

    print(json.dumps({'failures': [f.get('description') for f in failures],
                      'counters': report}, indent=1, ensure_ascii=False))
    print()
    print(f'setter calls         : {report.get("setterCalls")}')
    print(f'labels matching XTextView: {report.get("matchedLabels")}')
    print(f'owner samples        : {report.get("samples")}')
    for key, expect in (('ownerVtables', None), ('bindingVtables', ANCHORS['bindingVtable']),
                        ('uiMessageVtables', ANCHORS['uiMessageVtable']),
                        ('listenerVtables', ANCHORS['listenerVtable'])):
        dist = report.get(key) or {}
        top = sorted(dist.items(), key=lambda x: -x[1])[:5]
        mark = ''
        if expect is not None:
            hit = dist.get(hex(expect)) or dist.get(str(hex(expect)))
            mark = '   <-- static match' if hit else '   <-- STATIC MISMATCH'
        print(f'{key:14}: {top}{mark}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
