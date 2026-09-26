"""Validate the resolved vtable anchors against live WeChat objects, read-only.

Static resolution proves an address is *consistent* with the old build's layout;
it cannot prove the object graph actually uses it. This probe closes that gap
without waiting for chat activity: it scans readable memory for pointers equal to
the resolved label vtable (XTextView), follows the label -> owner link the
adapter itself requires (owner+0x508 == label, label+0x410 == owner), and
reports which vtable the real owner objects carry.

The scan runs asynchronously via Frida's callback API. A synchronous scan blocks
script loading and trips the transport timeout.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The adapter under test, resolved relative to this repository layout.
APP = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP / 'tool-libs'))
import frida

JS = r'''
const base = Process.getModuleByName('Weixin.dll').base;
const A = CONFIG.anchors;
const stats = {regions:0, scanned:0, labelHits:0, ownerRead:0, selfConsistent:0,
               done:false, errors:0};
const ownerVtables = {}, bindingVtables = {}, uiMessageVtables = {}, listenerVtables = {};
function bump(bucket, rva){ bucket[rva] = (bucket[rva]||0) + 1; }

const ranges = Process.enumerateRanges('r--')
  .concat(Process.enumerateRanges('rw-'))
  .filter(r => r.size <= 0x4000000);
let index = 0;

function step() {
  if (index >= ranges.length) {
    send({event:'result', ownerVtables, bindingVtables, uiMessageVtables,
          listenerVtables, stats});
    return;
  }
  const range = ranges[index++];
  stats.regions++;
  Memory.scan(range.base, range.size, ptr(A.vtables.labelVtable).toMatchPattern('exact'), {
    onMatch(address) {
      stats.labelHits++;
      try {
        const label = address;
        const owner = label.add(0x410).readPointer();
        if (owner.isNull()) return;
        if (!owner.add(0x508).readPointer().equals(label)) return;
        stats.ownerRead++;
        const ownerVt = owner.readPointer();
        if (ownerVt.compare(base) < 0 ||
            ownerVt.compare(base.add(A.module_size)) >= 0) return;
        stats.selfConsistent++;
        bump(ownerVtables, ownerVt.sub(base).toString());
        const binding = owner.add(0x250).readPointer();
        if (binding.isNull()) return;
        bump(bindingVtables, binding.readPointer().sub(base).toString());
        const uiMessage = binding.add(0x120);
        bump(uiMessageVtables, uiMessage.readPointer().sub(base).toString());
        const listener = binding.add(0xd0).readPointer();
        if (!listener.isNull())
          bump(listenerVtables, listener.readPointer().sub(base).toString());
      } catch (_) { stats.errors++; }
    },
    onComplete() {
      stats.scanned += range.size;
      step();
    },
    onError() { stats.errors++; step(); }
  });
}
send({event:'start', ranges:ranges.length});
step();
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--anchors', default=str(APP / 'native_anchors.json'))
    parser.add_argument('--timeout', type=int, default=90)
    args = parser.parse_args()

    anchors = json.loads(Path(args.anchors).read_text(encoding='utf-8'))
    config = {'anchors': {'vtables': anchors['vtables'],
                          'module_size': anchors['module_size']}}

    result = {}
    started = time.monotonic()
    session = frida.attach(args.pid, persist_timeout=args.timeout + 30)
    script = session.create_script('const CONFIG=' + json.dumps(config) + ';\n' + JS)

    def on_message(message, _data):
        if message.get('type') == 'send':
            payload = message['payload']
            if payload.get('event') == 'result':
                result.update(payload)
            else:
                result['_start'] = payload
        else:
            result.setdefault('_errors', []).append(message.get('description', 'unknown'))

    script.on('message', on_message)
    script.load()

    while time.monotonic() - started < args.timeout and not result.get('ownerVtables'):
        time.sleep(0.5)
    try:
        script.unload()
    except Exception:
        pass
    session.detach()

    stats = result.get('stats', {})
    expect = {'ownerVtables': anchors['vtables']['ownerVtable'],
              'bindingVtables': anchors['vtables']['bindingVtable'],
              'uiMessageVtables': anchors['vtables']['uiMessageVtable'],
              'listenerVtables': anchors['vtables']['listenerVtable']}
    print(json.dumps({k: v for k, v in result.items() if k.startswith('_')}, indent=1))
    print(f'scanned {stats.get("scanned",0)} bytes in {stats.get("regions",0)} regions; '
          f'label hits {stats.get("labelHits",0)}; self-consistent owners {stats.get("selfConsistent",0)}')
    print()
    for key, want in expect.items():
        dist = result.get(key) or {}
        ranked = sorted(dist.items(), key=lambda kv: -kv[1])[:5]
        want_hex = hex(want)
        hit = want_hex in dist
        verdict = 'CONFIRMED' if hit else ('no data' if not dist else 'MISMATCH')
        print(f'{key:18} want {want_hex:>12}  observed {ranked}   [{verdict}]')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
