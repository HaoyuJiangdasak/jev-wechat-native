"""Recover ChatTextItemView's vtable RVA from live objects, read-only.

The adapter compares every candidate widget's vtable against this RVA, but it
cannot be recovered statically: MSVC strips the class name from RTTI and 151
vtables share its base-class count. So it is read from the real object graph
instead, using a relation the adapter itself relies on - a widget stores its
text label at +0x508 and the label stores the widget back at +0x410.

The scan walks readable, non-writable memory for pointers equal to the already
verified XTextView (label) vtable, treats each hit as a label, follows +0x410
to the widget, and reports the widget's vtable. No writes, no function calls,
no chat text is read or transmitted.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The adapter under test, resolved relative to this repository layout.
APP = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP / 'tool-libs'))
import frida

# Verified statically for 4.1.15.13.
LABEL_VTABLE = 0x91D1C08
MODULE_SIZE = 0xC0AE000      # SizeOfImage of this build; bounds the vtable check

JS = r'''
const base = Process.getModuleByName('Weixin.dll').base;
const LABEL = base.add(CONFIG.labelVtable);
const ownerVtables = {};
const stats = {regions:0, scanned:0, labelHits:0, ownerRead:0, selfConsistent:0, errors:0};
function bump(k){ ownerVtables[k]=(ownerVtables[k]||0)+1; }

const ranges = Process.enumerateRanges({protection:'r--', coalesce:true})
  .concat(Process.enumerateRanges({protection:'rw-', coalesce:true}));
const needle = LABEL.toString();
for(const range of ranges){
  stats.regions++;
  if(range.size > 0x4000000) continue;           // skip huge mappings
  let hits;
  try { hits = Memory.scanSync(range.base, range.size, LABEL.toMatchPattern('exact')); }
  catch(_) { stats.errors++; continue; }
  stats.scanned += range.size;
  for(const hit of hits){
    stats.labelHits++;
    try{
      const label = hit.address;
      const owner = label.add(0x410).readPointer();
      if(owner.isNull()) continue;
      // The adapter requires the reciprocal link before trusting a widget.
      if(!owner.add(0x508).readPointer().equals(label)) continue;
      stats.ownerRead++;
      const vt = owner.readPointer().sub(base);
      const n = vt.toInt32();
      if(n<=0 || n>=CONFIG.moduleSize) continue;
      stats.selfConsistent++;
      bump(vt.toString());
    }catch(_){ stats.errors++; }
  }
}
send({event:'result', ownerVtables, stats});
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--timeout', type=int, default=60)
    args = parser.parse_args()

    result = {}
    started = time.monotonic()
    session = frida.attach(args.pid, persist_timeout=args.timeout + 30)
    script = session.create_script(
        'const CONFIG=' + json.dumps({'labelVtable': LABEL_VTABLE,
                                      'moduleSize': MODULE_SIZE}) + ';\n' + JS)
    script.on('message', lambda m, _d: result.update(m['payload']) if m.get('type') == 'send' else None)
    script.load()

    while time.monotonic() - started < args.timeout and 'stats' not in result:
        time.sleep(0.5)

    script.unload()
    session.detach()

    stats = result.get('stats', {})
    dist = result.get('ownerVtables', {})
    ranked = sorted(dist.items(), key=lambda kv: -kv[1])
    print(json.dumps({'stats': stats, 'ownerVtables': ranked[:8]}, indent=1))
    if ranked:
        best = int(ranked[0][0], 16)
        print()
        print(f'ownerVtable candidate : {hex(best)}  (observed {ranked[0][1]}x)')
        print(f'old                   : 0x9175d78')
        print(f'delta                 : {hex(best - 0x9175d78)}')
        print(f'distinct candidates   : {len(ranked)}')
    else:
        print('no owner widget found; WeChat may have no chat view open')
        print(f'scanned {stats.get("scanned", 0)} bytes over {stats.get("regions", 0)} regions, '
              f'{stats.get("labelHits", 0)} label hits')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
