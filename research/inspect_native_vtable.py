"""Inspect version-gated MSVC RTTI/vtable bytes without process attachment."""
from pathlib import Path
import hashlib
import json
import struct
import sys
import pefile

ROOT = Path(__file__).resolve().parent
evidence = json.loads((ROOT / 'native-storage-candidates.json').read_text())
raw = Path(evidence['path']).read_bytes()
assert hashlib.sha256(raw).hexdigest() == evidence['sha256']
pe = pefile.PE(data=raw, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase

def unpack(fmt, rva):
    return struct.unpack('<'+fmt, pe.get_data(rva, struct.calcsize('<'+fmt)))

def typename(rva):
    return pe.get_data(rva+16, 500).split(b'\0',1)[0].decode('ascii','backslashreplace')

def inspect(vt):
    col = unpack('Q',vt-8)[0]-base
    sign,offset,cd,td,chd,self_rva = unpack('IIIIII',col)
    if sign != 1 or self_rva != col:
        raise ValueError('No matching x64 RTTI COL')
    _,attributes,count,array = unpack('IIII',chd)
    assert count < 100
    bases=[]
    for i in range(count):
        bcd=unpack('I',array+4*i)[0]
        btd,contained,mdisp,pdisp,vdisp,flags = unpack('IIiiiI',bcd)
        bases.append({'type_rva':hex(btd),'name':typename(btd),'mdisp':mdisp,'pdisp':pdisp,'vdisp':vdisp,'attributes':flags})
    slots={}
    for i in range(100):
        value=unpack('Q',vt+8*i)[0]-base
        if not 0 < value < pe.OPTIONAL_HEADER.SizeOfImage:
            break
        if not any(s.VirtualAddress<=value<s.VirtualAddress+s.Misc_VirtualSize and s.Characteristics&0x20000000 for s in pe.sections):
            break
        slots[hex(8*i)]=hex(value)
    return {'vtable':hex(vt),'complete_offset':offset,'complete_type_rva':hex(td),'name':typename(td),'bases':bases,'slots':slots}

out = [inspect(int(a,0)) for a in sys.argv[1:]]
tag='-'.join(a[2:] for a in (row['vtable'] for row in out))
(ROOT/f'vtable-inspection-{tag}.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8')
print(json.dumps(out,indent=2))
