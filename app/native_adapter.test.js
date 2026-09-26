'use strict';
// Runs the actual adapter in node:vm with a synthetic address space and event
// queues. No Frida package, process attach, DLL loading, networking, or real UI.
// Geometry is independently covered by test_native_geometry.js; here only its
// visibility contract is mocked so lifecycle failures stay easy to diagnose.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const SOURCE = fs.readFileSync(path.join(__dirname, 'native_adapter.js'), 'utf8');
const BASE = 0x180000000;
// The adapter reads its addresses from the resolved anchor set, so the harness
// models exactly those values. Loading the real file keeps the synthetic layout
// in step with the adapter instead of drifting, and means the tests exercise the
// addresses that are actually shipped.
const ANCHOR_FILE = path.join(__dirname, 'native_anchors.json');
const ANCHORS = fs.existsSync(ANCHOR_FILE)
  ? JSON.parse(fs.readFileSync(ANCHOR_FILE, 'utf8'))
  : null;
const A = ANCHORS || {
  functions: {fromUtf8:{rva:0x27f80},destroyQString:{rva:0x14e0},setText:{rva:0x1e80d40},
    widgetMetaCall:{rva:0x5bbfc0},isSelf:{rva:0x5c41810},rebindListener:{rva:0x1bc6490}},
  vtables: {bindingVtable:0x956b278,uiMessageVtable:0x8d9c978,listenerVtable:0x95884e8,
    ownerVtable:0x9175d78,labelVtable:0x91cfb08},
  metaobjects: {recyclerMeta:0x8e9c418,scrollAreaMeta:0x8f1e978,scrollBarMeta:0x91cd6b8},
  module_size: 0xc0ac000
};
const RVA = {fromUtf8:A.functions.fromUtf8.rva,destroyQString:A.functions.destroyQString.rva,
  setText:A.functions.setText.rva,widgetMetaCall:A.functions.widgetMetaCall.rva,
  isSelf:A.functions.isSelf.rva,rebind:A.functions.rebindListener.rva};
const VT = A.vtables;

function harness(source=SOURCE) {
  const cells=new Map(), strings=new Map(), hooks=new Map(), functions=new Map();
  const owners=new Map(), roles=new Map(), timers=new Map();
  const posted=[], immediates=[], events=[], writes=[];
  let address=0x10000000, now=1000, nextTimer=1, nextNativeWrite=null;
  const PID=777, GUI_THREAD=88, HWND=1234, WNDPROC=0x71000000;
  class Pointer {
    constructor(value){this.value=Number(value);}
    add(offset){return new Pointer(this.value+Number(offset));}
    sub(offset){return new Pointer(this.value-Number(offset instanceof Pointer?offset.value:offset));}
    equals(other){return this.value===pointer(other).value;}
    isNull(){return this.value===0;}
    toString(){return '0x'+this.value.toString(16);}
    toUInt32(){return this.value>>>0;}
    readPointer(){return pointer(cells.get(this.value)||0);}
    writePointer(value){cells.set(this.value,pointer(value).value);}
    readU8(){return Number(cells.get(this.value)||0)&255;}
    readU32(){return Number(cells.get(this.value)||0)>>>0;}
    readS32(){return Number(cells.get(this.value)||0)|0;}
    readU64(){return BigInt(cells.get(this.value)||0);}
    readS64(){return BigInt(cells.get(this.value)||0);}
    writeU32(value){cells.set(this.value,Number(value)>>>0);}
    writeByteArray(value){for(let i=0;i<value.length;i++)cells.set(this.value+i,value[i]);}
    readByteArray(length){return Uint8Array.from({length},(_,i)=>cells.get(this.value+i)||0).buffer;}
    readUtf8String(){return strings.get(this.value)||'';}
    readUtf16String(){return strings.get(this.value)||'';}
  }
  function pointer(value){return value instanceof Pointer?value:new Pointer(value);}
  const Memory={
    alloc(size){const result=pointer(address);address+=Math.max(0x1000,size+64);return result;},
    allocUtf8String(text){const result=this.alloc(text.length*4+4);strings.set(result.value,text);return result;},
    allocUtf16String(text){const result=this.alloc(text.length*2+2);strings.set(result.value,text);return result;}
  };
  function qstring(text,out=Memory.alloc(8)){
    const data=Memory.alloc(text.length*2+64);out.writePointer(data);
    cells.set(data.value+4,text.length);cells.set(data.value+16,32);
    strings.set(data.value+32,text);return out;
  }
  function readQString(q){const data=q.readPointer();return strings.get(data.value+32);}
  function stdString(object,text){
    cells.set(object.value+16,Buffer.byteLength(text));
    cells.set(object.value+24,Math.max(15,Buffer.byteLength(text)));
    if(Buffer.byteLength(text)<16)strings.set(object.value,text);
    else object.writePointer(Memory.allocUtf8String(text));
  }
  function callHooks(location,args){
    for(const entry of hooks.get(location)||[]){
      if(!entry.detached&&entry.handler.onEnter)
        entry.handler.onEnter.call({threadId:GUI_THREAD},args);
    }
  }
  functions.set(BASE+RVA.fromUtf8,(out,data)=>{qstring(data.readUtf8String(),out);return out;});
  functions.set(BASE+RVA.destroyQString,()=>{});
  functions.set(BASE+RVA.setText,(label,q)=>{
    callHooks(BASE+RVA.setText,[label,q]);
    const text=readQString(q);writes.push({label:label.toString(),text});
    const owner=owners.get(label.add(0x410).readPointer().value);
    if(owner)owner.display=text;
    if(nextNativeWrite){const callback=nextNativeWrite;nextNativeWrite=null;callback();}
  });
  functions.set(BASE+RVA.widgetMetaCall,(widget,call,id,argv)=>{
    assert.equal(call,1);assert.equal(id,35);
    cells.set(argv.readPointer().value,owners.get(widget.value)?.visible?1:0);
  });
  functions.set(BASE+RVA.isSelf,binding=>roles.get(binding.value)||false);
  const exports=new Map();
  function win(name,implementation){const location=0x72000000+exports.size*16;exports.set(name,pointer(location));functions.set(location,implementation);}
  win('GetWindowThreadProcessId',(hwnd,out)=>{assert.equal(hwnd.value,HWND);out.writeU32(PID);return GUI_THREAD;});
  win('GetWindowLongPtrW',()=>pointer(WNDPROC));
  win('RegisterWindowMessageW',()=>0xc123);
  win('PostMessageW',(hwnd,msg,wp,lp)=>{posted.push([hwnd,pointer(msg),wp,lp]);return true;});
  win('IsIconic',()=>false);
  const context=vm.createContext({
    CONFIG:{pid:PID,hwnd:HWND,dllPath:'synthetic/Weixin.dll',nonce:'123456789abcdef',
      functions:Object.values(RVA).map(rva=>({rva,bytes:Array(24).fill(0)})),
      anchors:A},
    Process:{arch:'x64',pointerSize:8,id:PID,getModuleByName(name){
      if(name==='Weixin.dll')return {path:'synthetic/Weixin.dll',base:pointer(BASE)};
      if(name==='user32.dll')return {getExportByName(name){assert(exports.has(name));return exports.get(name);}};
      throw Error('Unexpected synthetic module');
    }},
    NativeFunction:function(location){assert(functions.has(location.value),'Unmodeled native call');return functions.get(location.value);},
    Memory,ptr:pointer,Date:{now:()=>now},
    Interceptor:{attach(location,handler){
      const entry={handler,detached:false,detach(){this.detached=true;}};
      if(!hooks.has(location.value))hooks.set(location.value,[]);
      hooks.get(location.value).push(entry);return entry;
    },flush(){}},
    createNativeGeometry(){return {inspect(widget){const owner=owners.get(widget.value);return {
      visible:!!owner?.visible,rect:[0,owner?.y||0,300,(owner?.y||0)+60],clipped:[0,0,300,60],rootId:'synthetic-root'};}};},
    // Follow-tail has its own native contract tests; lifecycle tests do not scroll.
    createNativeFollowTail(){return {begin(){return null;},step(){},cancel(){},cancelAll(){}};},
    setInterval(fn){const id=nextTimer++;timers.set(id,fn);return id;},
    clearInterval(id){timers.delete(id);},
    setImmediate(fn){immediates.push(fn);},
    send(payload){events.push(JSON.parse(JSON.stringify(payload)));},rpc:{exports:{}}
  });
  vm.runInContext(source,context,{timeout:1000,filename:'native_adapter.js'});
  function drain(flushImmediate=true){
    let steps=0;
    while(posted.length){assert(++steps<100,'Synthetic message loop must be bounded');callHooks(WNDPROC,posted.shift());}
    if(flushImmediate)while(immediates.length)immediates.shift()();
  }
  function timer(){for(const fn of [...timers.values()])fn();}
  function poll(){timer();drain();}
  function makeBinding(peer,who='her'){
    const binding=Memory.alloc(0x500),listener=Memory.alloc(0x200);
    binding.writePointer(pointer(BASE+VT.bindingVtable));
    binding.add(0x120).writePointer(pointer(BASE+VT.uiMessageVtable));
    binding.add(0xd0).writePointer(listener);listener.writePointer(pointer(BASE+VT.listenerVtable));
    cells.set(binding.value+0x128,1);
    // UIMessage identity fields used by the adapter's bounded ledger:
    // D0 is a synthetic valid Unix-second timestamp and +10 is sender ID.
    cells.set(binding.value+0x1f0,1700000000 + owners.size);
    cells.set(binding.value+0x1b4,owners.size + 1); // UIMessage +0x94 sequence
    stdString(binding.add(0x1b8),'fallback-message-'+(owners.size+1)); // +0x98
    stdString(binding.add(0x130),who==='me'?'self-synthetic':'peer-sender-'+binding.value);
    stdString(binding.add(0x190),'id-'+binding.value);
    stdString(binding.add(0x190),peer);stdString(listener.add(0xa0),peer);
    roles.set(binding.value,who==='me');return binding;
  }
  function incoming(view,text,{rebind=false}={}){
    const q=qstring(text);
    if(rebind)callHooks(BASE+RVA.rebind,[view.owner,q]);
    callHooks(BASE+RVA.setText,[view.label,q]);view.display=text;
  }
  function message(peer='peer-A',text='Synthetic remote message',who='her'){
    const owner=Memory.alloc(0x800),label=Memory.alloc(0x500),binding=makeBinding(peer,who);
    owner.writePointer(pointer(BASE+VT.ownerVtable));label.writePointer(pointer(BASE+VT.labelVtable));
    owner.add(0x508).writePointer(label);owner.add(0x250).writePointer(binding);label.add(0x410).writePointer(owner);
    const view={owner,label,binding,visible:true,y:owners.size*80,display:text};
    owners.set(owner.value,view);incoming(view,text);return view;
  }
  function snapshot(){return events.filter(e=>e.event==='snapshot').at(-1)?.snapshot;}
  function generation(view){return snapshot()?.messages.find(m=>m.id===view.owner.toString())?.generation;}
  function settle(){now+=700;poll();}
  function annotate(view,text='Jev｜Synthetic analysis'){
    return context.rpc.exports.annotate(view.owner.toString(),generation(view),text);
  }
  drain();assert(events.some(e=>e.event==='ready'),'Adapter initialization must complete');
  return {rpc:context.rpc.exports,message,incoming,makeBinding,drain,poll,timer,settle,
    onNextNativeWrite(callback){nextNativeWrite=callback;},
    advance(ms){now+=ms;},snapshot,generation,annotate,writes,events,
    changePeerInPlace(view,peer){
      stdString(view.binding.add(0x190),peer);
      stdString(view.binding.add(0xd0).readPointer().add(0xa0),peer);
    },
    setIdentity(view,sequence,fallback){
      cells.set(view.binding.value+0x1b4,sequence);
      stdString(view.binding.add(0x1b8),fallback);
    },
    activeHooks(){return [...hooks.values()].flat().filter(h=>!h.detached).length;},
    timerCount(){return timers.size;},
    flushImmediate(){while(immediates.length)immediates.shift()();}};
}

let passed=0;
function test(name,run){run();passed++;process.stdout.write('PASS '+name+'\n');}

test('watchdog restores before queued annotation and detaches all hooks',()=>{
  const h=harness(),view=h.message();h.settle();h.annotate(view);h.drain();
  assert.equal(h.writes.length,1);
  h.advance(11000);h.timer(); // Queue watchdog work ahead of another annotation.
  assert.equal(h.annotate(view,'Jev｜Late queued result'),true);
  h.drain(false); // Exercise stale OS messages before deferred bridge detach.
  assert.equal(h.writes.length,2);
  assert.equal(h.writes.at(-1).text,'Synthetic remote message');
  assert.equal(h.rpc.snapshot().applied,1);
  assert(h.events.some(e=>e.event==='stopped'&&e.unresolved===0));
  h.flushImmediate();assert.equal(h.activeHooks(),0);assert.equal(h.timerCount(),0);
  assert.equal(h.annotate(view),false);
});

test('explicit stop blocks annotation already in the GUI queue',()=>{
  const h=harness(),view=h.message();h.settle();h.annotate(view);h.drain();
  h.annotate(view,'Jev｜Queued before stop');h.rpc.stop();h.drain();
  assert.equal(h.writes.length,2);assert.equal(h.rpc.snapshot().applied,1);
  assert.equal(h.writes.at(-1).text,'Synthetic remote message');
});

test('asynchronous setter echo preserves original text and generation',()=>{
  const h=harness(),view=h.message();h.settle();const generation=h.generation(view);
  h.annotate(view);h.drain();const injected=view.display;
  h.incoming(view,injected); // Happens after applying returned to zero.
  h.message('peer-A','Another synthetic turn','me');h.settle();
  const remote=h.snapshot().messages.find(m=>m.id===view.owner.toString());
  assert.equal(remote.generation,generation);assert.equal(remote.text,'Synthetic remote message');
  assert(!remote.text.includes('Jev｜'));
  h.rpc.stop();h.drain();assert.equal(view.display,'Synthetic remote message');
});

test('rebind plus setter echo preserves restoration tracking',()=>{
  const h=harness(),view=h.message();h.settle();const generation=h.generation(view);
  h.annotate(view);h.drain();h.incoming(view,view.display,{rebind:true});
  h.message('peer-A','Another synthetic turn','me');h.settle();
  const remote=h.snapshot().messages.find(m=>m.id===view.owner.toString());
  assert.equal(remote.generation,generation);assert.equal(remote.text,'Synthetic remote message');
  h.rpc.stop();h.drain();assert.equal(h.rpc.snapshot().restored,1);
});

test('a new generation drops a queued result without overwriting the new message',()=>{
  const h=harness(),view=h.message();h.settle();const generation=h.generation(view);
  h.annotate(view);h.incoming(view,'Replacement synthetic message',{rebind:true});
  h.advance(700);h.drain();h.poll();
  const current=h.snapshot().messages.filter(m=>m.text==='Replacement synthetic message').at(-1);
  assert(current && current.generation!==generation);assert.equal(h.writes.length,0);
  assert.equal(view.display,'Replacement synthetic message');
});

test('binding pointer replacement invalidates a queued result even without setter notification',()=>{
  const h=harness(),view=h.message();h.settle();h.annotate(view);
  view.owner.add(0x250).writePointer(h.makeBinding('peer-B'));
  h.drain();assert.equal(h.writes.length,0);assert.equal(h.rpc.snapshot().applied,0);
});

test('conversation switch drops queued old-chat results and exposes only new peer',()=>{
  const h=harness(),old=h.message();h.settle();h.annotate(old);
  old.visible=false;const next=h.message('peer-B','Synthetic other conversation');
  h.advance(700);h.drain();h.poll();
  assert.equal(h.writes.length,0);assert.equal(h.snapshot().conversation,'peer-B');
  assert.equal(h.snapshot().messages.length,1);assert.equal(h.snapshot().messages[0].id,next.owner.toString());
});

test('settling guard drops results before a stable snapshot can be published',()=>{
  const h=harness(),view=h.message();h.settle();h.annotate(view);
  h.message('peer-A','New synthetic turn','me');h.drain();
  assert.equal(h.writes.length,0);
});

test('queued annotation retains its original conversation even if the model updates in place',()=>{
  const h=harness(),view=h.message();h.settle();
  h.timer(); // Collection runs before the queued result, but after the RPC call.
  h.annotate(view,'Jev｜Analysis belonging to peer A');
  h.changePeerInPlace(view,'peer-B');
  h.drain();
  assert.equal(h.snapshot().conversation,null,'Changed model identity must await a fresh setter binding');
  assert.equal(h.writes.length,0,'Old peer result must not follow an in-place model update');
});

test('ordinary user text containing Jev is preserved rather than blindly stripped',()=>{
  const h=harness(),view=h.message('peer-A','A user quote\n\nJev｜ordinary user-supplied text');h.settle();
  assert.equal(h.snapshot().messages[0].text,view.display);
});

test('ledger retains target eligibility when annotation hides an older view',()=>{
  const h=harness(),older=h.message('peer-A','Older remote message'),newer=h.message('peer-A','Latest remote message');
  h.settle();
  const first=h.snapshot();assert.equal(first.messages.length,2);
  h.annotate(newer);h.drain();
  older.visible=false;h.advance(700);h.poll();
  const after=h.snapshot();
  assert.equal(after.messages.length,2);
  assert(after.messages.every(message=>message.targetEligible===true));
  assert.equal(after.messages.map(message=>message.logicalId).sort().join(','),
               first.messages.map(message=>message.logicalId).sort().join(','));
});

test('ledger uses the verified fallback message key when sequence is zero',()=>{
  const h=harness(),view=h.message('peer-A','Fallback identity message');
  h.setIdentity(view,0,'stable-fallback-77');
  h.incoming(view,view.display);h.settle();
  const identity=h.snapshot().messages.filter(message=>message.text==='Fallback identity message').at(-1).logicalId;
  assert(identity.includes('stable-fallback-77'));
  assert(!identity.endsWith('_0'));
});

test('annotation reports applied only after its GUI operation succeeds',()=>{
  const h=harness(),view=h.message();h.settle();
  assert.equal(h.rpc.annotate(view.owner.toString(),h.generation(view),'Jev｜Acknowledged','delivery-1'),true);
  assert(!h.events.some(e=>e.event==='annotation_result'));
  h.drain();
  assert(h.events.some(e=>e.event==='annotation_result'&&e.deliveryId==='delivery-1'&&e.applied===true));
});

test('settling and hidden targets return negative acknowledgements for cached retry',()=>{
  const h=harness(),view=h.message();h.settle();const generation=h.generation(view);
  h.rpc.annotate(view.owner.toString(),generation,'Jev｜Deferred','delivery-settling');
  h.message('peer-A','Another turn','me');h.drain();
  assert(h.events.some(e=>e.deliveryId==='delivery-settling'&&e.applied===false));
  h.advance(700);view.visible=false;
  h.rpc.annotate(view.owner.toString(),generation,'Jev｜Deferred','delivery-hidden');h.drain();
  assert(h.events.some(e=>e.deliveryId==='delivery-hidden'&&e.applied===false));
  view.visible=true;
  h.rpc.annotate(view.owner.toString(),generation,'Jev｜Deferred','delivery-visible');h.drain();
  assert(h.events.some(e=>e.deliveryId==='delivery-visible'&&e.applied===true));
  assert.equal(h.rpc.snapshot().applied,1);
});

test('restoration never overwrites a model reused in place for another message',()=>{
  const h=harness(),view=h.message();h.settle();h.annotate(view);h.drain();
  h.setIdentity(view,992,'different-stable-message');
  view.display='Replacement message outside intercepted setters';
  h.rpc.stop();h.drain();
  assert.equal(view.display,'Replacement message outside intercepted setters');
  assert.equal(h.writes.length,1);assert.equal(h.rpc.snapshot().restored,0);
  assert(h.events.some(e=>e.event==='stopped'&&e.unresolved===0));
});

test('messages without a stable identity are rejected instead of merging by second',()=>{
  const h=harness(),view=h.message();
  h.setIdentity(view,0,'');h.incoming(view,'Message without a stable identity');h.settle();
  assert.equal(h.snapshot().conversation,null);
  assert.equal(h.rpc.snapshot().identityRejected,1);
});

test('temporarily hidden annotation remains on the same message when it reappears',()=>{
  const h=harness(),view=h.message();h.message('peer-A','Another visible message');h.settle();
  h.annotate(view);h.drain();const annotated=view.display;
  view.visible=false;h.poll();assert.equal(view.display,annotated);
  view.visible=true;h.poll();assert.equal(view.display,annotated);
  assert.equal(h.rpc.snapshot().restored,0);
  h.rpc.stop();h.drain();assert.equal(view.display,'Synthetic remote message');
});

test('writing one card observes other rows rebound synchronously during layout',()=>{
  const h=harness(),first=h.message('peer-A','First message'),second=h.message('peer-A','Second message');
  h.settle();h.annotate(first);h.drain();const oldGeneration=h.generation(first);
  h.onNextNativeWrite(()=>h.incoming(first,'First message',{rebind:true}));
  h.annotate(second);h.drain();h.settle();
  assert.notEqual(h.generation(first),oldGeneration,'Another row repaint must invalidate its displayed result');
  assert.equal(first.display,'First message');
  h.annotate(first);h.drain();assert(first.display.includes('Jev｜'));
  h.rpc.stop();h.drain();assert.equal(first.display,'First message');assert.equal(second.display,'Second message');
});

test('the same row synchronously replaced with different text cannot get a false applied acknowledgement',()=>{
  const h=harness(),view=h.message();h.settle();const generation=h.generation(view);
  h.onNextNativeWrite(()=>h.incoming(view,'Replacement during native write',{rebind:true}));
  h.rpc.annotate(view.owner.toString(),generation,'Jev｜Old analysis','same-row-replaced');h.drain();h.settle();
  assert(h.events.some(e=>e.deliveryId==='same-row-replaced'&&e.applied===false));
  assert.equal(h.rpc.snapshot().applied,0);assert.equal(view.display,'Replacement during native write');
  h.rpc.stop();h.drain();assert.equal(view.display,'Replacement during native write');
});

process.stdout.write(passed+' lifecycle tests passed; no live process was accessed\n');
