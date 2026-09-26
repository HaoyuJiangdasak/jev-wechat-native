// Local, temporary annotation in an existing native message text view.
// No database access, sending API, process persistence, or message-content logs.
// CONFIG contains the verified image path, function bytes, HWND, and PID.
const wx = Process.getModuleByName('Weixin.dll');
if (wx.path.toLowerCase() !== CONFIG.dllPath.toLowerCase()) throw Error('Wrong module path');
for (const check of CONFIG.functions) {
  const bytes = new Uint8Array(wx.base.add(check.rva).readByteArray(check.bytes.length));
  if (!Array.from(bytes).every((v,i)=>v===check.bytes[i])) throw Error('Unverified function '+check.rva);
}
const ptr0 = ptr(0);
const fn = (rva, ret, args) => new NativeFunction(wx.base.add(rva),ret,args);
const fromUtf8 = fn(0x27f80,'pointer',['pointer','pointer','int']);
const destroyQString = fn(0x14e0,'void',['pointer']);
const setText = fn(0x1e80d40,'void',['pointer','pointer']);
const widgetMetaCall = fn(0x5bbfc0,'void',['pointer','int','int','pointer']);
let applying = 0;
let stopped = false;
let epoch = 0;
const views = new Map();
const modified = new Map();
const pending = [];
const stats = {nativeBindings:0, validViews:0, applied:0, restored:0, staleSkipped:0,
  errors:0, guiThreadChecks:0, qstringChecks:0, measured:[], bindingVtables:{}, messageTypes:{},
  listenerVtables:{}, uniqueListeners:0};
const knownBindings = new Set(CONFIG.bindingVtables);
const seenListeners = new Set();

function utf8Size(text) {
  let n=0;
  for(const c of text){const p=c.codePointAt(0);n+=p<0x80?1:p<0x800?2:p<0x10000?3:4;}
  return n;
}
function readQString(address) {
  const d=address.readPointer();
  const n=d.add(4).readS32();
  if(n<0||n>4096) throw Error('Unexpected text length');
  const offset=Number(d.add(16).readS64());
  if(offset<0||offset>0x100000) throw Error('Unexpected QString layout');
  return d.add(offset).readUtf16String(n);
}
function withQString(text, use) {
  const bytes=Memory.allocUtf8String(text);
  const out=Memory.alloc(Process.pointerSize);out.writePointer(ptr0);
  fromUtf8(out,bytes,utf8Size(text));
  try { return use(out); } finally { destroyQString(out); }
}
function valid(view) {
  try {
    return view.threadId===guiThread && view.owner.readPointer().equals(wx.base.add(0x9175d78)) &&
      view.label.readPointer().equals(wx.base.add(0x91cfb08)) &&
      view.owner.add(0x508).readPointer().equals(view.label) &&
      view.label.add(0x410).readPointer().equals(view.owner) &&
      view.owner.add(0x250).readPointer().equals(view.binding) &&
      views.get(view.id)?.epoch===view.epoch;
  } catch(_) { return false; }
}
function dimensions(widget) {
  const out=Memory.alloc(4);const argv=Memory.alloc(Process.pointerSize);argv.writePointer(out);
  widgetMetaCall(widget,1,11,argv);const width=out.readS32();
  widgetMetaCall(widget,1,12,argv);const height=out.readS32();
  return {width,height};
}
function isVisible(widget) {
  const out=Memory.alloc(4);out.writeU32(0);
  const argv=Memory.alloc(Process.pointerSize);argv.writePointer(out);
  widgetMetaCall(widget,1,35,argv);return out.readU8()!==0;
}
function writeView(view,text) {
  if(!valid(view)){stats.staleSkipped++;return false;}
  applying++;
  try { withQString(text,q=>setText(view.label,q)); return true; }
  finally { applying--; }
}
const listener=Interceptor.attach(wx.base.add(0x1e80d40),{
  onEnter(args){
    if(applying||stopped)return;
    try {
      const label=args[0];
      if(!label.readPointer().equals(wx.base.add(0x91cfb08)))return;
      const owner=label.add(0x410).readPointer();
      if(owner.isNull()||!owner.readPointer().equals(wx.base.add(0x9175d78))||
         !owner.add(0x508).readPointer().equals(label))return;
      const id=owner.toString();
      modified.delete(id);views.delete(id);
      const original=readQString(args[1]);
      if(!original.trim())return;
      const binding=owner.add(0x250).readPointer();
      if(binding.isNull())return;
      const bindingVtable=binding.readPointer().sub(wx.base).toString();
      stats.bindingVtables[bindingVtable]=(stats.bindingVtables[bindingVtable]||0)+1;
      if(knownBindings.has(bindingVtable)){
        const type=binding.add(0x128).readU32();
        stats.messageTypes[type]=(stats.messageTypes[type]||0)+1;
        const modelListener=binding.add(0xd0).readPointer();
        if(!modelListener.isNull()){
          const listenerVtable=modelListener.readPointer();
          if(listenerVtable.compare(wx.base)>=0&&listenerVtable.compare(wx.base.add(wx.size))<0){
            const rva=listenerVtable.sub(wx.base).toString();
            stats.listenerVtables[rva]=(stats.listenerVtables[rva]||0)+1;
            seenListeners.add(modelListener.toString());stats.uniqueListeners=seenListeners.size;
          }
        }
      }
      views.set(id,{id,owner,label,binding,original,epoch:++epoch,threadId:this.threadId});
      while(views.size>100){
        const evict=Array.from(views.keys()).find(key=>!modified.has(key));
        if(evict===undefined)break;views.delete(evict);
      }
      stats.nativeBindings++;stats.validViews=views.size;
      send({event:'bindings',count:stats.nativeBindings});
    }catch(_){stats.errors++;}
  }
});
const rebindListener=Interceptor.attach(wx.base.add(0x1bc6490),{
  onEnter(args){if(applying||stopped)return;const id=args[0].toString();views.delete(id);modified.delete(id);}
});

// A registered private window message moves work onto the existing GUI thread.
const user=Process.getModuleByName('user32.dll');
const win=(name,ret,args)=>new NativeFunction(user.getExportByName(name),ret,args);
const getThread=win('GetWindowThreadProcessId','uint',['pointer','pointer']);
const getProc=win('GetWindowLongPtrW','pointer',['pointer','int']);
const register=win('RegisterWindowMessageW','uint',['pointer']);
const post=win('PostMessageW','bool',['pointer','uint','pointer','pointer']);
const hwnd=ptr(CONFIG.hwnd);const pidOut=Memory.alloc(4);
const guiThread=getThread(hwnd,pidOut);
if(pidOut.readU32()!==Process.id||Process.id!==CONFIG.pid)throw Error('Window ownership mismatch');
const message=register(Memory.allocUtf16String('Jev.LocalNativeFixture.'+CONFIG.nonce));
if(message<0xc000)throw Error('Private message registration failed');
const windowProc=getProc(hwnd,-4);
if(windowProc.isNull())throw Error('Window procedure unavailable');
const bridge=Interceptor.attach(windowProc,{
  onEnter(args){
    if(!args[0].equals(hwnd)||args[1].toUInt32()!==message)return;
    if(this.threadId!==guiThread){stats.errors++;return;}
    stats.guiThreadChecks++;
    const work=pending.shift();
    if(work){try{work();}catch(e){stats.errors++;send({event:'operation_error',message:String(e)});}}
  }
});
function enqueue(operation) {
  pending.push(operation);
  if(!post(hwnd,message,ptr0,ptr0)){pending.pop();throw Error('GUI scheduling failed');}
}
function safeMeasurements(view) {
  if(!valid(view))return {stale:true};
  return {label:dimensions(view.label),owner:dimensions(view.owner),
    animationActive:!view.owner.add(0x4d0).readPointer().isNull(),
    animationHeight:view.owner.add(0x4d8).readS32()};
}
function restore() {
  for(const [id,view] of modified){
    if(!valid(view)){stats.staleSkipped++;modified.delete(id);continue;}
    try{
      if(writeView(view,view.original)){stats.restored++;modified.delete(id);}
    }catch(_){stats.errors++;}
  }
  return modified.size;
}
rpc.exports={
  snapshot(){return stats;},
  checkQstring(){
    enqueue(()=>{
      const text='Jev 原生文字测试 ✓';
      withQString(text,q=>{if(readQString(q)!==text)throw Error('QString round-trip failed');});
      stats.qstringChecks++;send({event:'qstring_checked'});
    });return true;
  },
  applyFixture(){
    enqueue(()=>{
      if(stats.qstringChecks!==1)throw Error('QString allocation check must pass first');
      if(modified.size)throw Error('A fixture is already active');
      const candidates=Array.from(views.values()).reverse().filter(v=>valid(v)&&isVisible(v.owner));
      const view=candidates.find(v=>v.original.length>2&&v.original.length<300);
      if(!view){send({event:'no_view'});return;}
      const before=safeMeasurements(view);
      if(before.animationActive){send({event:'animation_busy'});return;}
      modified.set(view.id,view);
      if(writeView(view,view.original+'\n\nJev 本地显示测试\n原生布局校验 · 此内容未发送')){
        stats.applied++;
        stats.measured.push({stage:'before',...before});
        send({event:'fixture_applied',before});
        setTimeout(()=>enqueue(()=>{
          const after=safeMeasurements(view);stats.measured.push({stage:'after',...after});
          send({event:'fixture_measured',after});
        }),1000);
      }
    });return true;
  },
  restore(){enqueue(()=>{const unresolved=restore();send({event:'restored',count:stats.restored,unresolved});});return true;},
  stop(){
    enqueue(()=>{
      const unresolved=restore();
      if(unresolved){send({event:'stop_pending',stats,unresolved});return;}
      stopped=true;listener.detach();rebindListener.detach();send({event:'stopped',stats,unresolved});
    });return true;
  }
};
send({event:'ready',guiThread});
