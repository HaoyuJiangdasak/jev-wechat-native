// Version-locked local annotations. Message text never enters logs or the database.
'use strict';
if(Process.arch!=='x64'||Process.pointerSize!==8||Process.id!==CONFIG.pid)throw Error('TargetMismatch');
const wx=Process.getModuleByName('Weixin.dll');
if(wx.path.toLowerCase()!==CONFIG.dllPath.toLowerCase())throw Error('ModuleMismatch');
for(const check of CONFIG.functions){
  const actual=new Uint8Array(wx.base.add(check.rva).readByteArray(check.bytes.length));
  if(!Array.from(actual).every((v,i)=>v===check.bytes[i]))throw Error('CodeMismatch');
}
const zero=ptr(0);
const native=(rva,ret,args)=>new NativeFunction(wx.base.add(rva),ret,args,'win64');
const fromUtf8=native(0x27f80,'pointer',['pointer','pointer','int']);
const destroyQString=native(0x14e0,'void',['pointer']);
const setText=native(0x1e80d40,'void',['pointer','pointer']);
const widgetMetaCall=native(0x5bbfc0,'void',['pointer','int','int','pointer']);
const isSelf=native(0x5c41810,'bool',['pointer']);
const user=Process.getModuleByName('user32.dll');
const win=(name,ret,args)=>new NativeFunction(user.getExportByName(name),ret,args,'win64');
const getThread=win('GetWindowThreadProcessId','uint',['pointer','pointer']);
const getProc=win('GetWindowLongPtrW','pointer',['pointer','int']);
const register=win('RegisterWindowMessageW','uint',['pointer']);
const post=win('PostMessageW','bool',['pointer','uint','pointer','pointer']);
const isIconic=win('IsIconic','bool',['pointer']);
const hwnd=ptr(CONFIG.hwnd),pidOut=Memory.alloc(4);
const guiThread=getThread(hwnd,pidOut);
if(!guiThread||pidOut.readU32()!==Process.id)throw Error('WindowMismatch');
const message=register(Memory.allocUtf16String('Jev.NativeAnnotations.'+CONFIG.nonce));
const token=ptr('0x'+CONFIG.nonce.slice(0,12));
const wndProc=getProc(hwnd,-4);
if(message<0xc000||wndProc.isNull())throw Error('GuiBridgeUnavailable');
const pending=[],views=new Map(),modified=new Map();
const ledgers=new Map();
let messageSequence=0;
let applying=0,epoch=0,stopped=false,stopping=false,pollQueued=false;
let lastBindingAt=0,lastHeartbeat=Date.now(),lastSnapshot='',currentConversation=null;
let lastSeenConversation=null;
let scrollInputEpoch=0;
const stats={bindings:0,applied:0,restored:0,staleSkipped:0,errors:0,visibleViews:0,chatEpoch:0,
  identityMatches:0,identityRejected:0,remoteViews:0,selfViews:0,conversationChanges:0,
  tailCaptured:0,tailRestored:0,tailChanged:0,tailPositionChanged:0,tailFailed:0};

function readQString(address){
  const d=address.readPointer(),n=d.add(4).readS32();
  if(n<0||n>4096)throw Error('InvalidQString');
  const offset=Number(d.add(16).readS64());
  if(offset<0||offset>0x100000)throw Error('InvalidQString');
  return d.add(offset).readUtf16String(n);
}
function utf8Size(text){let n=0;for(const c of text){const p=c.codePointAt(0);n+=p<128?1:p<2048?2:p<65536?3:4;}return n;}
function withQString(text,callback){
  const data=Memory.allocUtf8String(text),out=Memory.alloc(8);out.writePointer(zero);
  fromUtf8(out,data,utf8Size(text));
  try{return callback(out);}finally{destroyQString(out);}
}
function readString(object,max=1024){
  const size=Number(object.add(16).readU64()),capacity=Number(object.add(24).readU64());
  if(!Number.isSafeInteger(size)||size<0||size>max||size>capacity||capacity>0x100000)throw Error('InvalidString');
  if(!size)return '';
  return (capacity<16?object:object.readPointer()).readUtf8String(size);
}
function property(widget,id,bytes=4){
  const out=Memory.alloc(bytes),args=Memory.alloc(8);out.writeByteArray(new Uint8Array(bytes));args.writePointer(out);
  widgetMetaCall(widget,1,id,args);return out;
}
function visible(widget){return property(widget,35).readU8()!==0;}
const geometry=createNativeGeometry({widgetMetaCall,Memory,pointerSize:8});
const followTail=createNativeFollowTail({base:wx.base,native,Memory,pointerSize:8});
function recordTailGuard(guard){
  const diagnostic=followTail.guardDiagnostic(guard);
  for(const [key,value] of Object.entries(diagnostic||{})){
    if(Number.isSafeInteger(value))stats['tailGuard'+key[0].toUpperCase()+key.slice(1)]=value;
  }
}
function continueTail(guard,view,generation,conversation,chatEpoch){
  if(!guard)return;
  setTimeout(()=>enqueue(()=>{
    if(stopping||stopped||isIconic(hwnd)||!valid(view)||view.generation!==generation||
       currentConversation!==conversation||stats.chatEpoch!==chatEpoch||
       conversationOf(view.binding)!==conversation){followTail.cancel(guard);return;}
    const result=followTail.step(guard,view.owner,{scope:chatEpoch,inputEpoch:scrollInputEpoch});
    recordTailGuard(guard);
    if(result.restored)stats.tailRestored++;
    if(result.changed)stats.tailChanged++;
    if(result.reason==='position_changed'||result.reason==='user_input')stats.tailPositionChanged++;
    if(result.reason==='native_error')stats.tailFailed++;
    if(result.active)continueTail(guard,view,generation,conversation,chatEpoch);
  }),100);
}
function visibleGeometry(widget){
  const result=geometry.inspect(widget);
  return result.visible?{x:result.rect[0],y:result.rect[1],bottom:result.rect[3],
    clipped:result.clipped,root:result.rootId}:null;
}
// Conversation identity must come from the verified model, not a display name.
function conversationOf(binding){
  try{
    if(!binding.readPointer().equals(wx.base.add(0x956b278)))return null;
    const uiMessage=binding.add(0x120),listener=binding.add(0xd0).readPointer();
    if(!uiMessage.readPointer().equals(wx.base.add(0x8d9c978))||listener.isNull()||
       !listener.readPointer().equals(wx.base.add(0x95884e8)))return null;
    const messagePeer=readString(uiMessage.add(0x70),256),modelPeer=readString(listener.add(0xa0),256);
    return messagePeer&&messagePeer===modelPeer?messagePeer:null;
  }catch(_){return null;}
}
function identityOf(binding,original,peer){
  const msg=binding.add(0x120),seconds=msg.add(0xd0).readU32(),sequence=msg.add(0x94).readU32();
  if(seconds<1293811200||seconds>4102444800||!peer)return null;
  let logicalId;
  if(sequence)logicalId=peer+'_'+seconds+'_'+sequence;
  else {const fallback=readString(msg.add(0x98),256);if(!fallback)return null;logicalId=peer+'_'+fallback;}
  return {logicalId,time:seconds};
}
function remember(view,peer){
  const identity=identityOf(view.binding,view.original,peer);
  if(!identity)return;
  view.logicalId=identity.logicalId;
  view.peer=peer;
  let ledger=ledgers.get(peer);
  if(!ledger){ledger=new Map();ledgers.set(peer,ledger);}
  const old=ledger.get(identity.logicalId);
  ledger.set(identity.logicalId,{logicalId:identity.logicalId,time:identity.time,
    sequence:old?old.sequence:++messageSequence,who:isSelf(view.binding)?'me':'her',text:view.original,
    id:view.id,generation:view.generation});
  const ordered=Array.from(ledger.values()).sort((a,b)=>a.time-b.time||a.sequence-b.sequence);
  while(ordered.length>64){ledger.delete(ordered.shift().logicalId);}
  while(ledgers.size>16){ledgers.delete(ledgers.keys().next().value);}
}

function valid(view){
  try{return view.threadId===guiThread&&views.get(view.id)===view&&
    view.owner.readPointer().equals(wx.base.add(0x9175d78))&&
    view.label.readPointer().equals(wx.base.add(0x91cfb08))&&
    view.owner.add(0x508).readPointer().equals(view.label)&&
    view.label.add(0x410).readPointer().equals(view.owner)&&
    view.owner.add(0x250).readPointer().equals(view.binding)&&
    view.binding.readPointer().equals(wx.base.add(0x956b278))&&
    view.peer&&conversationOf(view.binding)===view.peer&&
    identityOf(view.binding,view.original,view.peer)?.logicalId===view.logicalId;
  }catch(_){return false;}
}
function writeView(view,text){
  if(!valid(view)){stats.staleSkipped++;return false;}
  applying++;
  try{withQString(text,q=>setText(view.label,q));return true;}finally{applying--;}
}
function restoreOne(id,view){
  if(!valid(view)){stats.staleSkipped++;modified.delete(id);return;}
  if(writeView(view,view.original)){modified.delete(id);stats.restored++;view.annotation=null;}
}
function restoreAll(){
  for(const [id,view] of modified){try{restoreOne(id,view);}catch(_){stats.errors++;}}
  return modified.size;
}
function invalidate(owner){
  const id=owner.toString();views.delete(id);modified.delete(id);lastBindingAt=Date.now();
}
const textListener=Interceptor.attach(wx.base.add(0x1e80d40),{
  onEnter(args){
    if(applying||stopped||this.threadId!==guiThread)return;
    try{
      const label=args[0];
      if(!label.readPointer().equals(wx.base.add(0x91cfb08)))return;
      const owner=label.add(0x410).readPointer();
      if(owner.isNull()||!owner.readPointer().equals(wx.base.add(0x9175d78))||!owner.add(0x508).readPointer().equals(label))return;
      const binding=owner.add(0x250).readPointer();
      const original=readQString(args[1]),old=views.get(owner.toString());
      if(old&&old.annotation&&old.binding.equals(binding)&&valid(old)&&
         original===old.original+'\n\n'+old.annotation)return;
      invalidate(owner);
      if(binding.isNull()||!binding.readPointer().equals(wx.base.add(0x956b278))||binding.add(0x128).readU32()!==1)return;
      if(!original.trim()||original.length>3000||!readString(binding.add(0x130),256))return;
      const peer=conversationOf(binding);
      if(!peer||!identityOf(binding,original,peer)){stats.identityRejected++;return;}
      stats.identityMatches++;
      const id=owner.toString();
      const view={id,owner,label,binding,original,generation:++epoch,threadId:this.threadId,annotation:null};
      views.set(id,view);
      if(peer)remember(view,peer);
      stats.bindings++;
      while(views.size>128){const id=Array.from(views.keys()).find(k=>!modified.has(k));if(id===undefined)break;views.delete(id);}
    }catch(_){stats.errors++;}
  }
});
const rebindListener=Interceptor.attach(wx.base.add(0x1bc6490),{
  onEnter(args){
    if(applying||stopped)return;
    try{
      const old=views.get(args[0].toString());
      if(old&&old.annotation&&valid(old)&&readQString(args[1])===old.original+'\n\n'+old.annotation)return;
    }catch(_){}
    invalidate(args[0]);
  }
});
const bridge=Interceptor.attach(wndProc,{
  onEnter(args){
    if(args[0].equals(hwnd)){
      const inputMessage=args[1].toUInt32();
      if([0x100,0x104,0x201,0x204,0x207,0x20a,0x20b,0x20e,0x115,0x240,0x246].includes(inputMessage)){
        scrollInputEpoch++;followTail.cancelAll();
      }
    }
    if(!args[0].equals(hwnd)||args[1].toUInt32()!==message||!args[3].equals(token))return;
    if(this.threadId!==guiThread){stats.errors++;return;}
    const task=pending.shift();
    if(task){try{task();}catch(_){stats.errors++;send({event:'operation_error',errorType:'NativeOperationError'});}}
  }
});
function enqueue(task){
  if(stopped||pending.length>=12)return false;
  pending.push(task);
  if(!post(hwnd,message,zero,token)){pending.pop();stats.errors++;return false;}return true;
}
function emitSnapshot(conversation,messages){
  const signature=JSON.stringify([conversation,messages.map(m=>[m.id,m.generation,m.targetEligible,m.logicalId])]);
  if(signature===lastSnapshot)return;
  lastSnapshot=signature;
  send({event:'snapshot',snapshot:{conversation,messages}});
}
function collect(){
  if(stopping||stopped)return;
  if(isIconic(hwnd)){emitSnapshot(null,[]);return;}
  if(Date.now()-lastBindingAt<650)return;
  const candidates=[];
  for(const [id,view] of views){
    if(!valid(view)){views.delete(id);modified.delete(id);continue;}
    if(!visible(view.owner))continue;
    const rect=visibleGeometry(view.owner);
    if(!rect)continue;
    const conversation=conversationOf(view.binding);
    if(!conversation)continue;
    const self=isSelf(view.binding);
    candidates.push({view,rect,conversation,self});
  }
  stats.visibleViews=candidates.length;
  const conversations=new Set(candidates.map(c=>c.conversation));
  if(conversations.size!==1){currentConversation=null;emitSnapshot(null,[]);return;}
  const conversation=candidates[0].conversation;
  if(conversation!==currentConversation){
    followTail.cancelAll();
    if(lastSeenConversation!==null&&lastSeenConversation!==conversation)stats.conversationChanges++;
    lastSeenConversation=conversation;
    currentConversation=conversation;stats.chatEpoch++;
  }
  stats.remoteViews=candidates.filter(c=>!c.self).length;
  stats.selfViews=candidates.filter(c=>c.self).length;
  if(CONFIG.diagnostics){
    const d=followTail.diagnose(candidates[0].view.owner);
    stats.tailStage=d.stageNumber;
    stats.tailArea=d.areaVtableRva?parseInt(d.areaVtableRva,16):0;
    stats.tailBar=d.barVtableRva?parseInt(d.barVtableRva,16):0;
    d.chainVtableRvas.slice(0,24).forEach((rva,i)=>{stats['tailAncestor'+i]=rva?parseInt(rva,16):0;});
    if(d.sliderState){stats.tailMin=d.sliderState.min;stats.tailMax=d.sliderState.max;stats.tailValue=d.sliderState.value;stats.tailOrientation=d.sliderState.orientation;stats.tailDown=d.sliderState.down?1:0;}
  }
  candidates.sort((a,b)=>a.rect.y-b.rect.y);
  // Keep original messages across the layout changes introduced by annotations.
  // Native view pointers may change; logical context and targets must not.
  const ledger=ledgers.get(conversation);
  const selected=ledger?Array.from(ledger.values()).sort((a,b)=>a.time-b.time||a.sequence-b.sequence).slice(-24):[];
  const targets=new Set(selected.filter(m=>m.who==='her').slice(-3).map(m=>m.logicalId));
  // Clipping or temporary hiding within this chat must not remove an applied
  // annotation: the same binding may reappear without a new setter event.
  for(const [id,view] of modified){
    if(conversationOf(view.binding)!==conversation)restoreOne(id,view);
  }
  emitSnapshot(conversation,selected.map(m=>{
    const view=views.get(m.id);
    return {id:m.id,generation:m.generation,logicalId:m.logicalId,who:m.who,text:m.text,
      targetEligible:targets.has(m.logicalId)&&!!view&&valid(view)&&view.generation===m.generation};
  }));
}
function finish(){
  stopping=true;
  followTail.cancelAll();
  const unresolved=restoreAll();
  if(unresolved){send({event:'stop_pending',stats:{...stats},unresolved});return;}
  stopped=true;clearInterval(timer);textListener.detach();rebindListener.detach();
  pending.length=0;pollQueued=false;
  setImmediate(()=>bridge.detach());
  send({event:'stopped',stats:{...stats},unresolved:0});
}
const timer=setInterval(()=>{
  if(stopped||pollQueued)return;
  pollQueued=true;
  if(!enqueue(()=>{
    pollQueued=false;
    if(Date.now()-lastHeartbeat>10000||stopping)finish();else collect();
    send({event:'stats',stats:{...stats}});
  }))pollQueued=false;
},500);
rpc.exports={
  heartbeat(){lastHeartbeat=Date.now();return !stopped;},
  annotate(id,generation,text,deliveryId){
    if(stopping||stopped||typeof text!=='string'||text.length>420||!text.startsWith('Jev｜'))return false;
    if(deliveryId!==undefined&&(typeof deliveryId!=='string'||!deliveryId||deliveryId.length>120))return false;
    const requestedConversation=currentConversation,requestedChatEpoch=stats.chatEpoch;
    if(!requestedConversation)return false;
    return enqueue(()=>{
      let applied=false;
      try{
      if(stopping||stopped||Date.now()-lastBindingAt<650)return;
      const view=views.get(id);
      if(!view||view.generation!==generation||!valid(view)||!visible(view.owner)||!visibleGeometry(view.owner)||
         currentConversation!==requestedConversation||stats.chatEpoch!==requestedChatEpoch||
         conversationOf(view.binding)!==requestedConversation||isSelf(view.binding)){stats.staleSkipped++;return;}
      if(view.annotation===text){applied=true;return;}
      const tail=followTail.begin(view.owner,{scope:requestedChatEpoch,inputEpoch:scrollInputEpoch});
      if(tail){stats.tailCaptured++;recordTailGuard(tail);}
      modified.set(id,view);
      if(writeView(view,view.original+'\n\n'+text)){
        view.annotation=text;stats.applied++;applied=true;
        continueTail(tail,view,generation,requestedConversation,requestedChatEpoch);
      }else if(tail){
        followTail.cancel(tail);
      }
      }finally{
        if(deliveryId!==undefined)send({event:'annotation_result',deliveryId,applied});
      }
    });
  },
  stop(){stopping=true;return enqueue(finish);},
  snapshot(){return {...stats};}
};
Interceptor.flush();
enqueue(()=>{withQString('Jev 原生中文 ✓',q=>{if(readQString(q)!=='Jev 原生中文 ✓')throw Error('StringCheckFailed');});send({event:'ready',guiThread});});
