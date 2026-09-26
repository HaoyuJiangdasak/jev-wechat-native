// WeChat-version-adaptive tail following. Caller pins the image/hash and invokes
// capture and restore on the GUI thread, with its own current
// owner/conversation generation. No hooks, timers, UI messages, or Frida
// initialization are created here.
//
// Addresses are taken from the host's resolved anchor set for the installed
// build. The literals below are only a fallback for the offline unit tests,
// which load this file without a host CONFIG.
const NATIVE_FOLLOW_TAIL_RVAS=Object.freeze({
  metaCast:(typeof CONFIG!=='undefined'&&CONFIG.anchors)?CONFIG.anchors.functions.metaCast.rva:0x28c390,
  verticalScrollBar:(typeof CONFIG!=='undefined'&&CONFIG.anchors)?CONFIG.anchors.functions.verticalScrollBar.rva:0xce87b0,
  sliderMetaCall:(typeof CONFIG!=='undefined'&&CONFIG.anchors)?CONFIG.anchors.functions.sliderMetaCall.rva:0x20b4600,
  setValue:(typeof CONFIG!=='undefined'&&CONFIG.anchors)?CONFIG.anchors.functions.setValue.rva:0x20b34a0,
  // The observed chat ancestor is RecyclerListView, not its XRecycler subclass.
  recyclerMeta:(typeof CONFIG!=='undefined'&&CONFIG.anchors)?CONFIG.anchors.metaobjects.recyclerMeta:0x8e9c418,
  scrollAreaMeta:(typeof CONFIG!=='undefined'&&CONFIG.anchors)?CONFIG.anchors.metaobjects.scrollAreaMeta:0x8f1e978,
  scrollBarMeta:(typeof CONFIG!=='undefined'&&CONFIG.anchors)?CONFIG.anchors.metaobjects.scrollBarMeta:0x91cd6b8,
  moduleSize:(typeof CONFIG!=='undefined'&&CONFIG.anchors)?CONFIG.anchors.module_size:0xc0ac000
});
const NATIVE_FOLLOW_TAIL_FUNCTION_RVAS=Object.freeze([
  NATIVE_FOLLOW_TAIL_RVAS.metaCast,NATIVE_FOLLOW_TAIL_RVAS.verticalScrollBar,
  NATIVE_FOLLOW_TAIL_RVAS.sliderMetaCall,NATIVE_FOLLOW_TAIL_RVAS.setValue
]);
const NATIVE_FOLLOW_TAIL_DIAGNOSTIC_STAGES=Object.freeze({
  0:'not_started',1:'reading_widget_chain',2:'reading_vertical_bar',3:'reading_slider_state',
  10:'not_live_widget',11:'parent_cycle',12:'window_reached_without_recycler',13:'parent_depth_limit',
  20:'null_vertical_bar',21:'not_live_bar',22:'not_qscrollbar',23:'not_qabstractscrollarea',
  100:'eligible_at_bottom',101:'not_at_bottom',102:'slider_down',103:'invalid_slider_range',104:'not_vertical'
});
// Stable numbers only are published to the host's metadata diagnostics.
const NATIVE_FOLLOW_TAIL_GUARD_REASONS=Object.freeze({
  captured:0,invalid_guard:1,cancelled:2,superseded:3,invalid_context:4,
  scope_changed:5,user_input:6,clock_changed:7,expired:8,throttled:9,
  different_owner:10,unavailable_scrollbar:11,different_list_or_scrollbar:12,
  invalid_slider_state:13,slider_down:14,range_changed:15,position_changed:16,
  step_limit:17,write_limit:18,state_changed_during_write:19,
  position_changed_during_write:20,native_error:21,followed_tail:100,watching_range:101
});

function nativeTailStateValid(state) {
  return !!state && [state.minimum,state.maximum,state.value].every(Number.isSafeInteger) &&
    state.maximum>=state.minimum && state.value>=state.minimum && state.value<=state.maximum &&
    state.orientation===2 && typeof state.down==='boolean';
}
function nativeTailCaptureEligible(state) {
  return nativeTailStateValid(state) && !state.down && state.value>=state.maximum-2;
}
function nativeTailRestoreDecision(token,state) {
  if(!token || !Number.isSafeInteger(token.startValue))return {follow:false,reason:'invalid_token'};
  if(!nativeTailStateValid(state))return {follow:false,reason:'invalid_slider_state'};
  if(state.down)return {follow:false,reason:'slider_down'};
  if(state.value===state.maximum)return {follow:true,changed:false,reason:'already_at_bottom'};
  if(state.value!==token.startValue)return {follow:false,reason:'position_changed'};
  return {follow:true,changed:true,reason:'followed_tail',value:state.maximum};
}

function createNativeFollowTail({base,native,Memory,pointerSize=8,now=()=>Date.now()}) {
  if(pointerSize!==8)throw Error('NativeFollowTailRequiresWin64');
  const r=NATIVE_FOLLOW_TAIL_RVAS;
  const cast=native(r.metaCast,'pointer',['pointer','pointer']);
  const getVertical=native(r.verticalScrollBar,'pointer',['pointer']);
  const sliderMeta=native(r.sliderMetaCall,'void',['pointer','int','int','pointer']);
  const setValue=native(r.setValue,'void',['pointer','int']);
  const issued=new WeakSet(),consumed=new WeakSet();
  const guardStates=new WeakMap(),activeGuards=new Set();
  function liveWidget(widget) {
    if(!widget || widget.isNull())return null;
    const d=widget.add(8).readPointer();
    if(d.isNull())return null;
    const flags=d.add(0x20).readU8();
    return (flags&1) && !(flags&4) ? d : null;
  }
  function vtableRva(widget) {
    try {
      const vt=widget.readPointer();
      // Bound by the resolved PE SizeOfImage so a vtable is only ever reported
      // for a pointer that really lands inside this module. Never emit a
      // pointer outside it, or any heap/absolute object address.
      if(vt.compare(base)<0 || vt.compare(base.add(NATIVE_FOLLOW_TAIL_RVAS.moduleSize))>=0)return null;
      return vt.sub(base).toString();
    }catch(_){return null;}
  }
  function locate(owner,diagnostic=null) {
    function stage(n){if(diagnostic)diagnostic.stageNumber=n;}
    let current=owner;const seen=new Set();
    for(let i=0;i<64;i++) {
      stage(1);
      const d=liveWidget(current);if(!d){stage(10);return null;}
      const id=current.toString();if(seen.has(id)){stage(11);return null;}seen.add(id);
      if(diagnostic)diagnostic.chainVtableRvas.push(vtableRva(current));
      const area=cast(base.add(r.recyclerMeta),current);
      if(!area.isNull()) {
        if(diagnostic)diagnostic.areaVtableRva=vtableRva(area);
        stage(2);
        const scrollArea=cast(base.add(r.scrollAreaMeta),area);
        if(scrollArea.isNull()){stage(23);return null;}
        const bar=getVertical(scrollArea);
        if(!bar || bar.isNull()){stage(20);return null;}
        if(diagnostic)diagnostic.barVtableRva=vtableRva(bar);
        if(!liveWidget(bar)){stage(21);return null;}
        if(cast(base.add(r.scrollBarMeta),bar).isNull()){stage(22);return null;}
        return {area,bar,areaId:area.toString(),barId:bar.toString()};
      }
      const data=current.add(0x28).readPointer();
      if(data.isNull()){stage(10);return null;}
      if(data.add(0xc).readU32()&1){stage(12);return null;}
      current=d.add(0x10).readPointer();
    }
    stage(13);
    return null;
  }
  function stateOf(bar) {
    const out=Memory.alloc(4),argv=Memory.alloc(pointerSize);argv.writePointer(out);
    function read(id,bool=false){sliderMeta(bar,1,id,argv);return bool?out.readU8()!==0:out.readS32();}
    return {minimum:read(0),maximum:read(1),value:read(4),orientation:read(7),down:read(10,true)};
  }
  function capture(owner) {
    try {
      const found=locate(owner);if(!found)return null;
      const state=stateOf(found.bar);if(!nativeTailCaptureEligible(state))return null;
      const token=Object.freeze({...found,ownerId:owner.toString(),startValue:state.value,
        bottom:state.maximum,minimum:state.minimum});
      issued.add(token);return token;
    }catch(_){return null;}
  }
  function diagnose(owner) {
    const diagnostic={stageNumber:0,chainVtableRvas:[],areaVtableRva:null,barVtableRva:null,
      sliderState:{min:null,max:null,value:null,orientation:null,down:null}};
    try {
      const found=locate(owner,diagnostic);if(!found)return diagnostic;
      diagnostic.stageNumber=3;
      const state=stateOf(found.bar);
      diagnostic.sliderState={min:state.minimum,max:state.maximum,value:state.value,
        orientation:state.orientation,down:state.down};
      if(state.orientation!==2)diagnostic.stageNumber=104;
      else if(!nativeTailStateValid(state))diagnostic.stageNumber=103;
      else if(state.down)diagnostic.stageNumber=102;
      else diagnostic.stageNumber=nativeTailCaptureEligible(state)?100:101;
    }catch(_){/* Fixed numeric stage identifies the failed read; no exception text. */}
    return diagnostic;
  }
  function restore(token,owner) {
    if(!token || typeof token!=='object' || !issued.has(token))
      return {restored:false,changed:false,reason:'invalid_token'};
    if(consumed.has(token))return {restored:false,changed:false,reason:'token_consumed'};
    consumed.add(token);
    try {
      if(!owner || owner.toString()!==token.ownerId)
        return {restored:false,changed:false,reason:'different_owner'};
      const found=locate(owner);
      if(!found)return {restored:false,changed:false,reason:'unavailable_scrollbar'};
      if(found.areaId!==token.areaId || found.barId!==token.barId)
        return {restored:false,changed:false,reason:'different_list_or_scrollbar'};
      const decision=nativeTailRestoreDecision(token,stateOf(found.bar));
      if(!decision.follow)return {restored:false,changed:false,reason:decision.reason};
      if(decision.changed)setValue(found.bar,decision.value);
      return {restored:true,changed:decision.changed,reason:decision.reason};
    }catch(_){return {restored:false,changed:false,reason:'native_error'};}
  }
  // Guard callbacks are supplied by the adapter. The guard owns no timer and
  // expires 2 s after begin even if the first callback arrives late. The input
  // epoch must reflect actual input, not slider valueChanged (our writes emit
  // that too). Sampling the value alone cannot detect a user returning to the
  // same position between callbacks.
  function guardContextValid(context) {
    return !!context && ((typeof context.scope==='string'&&context.scope.length>0) ||
      (typeof context.scope==='number'&&Number.isSafeInteger(context.scope))) &&
      Number.isSafeInteger(context.inputEpoch) && context.inputEpoch>=0;
  }
  function guardDiagnostic(handle,reason=null) {
    const g=handle&&typeof handle==='object'?guardStates.get(handle):null;
    const number=value=>Number.isFinite(value)?value:null;
    return {
      startValue:number(g?.startValue),startMax:number(g?.startMaximum),
      lastValue:number(g?.lastValue),lastMax:number(g?.lastMaximum),
      seenValue:number(g?.seen?.value),seenMax:number(g?.seen?.maximum),
      seenMin:number(g?.seen?.minimum),seenDown:g?.seen?Number(g.seen.down):null,
      afterValue:number(g?.after?.value),afterMax:number(g?.after?.maximum),
      elapsedMs:g?Math.max(0,g.lastTime-g.started):null,
      steps:number(g?.steps),writes:number(g?.writes),inputChanged:g?Number(g.inputChanged):null,
      reasonNumber:NATIVE_FOLLOW_TAIL_GUARD_REASONS[reason||(g?(g.reason||g.lastReason||'captured'):'invalid_guard')]
    };
  }
  function guardResult(handle,result) {
    const g=guardStates.get(handle);if(g)g.lastReason=result.reason;
    return {...result,diagnostics:guardDiagnostic(handle,result.reason)};
  }
  function endGuard(handle,reason) {
    const g=guardStates.get(handle);
    if(g){g.active=false;g.reason=reason;activeGuards.delete(handle);}
    return guardResult(handle,{active:false,restored:false,changed:false,reason,nextDelayMs:0});
  }
  function cancel(handle) {
    if(!handle || !guardStates.has(handle))return endGuard(null,'invalid_guard');
    return endGuard(handle,'cancelled');
  }
  function cancelAll() {
    const count=activeGuards.size;
    for(const handle of activeGuards)endGuard(handle,'cancelled');
    return count;
  }
  function begin(owner,context) {
    if(!guardContextValid(context))return null;
    try {
      const started=now();if(!Number.isFinite(started))return null;
      const found=locate(owner);if(!found)return null;
      const state=stateOf(found.bar);if(!nativeTailCaptureEligible(state))return null;
      // At most one active guard per native list, even if two results arrive.
      for(const previous of activeGuards) {
        const p=guardStates.get(previous);
        if(p.areaId===found.areaId)endGuard(previous,'superseded');
      }
      const handle=Object.freeze({});
      guardStates.set(handle,{...found,ownerId:owner.toString(),scope:context.scope,
        inputEpoch:context.inputEpoch,started,deadline:started+2000,lastTime:started,
        lastStep:-Infinity,lastValue:state.value,lastMaximum:state.maximum,
        startValue:state.value,startMaximum:state.maximum,seen:{...state},after:null,
        minimum:state.minimum,steps:0,writes:0,active:true,reason:null,inputChanged:false});
      activeGuards.add(handle);return handle;
    }catch(_){return null;}
  }
  function step(handle,owner,context) {
    if(!handle || typeof handle!=='object' || !guardStates.has(handle))
      return endGuard(null,'invalid_guard');
    const g=guardStates.get(handle);
    if(!g.active)return endGuard(handle,g.reason||'cancelled');
    if(!guardContextValid(context))return endGuard(handle,'invalid_context');
    if(context.scope!==g.scope)return endGuard(handle,'scope_changed');
    if(context.inputEpoch!==g.inputEpoch){g.inputChanged=true;return endGuard(handle,'user_input');}
    try {
      const time=now();
      if(!Number.isFinite(time)||time<g.lastTime)return endGuard(handle,'clock_changed');
      g.lastTime=time;
      if(time>=g.deadline)return endGuard(handle,'expired');
      if(time-g.lastStep<80)return guardResult(handle,{active:true,restored:false,changed:false,
        reason:'throttled',nextDelayMs:Math.min(100,g.deadline-time)});
      if(!owner || owner.toString()!==g.ownerId)return endGuard(handle,'different_owner');
      const found=locate(owner);
      if(!found)return endGuard(handle,'unavailable_scrollbar');
      if(found.areaId!==g.areaId||found.barId!==g.barId)return endGuard(handle,'different_list_or_scrollbar');
      const state=stateOf(found.bar);
      g.seen={...state};g.after=null;
      if(!nativeTailStateValid(state))return endGuard(handle,'invalid_slider_state');
      if(state.down)return endGuard(handle,'slider_down');
      if(state.minimum!==g.minimum||state.maximum<g.lastMaximum)return endGuard(handle,'range_changed');
      // Observed MMUI layout rounds a requested 4379 to 4378 while its range
      // grows 4379 -> 4414. Permit only the existing 2 px tail tolerance;
      // input epoch, dragging, range and identity guards still take precedence.
      if(Math.abs(state.value-g.lastValue)>2&&state.value!==state.maximum)
        return endGuard(handle,'position_changed');
      if(g.steps>=25)return endGuard(handle,'step_limit');
      g.steps++;g.lastStep=time;
      const changed=state.value!==state.maximum && (g.steps===1||state.maximum>g.lastMaximum);
      if(changed) {
        if(g.writes>=20)return endGuard(handle,'write_limit');
        // A late callback never causes a native write beyond the hard deadline.
        if(now()>=g.deadline)return endGuard(handle,'expired');
        g.writes++;setValue(found.bar,state.maximum);
        if(!g.active)return endGuard(handle,g.reason||'cancelled');
        const after=stateOf(found.bar);
        g.after={...after};
        if(!nativeTailStateValid(after)||after.down||after.minimum!==g.minimum||after.maximum<state.maximum)
          return endGuard(handle,'state_changed_during_write');
        if(Math.abs(after.value-state.maximum)>2&&after.value!==after.maximum)
          return endGuard(handle,'position_changed_during_write');
        g.lastValue=after.value;
        // If setValue itself triggers another layout/range increase, leave
        // that increase for a later callback; never loop native writes here.
      } else g.lastValue=state.value;
      g.lastMaximum=state.maximum;
      return guardResult(handle,{active:true,restored:true,changed,reason:changed?'followed_tail':'watching_range',
        nextDelayMs:Math.min(100,g.deadline-time)});
    }catch(_){return endGuard(handle,'native_error');}
  }
  return {capture,restore,diagnose,begin,step,cancel,cancelAll,guardDiagnostic};
}

if(typeof module!=='undefined' && module.exports)module.exports={
  NATIVE_FOLLOW_TAIL_RVAS,NATIVE_FOLLOW_TAIL_FUNCTION_RVAS,
  NATIVE_FOLLOW_TAIL_DIAGNOSTIC_STAGES,NATIVE_FOLLOW_TAIL_GUARD_REASONS,
  nativeTailStateValid,nativeTailCaptureEligible,nativeTailRestoreDecision,createNativeFollowTail
};
