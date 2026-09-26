// Weixin.dll 4.1.15.11 only. Caller pins the image/hash and invokes capture and
// restore on the GUI thread, with its own current owner/conversation generation.
// No hooks, timers, UI messages, or Frida initialization are created here.
const NATIVE_FOLLOW_TAIL_RVAS=Object.freeze({
  metaCast:0x28c390,verticalScrollBar:0xce87b0,
  sliderMetaCall:0x20b4600,setValue:0x20b34a0,
  // The observed chat ancestor is RecyclerListView, not its XRecycler subclass.
  recyclerMeta:0x8e9c418,scrollAreaMeta:0x8f1e978,scrollBarMeta:0x91cd6b8
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

function createNativeFollowTail({base,native,Memory,pointerSize=8}) {
  if(pointerSize!==8)throw Error('NativeFollowTailRequiresWin64');
  const r=NATIVE_FOLLOW_TAIL_RVAS;
  const cast=native(r.metaCast,'pointer',['pointer','pointer']);
  const getVertical=native(r.verticalScrollBar,'pointer',['pointer']);
  const sliderMeta=native(r.sliderMetaCall,'void',['pointer','int','int','pointer']);
  const setValue=native(r.setValue,'void',['pointer','int']);
  const issued=new WeakSet(),consumed=new WeakSet();
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
      // This is the pinned PE SizeOfImage, not the file size. Never emit a
      // pointer outside this module, or any heap/absolute object address.
      if(vt.compare(base)<0 || vt.compare(base.add(0xc0ac000))>=0)return null;
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
  return {capture,restore,diagnose};
}

if(typeof module!=='undefined' && module.exports)module.exports={
  NATIVE_FOLLOW_TAIL_RVAS,NATIVE_FOLLOW_TAIL_FUNCTION_RVAS,
  NATIVE_FOLLOW_TAIL_DIAGNOSTIC_STAGES,
  nativeTailStateValid,nativeTailCaptureEligible,nativeTailRestoreDecision,createNativeFollowTail
};
