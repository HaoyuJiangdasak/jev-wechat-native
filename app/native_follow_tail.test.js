'use strict';
const assert=require('node:assert/strict');
const {NATIVE_FOLLOW_TAIL_RVAS:R,NATIVE_FOLLOW_TAIL_FUNCTION_RVAS,
 nativeTailCaptureEligible,nativeTailRestoreDecision,createNativeFollowTail}=require('./native_follow_tail.js');
let tests=0;
function test(name,run){run();tests++;process.stdout.write('PASS '+name+'\n');}
const state=(value=100,maximum=100,extra={})=>({minimum:0,maximum,value,orientation:2,down:false,...extra});
test('capture threshold is exactly the last two units',()=>{
 assert.equal(nativeTailCaptureEligible(state(98)),true);
 assert.equal(nativeTailCaptureEligible(state(97)),false);
 assert.equal(nativeTailCaptureEligible(state(0,0)),true);
});
test('horizontal, dragging, invalid range and invalid value reject capture',()=>{
 for(const s of [state(100,100,{orientation:1}),state(100,100,{down:true}),
   state(100,99),state(-1),state(100,-5),state(NaN)])assert.equal(nativeTailCaptureEligible(s),false);
});
test('unchanged former bottom follows new maximum',()=>{
 assert.deepEqual(nativeTailRestoreDecision({startValue:100},state(100,180)),
   {follow:true,changed:true,reason:'followed_tail',value:180});
});
test('user position change cancels follow even near new bottom',()=>{
 assert.equal(nativeTailRestoreDecision({startValue:100},state(179,180)).reason,'position_changed');
 assert.equal(nativeTailRestoreDecision({startValue:100},state(40,180)).reason,'position_changed');
});
test('native layout already preserved bottom needs no write',()=>{
 assert.deepEqual(nativeTailRestoreDecision({startValue:100},state(180,180)),
   {follow:true,changed:false,reason:'already_at_bottom'});
});
test('active drag always wins even when currently at maximum',()=>{
 assert.equal(nativeTailRestoreDecision({startValue:100},state(180,180,{down:true})).reason,'slider_down');
});

// Invoke the actual helper against synthetic QObject/QWidget memory and mock
// verified native APIs. This does not load Frida or touch any live process.
function fixture(){
 const bytes=new Map(),refs=new Map(),widgets=new Map(),states=new Map(),writes=[];let next=0x10000;
 const clock={time:0},controls={afterWrite:null};
 class Ptr{
  constructor(n){this.n=n;} add(n){return new Ptr(this.n+n);} isNull(){return !this.n;}
  sub(p){return new Ptr(this.n-p.n);} compare(p){return Math.sign(this.n-p.n);}
  toString(){return '0x'+this.n.toString(16);} readPointer(){return new Ptr(refs.get(this.n)||0);}
  writePointer(p){refs.set(this.n,p.n);} readU8(){return (bytes.get(this.n)||0)&255;}
  readU32(){return (bytes.get(this.n)||0)>>>0;} readS32(){return (bytes.get(this.n)||0)|0;}
 }
 const Memory={alloc(n){const p=new Ptr(next);next+=Math.max(n,32);return p;}};
 const base=new Ptr(0x180000000);
 function widget(kind,parent=null,window=false,flags=1){
  const p=Memory.alloc(64),d=Memory.alloc(128),data=Memory.alloc(64);
  p.writePointer(base.add({root:0x9000100,area:0x9000200,owner:0x9175d78,bar:0x9000300}[kind]||0x9000400));
  p.add(8).writePointer(d);p.add(0x28).writePointer(data);d.add(0x10).writePointer(parent||new Ptr(0));
  bytes.set(d.n+0x20,flags);bytes.set(data.n+0xc,window?1:0);widgets.set(p.n,{kind,d,data});return p;
 }
 const root=widget('root',null,true),area=widget('area',root),owner=widget('owner',area),bar=widget('bar',root);
 widgets.get(area.n).bar=bar;states.set(bar.n,state());
 const nativeCalls=[];
 function native(rva,ret,args){
  nativeCalls.push(rva);assert.ok(NATIVE_FOLLOW_TAIL_FUNCTION_RVAS.includes(rva));
  if(rva===R.metaCast)return (meta,obj)=>{
   // Independent model of the observed real inheritance. In particular a
   // RecyclerListView does NOT cast to XRecyclerTableView (0x8e9c448).
   const chains={area:[0x8e9c418,0x8e9c300,0x8f1e978],bar:[0x91cd6b8,0x920e670]};
   const known=chains[widgets.get(obj.n)?.kind]||[];
   return known.includes(meta.n-base.n)?obj:new Ptr(0);
  };
  if(rva===R.verticalScrollBar)return a=>widgets.get(a.n).bar;
  if(rva===R.sliderMetaCall)return (b,call,id,argv)=>{
   if(controls.failRead)throw Error('Native read disabled by test');
   assert.equal(call,1);const key={0:'minimum',1:'maximum',4:'value',7:'orientation',10:'down'}[id];
   assert.ok(key);const out=argv.readPointer();bytes.set(out.n,Number(states.get(b.n)[key]));
  };
  if(rva===R.setValue)return (b,v)=>{writes.push({bar:b.n,value:v});states.get(b.n).value=v;
    if(controls.afterWrite)controls.afterWrite(states.get(b.n));};
  throw Error('Unexpected function');
 }
 const helper=createNativeFollowTail({base,native,Memory,pointerSize:8,now:()=>clock.time});
 assert.deepEqual(nativeCalls,NATIVE_FOLLOW_TAIL_FUNCTION_RVAS);
 return {helper,owner,area,bar,root,states,writes,widget,widgets,bytes,clock,controls,stateOf:()=>states.get(bar.n)};
}
test('actual helper captures verified ancestor and follows once',()=>{
 const f=fixture(),t=f.helper.capture(f.owner);assert.equal(t.bottom,100);assert.equal(t.startValue,100);
 f.stateOf().maximum=180;assert.equal(f.helper.restore(t,f.owner).changed,true);
 assert.deepEqual(f.writes,[{bar:f.bar.n,value:180}]);
 assert.equal(f.helper.restore(t,f.owner).reason,'token_consumed');assert.equal(f.writes.length,1);
});
test('observed RecyclerListView is accepted without requiring XRecycler subclass',()=>{
 const f=fixture();
 assert.equal(f.helper.diagnose(f.owner).stageNumber,100);
 assert.ok(f.helper.capture(f.owner));
 assert.deepEqual(f.writes,[]);
});
test('actual helper does not pull a reader away from history',()=>{
 const f=fixture();f.stateOf().value=70;assert.equal(f.helper.capture(f.owner),null);assert.deepEqual(f.writes,[]);
});
test('actual helper cancels a wheel/keyboard position change',()=>{
 const f=fixture(),t=f.helper.capture(f.owner);f.stateOf().maximum=180;f.stateOf().value=50;
 assert.equal(f.helper.restore(t,f.owner).reason,'position_changed');assert.deepEqual(f.writes,[]);
});
test('actual helper cancels drag started during layout',()=>{
 const f=fixture(),t=f.helper.capture(f.owner);f.stateOf().maximum=180;f.stateOf().down=true;
 assert.equal(f.helper.restore(t,f.owner).reason,'slider_down');assert.deepEqual(f.writes,[]);
});
test('actual helper accepts native automatic tail adjustment without writing',()=>{
 const f=fixture(),t=f.helper.capture(f.owner);f.stateOf().maximum=180;f.stateOf().value=180;
 const r=f.helper.restore(t,f.owner);assert.equal(r.restored,true);assert.equal(r.changed,false);assert.deepEqual(f.writes,[]);
});
test('owner moved to another list cannot reuse token',()=>{
 const f=fixture(),t=f.helper.capture(f.owner),other=f.widget('area',f.root);
 f.widgets.get(other.n).bar=f.bar;f.widgets.get(f.owner.n).d.add(0x10).writePointer(other);
 assert.equal(f.helper.restore(t,f.owner).reason,'different_list_or_scrollbar');assert.deepEqual(f.writes,[]);
});
test('scrollbar replaced on same list cannot reuse token',()=>{
 const f=fixture(),t=f.helper.capture(f.owner),other=f.widget('bar',f.root);
 f.widgets.get(f.area.n).bar=other;f.states.set(other.n,state());
 assert.equal(f.helper.restore(t,f.owner).reason,'different_list_or_scrollbar');assert.deepEqual(f.writes,[]);
});
test('different owner, forged token and destroyed owner fail closed',()=>{
 const f=fixture(),t=f.helper.capture(f.owner);
 assert.equal(f.helper.restore({...t},f.owner).reason,'invalid_token');
 assert.equal(f.helper.restore(t,f.area).reason,'different_owner');
 const t2=f.helper.capture(f.owner);f.bytes.set(f.widgets.get(f.owner.n).d.n+0x20,5);
 assert.equal(f.helper.restore(t2,f.owner).reason,'unavailable_scrollbar');assert.deepEqual(f.writes,[]);
});
test('parent cycle and owner window boundary do not wander into other lists',()=>{
 const f=fixture();f.widgets.get(f.owner.n).d.add(0x10).writePointer(f.owner);
 assert.equal(f.helper.capture(f.owner),null);
 const popup=f.widget('popup',f.area,true);assert.equal(f.helper.capture(popup),null);
});
test('horizontal or non-scrollbar replacement is rejected',()=>{
 const f=fixture();f.stateOf().orientation=1;assert.equal(f.helper.capture(f.owner),null);
 f.stateOf().orientation=2;f.widgets.get(f.bar.n).kind='other';assert.equal(f.helper.capture(f.owner),null);
});
test('diagnose returns only fixed metadata fields and never writes',()=>{
 const f=fixture(),d=f.helper.diagnose(f.owner);
 assert.deepEqual(Object.keys(d),['stageNumber','chainVtableRvas','areaVtableRva','barVtableRva','sliderState']);
 assert.equal(d.stageNumber,100);assert.deepEqual(d.chainVtableRvas,['0x9175d78','0x9000200']);
 assert.equal(d.areaVtableRva,'0x9000200');assert.equal(d.barVtableRva,'0x9000300');
 assert.deepEqual(d.sliderState,{min:0,max:100,value:100,orientation:2,down:false});
 assert.equal(JSON.stringify(d).includes(f.owner.toString()),false);assert.deepEqual(f.writes,[]);
});
test('diagnose identifies missing recycler and bar type mismatch separately',()=>{
 const f=fixture();f.widgets.get(f.area.n).kind='other';
 const missing=f.helper.diagnose(f.owner);assert.equal(missing.stageNumber,12);
 assert.equal(missing.chainVtableRvas.length,3);assert.equal(missing.areaVtableRva,null);
 f.widgets.get(f.area.n).kind='area';f.widgets.get(f.bar.n).kind='other';
 const wrongBar=f.helper.diagnose(f.owner);assert.equal(wrongBar.stageNumber,22);
 assert.equal(wrongBar.areaVtableRva,'0x9000200');assert.equal(wrongBar.barVtableRva,'0x9000300');
 assert.equal(wrongBar.sliderState.value,null);assert.deepEqual(f.writes,[]);
});
test('diagnose separates position, drag, orientation and bad range',()=>{
 const f=fixture();f.stateOf().value=70;assert.equal(f.helper.diagnose(f.owner).stageNumber,101);
 f.stateOf().down=true;assert.equal(f.helper.diagnose(f.owner).stageNumber,102);
 f.stateOf().orientation=1;assert.equal(f.helper.diagnose(f.owner).stageNumber,104);
 f.stateOf().orientation=2;f.stateOf().maximum=60;assert.equal(f.helper.diagnose(f.owner).stageNumber,103);
 assert.deepEqual(f.writes,[]);
});
test('diagnose catches native read failure without exposing exception details',()=>{
 const f=fixture();f.states.delete(f.bar.n);const d=f.helper.diagnose(f.owner);
 assert.equal(d.stageNumber,3);assert.deepEqual(d.sliderState,{min:null,max:null,value:null,orientation:null,down:null});
 assert.equal(Object.keys(d).length,5);assert.deepEqual(f.writes,[]);
});
test('diagnose excludes addresses outside pinned module',()=>{
 const f=fixture();f.owner.writePointer(f.owner);f.bar.writePointer(f.bar);
 const d=f.helper.diagnose(f.owner);assert.equal(d.stageNumber,100);
 assert.equal(d.chainVtableRvas[0],null);assert.equal(d.barVtableRva,null);assert.deepEqual(f.writes,[]);
});
const context=(scope=7,inputEpoch=3)=>({scope,inputEpoch});
function tick(f,g,time,max=f.stateOf().maximum,c=context()){
 f.clock.time=time;f.stateOf().maximum=max;return f.helper.step(g,f.owner,c);
}
test('guard follows range increases after initial 120ms no-op, ending at 2 seconds',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());assert.ok(g);
 assert.equal(tick(f,g,120).changed,false);
 assert.equal(tick(f,g,600,180).changed,true);
 assert.equal(tick(f,g,1300,240).changed,true);
 assert.equal(tick(f,g,1950,290).changed,true);
 assert.equal(tick(f,g,2000,330).reason,'expired');
 assert.equal(tick(f,g,2500,400).active,false);
 assert.deepEqual(f.writes.map(x=>x.value),[180,240,290]);
});
test('guard handles setValue triggering another delayed range calculation',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());
 f.controls.afterWrite=s=>{s.maximum+=40;};
 assert.equal(tick(f,g,120,180).changed,true);assert.equal(f.writes.length,1);
 assert.equal(tick(f,g,220).changed,true);assert.deepEqual(f.writes.map(x=>x.value),[180,220]);
 assert.equal(f.stateOf().maximum,260);
});
test('guard first callback after deadline never writes or extends its lifetime',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());
 assert.equal(tick(f,g,2200,300).reason,'expired');assert.deepEqual(f.writes,[]);
});
test('guard only begins with explicit context and original bottom position',()=>{
 const f=fixture();assert.equal(f.helper.begin(f.owner),null);
 assert.equal(f.helper.begin(f.owner,{scope:7}),null);
 f.stateOf().value=70;assert.equal(f.helper.begin(f.owner,context()),null);
 assert.deepEqual(f.writes,[]);
});
test('input epoch cancels even if user returned to the identical slider value',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());
 assert.equal(tick(f,g,120,180,context(7,4)).reason,'user_input');
 assert.equal(tick(f,g,220,200,context()).active,false);assert.deepEqual(f.writes,[]);
});
test('scope change cancels despite identical reused owner/list/bar pointers',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());
 assert.equal(tick(f,g,120,180,context(8)).reason,'scope_changed');assert.deepEqual(f.writes,[]);
});
test('guard detects value drift even without input notification',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());
 tick(f,g,120,180);f.stateOf().value=140;
 assert.equal(tick(f,g,240,220).reason,'position_changed');assert.equal(f.writes.length,1);
});
test('guard detects active thumb drag and does not resume after release',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());f.stateOf().down=true;
 assert.equal(tick(f,g,120,180).reason,'slider_down');f.stateOf().down=false;
 assert.equal(tick(f,g,240,220).active,false);assert.deepEqual(f.writes,[]);
});
test('unchanged range produces no repeated native writes',()=>{
 const f=fixture();f.stateOf().value=98;const g=f.helper.begin(f.owner,context());
 assert.equal(tick(f,g,100).changed,true);
 for(let t=200;t<2000;t+=100)assert.equal(tick(f,g,t).changed,false);
 assert.deepEqual(f.writes.map(x=>x.value),[100]);
});
test('automatic native bottom adjustment is accepted before later growth',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());f.stateOf().value=180;
 assert.equal(tick(f,g,100,180).changed,false);
 assert.equal(tick(f,g,250,220).changed,true);assert.deepEqual(f.writes.map(x=>x.value),[220]);
});
test('guard cancels on range shrink or scrollbar replacement',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());f.stateOf().value=90;
 assert.equal(tick(f,g,100,90).reason,'range_changed');assert.deepEqual(f.writes,[]);
 const h=fixture(),q=h.helper.begin(h.owner,context()),other=h.widget('bar',h.root);
 h.widgets.get(h.area.n).bar=other;h.states.set(other.n,state());
 assert.equal(tick(h,q,100).reason,'different_list_or_scrollbar');assert.deepEqual(h.writes,[]);
});
test('cancelAll immediately cancels pending guards and new guard supersedes old',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context()),h=f.helper.begin(f.owner,context());
 assert.equal(tick(f,g,100).reason,'superseded');assert.equal(f.helper.cancelAll(),1);
 assert.equal(tick(f,h,200,180).reason,'cancelled');assert.deepEqual(f.writes,[]);
});
test('cancelAll during reentrant native setter prevents subsequent writes',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());f.controls.afterWrite=()=>f.helper.cancelAll();
 assert.equal(tick(f,g,100,180).reason,'cancelled');assert.equal(f.writes.length,1);
 assert.equal(tick(f,g,200,220).active,false);assert.equal(f.writes.length,1);
});
test('too-frequent callbacks are throttled and clock rollback cancels',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());tick(f,g,100,180);
 assert.equal(tick(f,g,110,200).reason,'throttled');assert.equal(f.writes.length,1);
 assert.equal(tick(f,g,90,220).reason,'clock_changed');assert.equal(f.writes.length,1);
});
test('guard confirms setter result rather than retrying an ignored native write',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());f.controls.afterWrite=s=>{s.value=100;};
 assert.equal(tick(f,g,100,180).reason,'position_changed_during_write');
 assert.equal(tick(f,g,200,220).active,false);assert.equal(f.writes.length,1);
});
test('guard diagnostics expose a fixed numeric-only initial record without native reads',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());f.controls.failRead=true;
 const d=f.helper.guardDiagnostic(g);
 assert.deepEqual(d,{startValue:100,startMax:100,lastValue:100,lastMax:100,
  seenValue:100,seenMax:100,seenMin:0,seenDown:0,afterValue:null,afterMax:null,
  elapsedMs:0,steps:0,writes:0,inputChanged:0,reasonNumber:0});
 assert.ok(Object.values(d).every(x=>x===null||Number.isFinite(x)));
 assert.deepEqual(f.writes,[]);
});
test('position cancellation preserves observed drift and original tail values',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());f.stateOf().value=90;
 const r=tick(f,g,120,180),d=r.diagnostics;
 assert.equal(r.reason,'position_changed');assert.equal(d.reasonNumber,16);
 assert.equal(d.startValue,100);assert.equal(d.startMax,100);
 assert.equal(d.lastValue,100);assert.equal(d.lastMax,100);
 assert.equal(d.seenValue,90);assert.equal(d.seenMax,180);assert.equal(d.seenMin,0);
 assert.equal(d.elapsedMs,120);assert.equal(d.inputChanged,0);assert.equal(d.writes,0);
 assert.deepEqual(f.helper.guardDiagnostic(g),d);
 assert.deepEqual(f.writes,[]);
});
test('guard diagnostics distinguish input cancellation and post-write range recalculation',()=>{
 const f=fixture(),g=f.helper.begin(f.owner,context());
 assert.equal(tick(f,g,120,180,context(7,4)).diagnostics.inputChanged,1);
 assert.equal(f.helper.guardDiagnostic(g).reasonNumber,6);
 const h=fixture(),q=h.helper.begin(h.owner,context());
 h.controls.afterWrite=s=>{s.maximum=220;};
 const d=tick(h,q,120,180).diagnostics;
 assert.equal(d.seenValue,100);assert.equal(d.seenMax,180);
 assert.equal(d.afterValue,180);assert.equal(d.afterMax,220);
 assert.equal(d.steps,1);assert.equal(d.writes,1);assert.equal(d.reasonNumber,100);
 assert.deepEqual(h.helper.guardDiagnostic(q),d);
 const invalid=h.helper.guardDiagnostic({});
 assert.equal(invalid.reasonNumber,1);assert.equal(invalid.startValue,null);
 assert.deepEqual(Object.keys(invalid),Object.keys(d));
});
test('observed MMUI 4270 to 4333 to 4379 rounding and 4414 range growth stays bounded',()=>{
 const f=fixture();Object.assign(f.stateOf(),state(4270,4270));
 const g=f.helper.begin(f.owner,context());
 assert.equal(tick(f,g,110,4333).changed,true);
 f.controls.afterWrite=s=>{if(s.value===4379){s.value=4378;s.maximum=4414;}};
 const r=tick(f,g,214,4379);
 assert.equal(r.active,true);assert.equal(r.reason,'followed_tail');
 assert.equal(r.diagnostics.afterValue,4378);assert.equal(r.diagnostics.afterMax,4414);
 assert.equal(r.diagnostics.lastValue,4378);assert.equal(r.diagnostics.inputChanged,0);
 assert.equal(tick(f,g,314).changed,true);assert.equal(f.stateOf().value,4414);
 assert.deepEqual(f.writes.map(x=>x.value),[4333,4379,4414]);
 assert.equal(tick(f,g,2000,4500).reason,'expired');assert.equal(f.writes.length,3);
});
test('pre-step rounding accepts at most two units with unchanged input and rejects three',()=>{
 for(const drift of [-3,-2,-1,1,2,3]){
  const f=fixture(),g=f.helper.begin(f.owner,context());f.stateOf().value=100+drift;
  const r=tick(f,g,100,180);
  assert.equal(r.active,Math.abs(drift)<=2);
  assert.equal(f.writes.length,Math.abs(drift)<=2?1:0);
  if(Math.abs(drift)>2)assert.equal(r.reason,'position_changed');
 }
 const f=fixture(),g=f.helper.begin(f.owner,context());f.stateOf().value=99;
 assert.equal(tick(f,g,100,180,context(7,4)).reason,'user_input');assert.equal(f.writes.length,0);
});
test('post-write rounding accepts at most two units only within valid nonshrinking range',()=>{
 for(const drift of [-3,-2,-1,1,2,3]){
  const f=fixture(),g=f.helper.begin(f.owner,context());
  f.controls.afterWrite=s=>{s.value+=drift;s.maximum=220;};
  const r=tick(f,g,100,180);
  assert.equal(r.active,Math.abs(drift)<=2);
  if(Math.abs(drift)>2)assert.equal(r.reason,'position_changed_during_write');
 }
 const f=fixture(),g=f.helper.begin(f.owner,context());
 f.controls.afterWrite=s=>{s.value=178;s.maximum=179;};
 assert.equal(tick(f,g,100,180).reason,'state_changed_during_write');
});
process.stdout.write(tests+' tests passed\n');
