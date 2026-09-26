'use strict';
const assert=require('node:assert/strict');
const {projectWidgetChain,createNativeGeometry}=require('./native_geometry.js');
let count=0;
function test(name,run){run();count++;process.stdout.write('PASS '+name+'\n');}
function node(id,geometry,visible=true,isWindow=false){return {id,geometry,visible,isWindow};}
const root=node('root',[500,-250,1200,900],true,true);
test('client coordinates exclude top-level screen position',()=>{
 const r=projectWidgetChain([node('msg',[35,60,400,56]),node('viewport',[220,80,700,620]),root]);
 assert.deepEqual(r.rect,[255,140,655,196]);assert.equal(r.fullyVisible,true);
});
test('scrolling clips old rows despite visible property',()=>{
 const r=projectWidgetChain([node('msg',[0,10,400,56]),node('contents',[0,-100,700,1500]),node('viewport',[220,80,700,620]),root]);
 assert.equal(r.visible,false);assert.equal(r.reason,'clipped_by_ancestor');
});
test('partly visible row retains true position for stable ordering',()=>{
 const r=projectWidgetChain([node('msg',[0,80,400,56]),node('contents',[0,-100,700,1500]),node('viewport',[220,80,700,620]),root]);
 assert.deepEqual(r.rect,[220,60,620,116]);assert.deepEqual(r.clipped,[220,80,620,116]);assert.equal(r.fullyVisible,false);
});
test('bottom crop is bounded by viewport rather than whole window',()=>{
 const r=projectWidgetChain([node('msg',[0,610,400,100]),node('viewport',[220,80,700,620]),root]);
 assert.deepEqual(r.clipped,[220,690,620,700]);assert.equal(r.fullyVisible,false);
});
test('hidden ancestor rejects children that retain visible flag',()=>{
 assert.equal(projectWidgetChain([node('msg',[0,0,100,50]),node('viewport',[0,0,700,620],false),root]).reason,'hidden_ancestor');
});
test('cycle and missing root fail closed',()=>{
 assert.equal(projectWidgetChain([node('msg',[0,0,100,50]),node('msg',[0,0,100,50])]).reason,'parent_cycle');
 assert.equal(projectWidgetChain([node('msg',[0,0,100,50])]).reason,'invalid_window_boundary');
});
test('nested window does not become a fake child coordinate',()=>{
 assert.equal(projectWidgetChain([node('popup',[0,0,100,50],true,true),root]).reason,'invalid_window_boundary');
});
test('empty or malformed geometry is rejected',()=>{
 assert.equal(projectWidgetChain([node('msg',[0,0,0,50]),root]).visible,false);
 assert.equal(projectWidgetChain([node('msg',[0,NaN,100,50]),root]).visible,false);
});
// Exercise the actual pointer/Qt-MOC reader with a synthetic address space.
// No Process, native DLL, attach, or live UI is involved.
const bytes=new Map(), refs=new Map();let next=0x10000;
class Ptr {
 constructor(n){this.n=n;}
 add(n){return new Ptr(this.n+n);} isNull(){return this.n===0;} toString(){return '0x'+this.n.toString(16);}
 readPointer(){return new Ptr(refs.get(this.n)||0);} writePointer(p){refs.set(this.n,p.n);}
 readU8(){return (bytes.get(this.n)||0)&255;} readU32(){return (bytes.get(this.n)||0)>>>0;} readS32(){return (bytes.get(this.n)||0)|0;}
}
const Memory={alloc(n){const p=new Ptr(next);next+=Math.max(n,32);return p;}};
function mockWidget(g,parent=null,isWindow=false,flags=1){
 const p=Memory.alloc(64),d=Memory.alloc(128),data=Memory.alloc(64);
 p.add(8).writePointer(d);p.add(0x28).writePointer(data);d.add(0x10).writePointer(parent||new Ptr(0));
 bytes.set(d.n+0x20,flags);bytes.set(data.n+0xc,isWindow?1:0);
 p.geometry=g;p.visible=true;return p;
}
const widgets=new Map();
function register(w){widgets.set(w.n,w);return w;}
let reads=0;
const reader=createNativeGeometry({Memory,widgetMetaCall(w,call,id,argv){
 reads++;assert.equal(call,1);const p=widgets.get(w.n),out=argv.readPointer();
 if(id===3){const [x,y,ww,h]=p.geometry;[x,y,x+ww-1,y+h-1].forEach((v,i)=>bytes.set(out.n+4*i,v));}
 else if(id===35)bytes.set(out.n,p.visible?1:0);else throw Error('Unexpected MOC property');
}});
test('pointer reader stops at native window despite QObject parent',()=>{
 const unrelated=register(mockWidget([0,0,800,800],null,true));
 const top=register(mockWidget([500,300,800,600],unrelated,true));
 const child=register(mockWidget([10,20,100,50],top));
 reads=0;const r=reader.inspect(child);assert.deepEqual(r.rect,[10,20,110,70]);
 assert.equal(r.rootId,top.toString());assert.equal(reads,4);
 assert.equal(reader.inspect(child,{expectedRootId:unrelated.toString()}).reason,'different_window_root');
});
test('pointer reader rejects non-widget before native property call',()=>{
 const obj=register(mockWidget([0,0,20,20],null,false,0));reads=0;
 assert.equal(reader.inspect(obj).reason,'not_live_widget');assert.equal(reads,0);
});
test('pointer reader rejects destructor-state widget',()=>{
 const obj=register(mockWidget([0,0,20,20],null,true,5));reads=0;
 assert.equal(reader.inspect(obj).reason,'not_live_widget');assert.equal(reads,0);
});
process.stdout.write(count+' tests passed\n');
