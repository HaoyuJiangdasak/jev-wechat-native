// Geometry only. No Frida initialization, hooks, text access, or native writes.
// Holds no addresses: the adapter passes in the verified widget accessor, so this
// file is independent of the WeChat build. Compatibility data lives in
// native_anchors.json.
// All rectangles below are half-open Qt logical pixels, relative to a common
// top-level QWidget client area. They are NOT WGC physical/screen coordinates.
function projectWidgetChain(chain) {
  const fail = reason => ({visible:false, reason});
  if (!Array.isArray(chain) || !chain.length || chain.length > 64) return fail('invalid_chain');
  const seen = new Set();
  for (let i=0; i<chain.length; i++) {
    const n=chain[i];
    if (!n || seen.has(n.id)) return fail('parent_cycle');
    seen.add(n.id);
    if (!Array.isArray(n.geometry) || n.geometry.length!==4 ||
        !n.geometry.every(Number.isSafeInteger)) return fail('invalid_geometry');
    const [x,y,w,h]=n.geometry;
    if (Math.abs(x)>1e7 || Math.abs(y)>1e7 || w<=0 || h<=0 || w>1e6 || h>1e6)
      return fail('empty_or_invalid_geometry');
    if (!n.visible) return fail('hidden_ancestor');
    if (n.isWindow !== (i===chain.length-1)) return fail('invalid_window_boundary');
  }
  let rect=[0,0,chain[0].geometry[2],chain[0].geometry[3]], clipped=rect.slice();
  for(let i=0;i<chain.length-1;i++) {
    const [x,y]=chain[i].geometry, p=chain[i+1].geometry;
    rect=[rect[0]+x,rect[1]+y,rect[2]+x,rect[3]+y];
    clipped=[Math.max(0,clipped[0]+x),Math.max(0,clipped[1]+y),
             Math.min(p[2],clipped[2]+x),Math.min(p[3],clipped[3]+y)];
    if(clipped[2]<=clipped[0] || clipped[3]<=clipped[1])
      return fail('clipped_by_ancestor');
  }
  const root=chain[chain.length-1];
  return {visible:true,reason:'visible',rootId:root.id,rect,clipped,
    rootSize:root.geometry.slice(2),depth:chain.length,
    fullyVisible:rect.every((n,i)=>n===clipped[i])};
}

function createNativeGeometry({widgetMetaCall,Memory,pointerSize=8}) {
  function property(widget,index,size) {
    const out=Memory.alloc(size), argv=Memory.alloc(pointerSize);
    argv.writePointer(out); widgetMetaCall(widget,1,index,argv); return out;
  }
  function inspect(widget,options={}) {
    const chain=[], seen=new Set(); let current=widget;
    try {
      for(let depth=0;depth<64;depth++) {
        if(!current || current.isNull()) return {visible:false,reason:'missing_window_root'};
        const id=current.toString();
        if(seen.has(id)) return {visible:false,reason:'parent_cycle'};
        seen.add(id);
        const d=current.add(8).readPointer();
        if(d.isNull()) return {visible:false,reason:'invalid_qobject'};
        const flags=d.add(0x20).readU8();
        // QObjectData.isWidget bit 0; wasDeleted bit 2.
        if(!(flags&1) || (flags&4)) return {visible:false,reason:'not_live_widget'};
        const data=current.add(0x28).readPointer();
        if(data.isNull()) return {visible:false,reason:'invalid_widget_data'};
        const isWindow=(data.add(0x0c).readU32()&1)!==0;
        const qrect=property(current,3,16);
        const x=qrect.readS32(),y=qrect.add(4).readS32();
        const geometry=[x,y,qrect.add(8).readS32()-x+1,qrect.add(12).readS32()-y+1];
        const visible=property(current,35,1).readU8()!==0;
        chain.push({id,geometry,isWindow,visible});
        if(isWindow) {
          if(options.expectedRootId!==undefined && String(options.expectedRootId)!==id)
            return {visible:false,reason:'different_window_root'};
          const result=projectWidgetChain(chain);
          if(result.visible)result.root=current;
          return result;
        }
        current=d.add(0x10).readPointer();
      }
      return {visible:false,reason:'parent_depth_limit'};
    } catch(_) { return {visible:false,reason:'unreadable_widget'}; }
  }
  return {inspect};
}

if(typeof module!=='undefined' && module.exports)
  module.exports={projectWidgetChain,createNativeGeometry};
