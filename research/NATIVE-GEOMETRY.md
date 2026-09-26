# 原生消息视口与底部保持：静态证据

适配目标仅为本机 `Weixin.dll` 4.1.15.11，SHA-256 `7d056cf7fb834b5558d6646bfb4e0036aae93568e3f9a04cf1dfc5e79032bcac`。下列地址全为模块相对 RVA。本轮只读取安装文件并运行合成数据测试，没有附加或调用微信进程。

## 当前可集成的几何辅助模块

`native_geometry.js` 提供 `createNativeGeometry({widgetMetaCall, Memory, pointerSize})`，返回 `inspect(widget, {expectedRootId?})`。调用方沿用已经验证过的 QWidget MOC NativeFunction；辅助模块不初始化 Frida、不建立 hook、不读取文字、不写 native 对象。

成功结果包含 `visible, rect, clipped, fullyVisible, root, rootId, rootSize, depth`。两个矩形都是 `[left, top, right, bottom)`，坐标为共同顶层 QWidget **客户区内的 Qt 逻辑像素**。顶层本身的桌面 x/y 不参与累加；不能把这些坐标直接当作 WGC 物理像素或 Win32 屏幕坐标。按 `rect[1]` 排序才是当前实际纵向顺序，不能用文本 setter 的调用先后排序。

模块读取每一级 QWidget 的 geometry 和 visible，累加子控件的 parent-relative x/y，并且逐级与父控件的本地矩形求交。这样可以排除 `visible=true` 但已滚出 viewport 的旧行；还保留原始完整 rect 与裁剪后的 clipped，便于辨认半露出的消息。它不处理非矩形 QWidget mask、兄弟窗口遮挡或另一个应用遮挡；前台/最小化检查仍由正式适配器负责。

关键 ABI 已从本版指令静态核对：

| 操作 | 已证实内容 |
| --- | --- |
| QObject 私有对象 | `d = *(widget + 8)` |
| QWidget 类型位 | `byte(d + 0x20) & 1`；`mmui::QWidgetExtension::SetWidth` `0x1E938A0` 在 `0x1E938C0` 检查该位，否则走具名 `Invalid target pointer` 日志；QObjectData `wasDeleted` 为同字段 bit 2 |
| parentWidget | `*(d + 0x10)`；Qt parentWidget 只是对 QObject.parent 的 static_cast。本版完整 leaf `0x909930` / `0x33D1380` 均为两次指针读取后 ret；`QLayout::addChildWidget` 中亦使用相同关系 |
| QWidget 窗口边界 | `data=*(widget+0x28)`，`uint(data+0x0C)&1` 为 Qt::Window 位；本版 `0x5B54A0` / `0x5B54A4` 依此区分子控件与窗口 |
| QWidget MOC | `0x5BBFC0`，`void(widget*, int call, int local_id, void** argv)`，ReadProperty=1 |
| geometry | 本类 property 3：argv[0] 指向 16 字节 QRect。分支 `0x5BCE54` 直接复制 `data+0x14` 的四个 int：x1,y1,x2,y2，宽高分别末端减起点再加 1 |
| rect | 本类 property 13：本地 `[0,0,width-1,height-1]`，分支 `0x5BCF12` |
| x/y | 本类 property 6/7，分别调用完整 getter `int x(widget*) @0x5A7C70` / `int y(widget*) @0x5A7D10`；顶层分支可能修正 frame margins，因此辅助模块优先使用 geometry，仅累计非顶层节点 |
| visible | 本类 property 35，bool，一字节输出；仅此属性不能证明位于视口 |

根终止条件是遇到 isWindow=true，立即停止，即使这个顶层 QWidget 仍有 QObject owner。遇非 QWidget、正在销毁、空父却非窗口、父链循环或超过 64 层均 fail closed，不把地址继续解释为 QWidget。`expectedRootId` 可拒绝不属于同一个顶层窗口的消息。

证据：`qwidget-moc-static-trace.txt`、`parentwidget-leaf-trace.txt`、`iswidget-static-trace.txt`、`layout-disassembly-5a7c70-5a7d10.json`。辅助模块已运行 `node test_native_geometry.js`，11 项通过，包含真实 reader 对合成指针空间的测试，并覆盖滚动裁剪、底部裁剪、隐藏、循环、非 QWidget、销毁状态和顶层有 owner 的边界。

类型位和 parentWidget 语义以本版反汇编为主，并交叉核对 [Qt 5.15 QObjectData 源码](https://github.com/qt/qtbase/blob/5.15/src/corelib/kernel/qobject.h) 与 [QWidget parentWidget 源码](https://github.com/qt/qtbase/blob/5.15/src/widgets/kernel/qwidget.h)。Qt 源码本身不是对微信对象地址的动态验证。

## 原生底部保持入口

本版 `XRecyclerTableView → RecyclerListView → VirtualScrollArea → QAbstractScrollArea` 元对象链已验证。这三个 MMUI 类没有公开 `scrollToBottom` 或 `ensureVisible` slot；`VScrollBarSliderMoved` 是信号，不应把手动发射它当作滚动操作。

可用的 Qt 路线是先确认该消息祖先中的实际 RecyclerListView，再取其**垂直滑条**，在原生 UI 线程使用正常 setValue：

| 操作 | 入口与契约 |
| --- | --- |
| 校验 QObject 继承 | `QObject* QMetaObject::cast(const QMetaObject*, QObject*) @0x28C390`，RCX=meta，RDX=object。读取对象 virtual metaObject() 后沿 superdata 指针链查找相同 meta，命中返回 object，否则 null |
| Recycler 类型 meta | XRecyclerTableView=`0x8E9C448`，RecyclerListView=`0x8E9C418`，VirtualScrollArea=`0x8E9C300`，QAbstractScrollArea=`0x8F1E978` |
| 垂直滑条 | `pointer verticalScrollBar(area*) @0xCE87B0`，RCX=已验证的 QAbstractScrollArea 派生对象；完整 leaf 读取 `[[area+8]+0x220]` 后 ret。水平 getter `0xCE88A0` 使用 `+0x218` |
| 滑条类型 meta | QScrollBar=`0x91CD6B8`，QAbstractSlider=`0x920E670` |
| 滑条 MOC | `0x20B4600`，与 QWidget MOC 相同四参数签名，但本类索引属于 QAbstractSlider |
| 滑条 ReadProperty=1 | minimum=0, maximum=1, value=4, orientation=7, sliderDown=10；前四项 int，sliderDown 是 bool。垂直 orientation 必须为 2 |
| 设置 value | WriteProperty=2，local_id=4，argv[0]=int*。与 InvokeMetaMethod=0、slot index 6 共用 setter `void setValue(slider*, int) @0x20B34A0`，RCX=slider，EDX=value |

setter 走正常 sliderChange 与 valueChanged 信号；没有直接改滑条私有数值。静态 `QAbstractScrollArea` 的 `_q_vslide` 分派会计算 dy 并调用 scrollContentsBy 虚函数，因此这是正常原生滚动路径。尚未在本机 MMUI 列表上动态执行，不能先声称已完成留底效果。

最小策略：追加文字**之前**读取 min/max/value 和 sliderDown；仅当未拖动且 value 接近 max 时记录留底意图。布局完成后，在同一个会话、同一个仍有效的列表/滑条上重新读取最新 max，再调用一次 setValue(max)。用户原来在读历史时不执行；等待期间若用户滚动、切会话、对象复用、前台变化，应放弃本次留底。不得在每次轮询时持续 setValue(max)，也不要把一个 QWidget 的简单子类 vtable 当作任意 QAbstractScrollArea 调用。

`QAbstractScrollAreaPrivate` 成员相邻关系和 verticalScrollBar getter 与 [Qt 5.15 滚动区域实现](https://github.com/qt/qtbase/blob/5.15/src/widgets/widgets/qabstractscrollarea.cpp) 及 [其私有结构](https://github.com/qt/qtbase/blob/5.15/src/widgets/widgets/qabstractscrollarea_p.h) 一致。本版专有证据：`qt-scroll-meta.json`、`scrollarea-moc-trace.txt`、`scrollbar-getters-static-trace.txt`、`slider-moc-trace.txt`、`slider-setvalue-static-trace.txt`。

## 留底辅助模块实现与离线验证

`native_follow_tail.js` 已按上述 ABI 实现 `createNativeFollowTail({base, native, Memory, pointerSize:8})`。其中 native 是调用方已使用的 `native(rva, returnType, argTypes)` 工厂；模块不自行加载 Frida 或目标 DLL，不建立 hook/timer。主适配器负责在 GUI 线程调用，并在恢复前确认 owner/会话代次仍然有效。

`capture(owner)` 只沿活着的 QWidget 父链查找经 `QMetaObject::cast` 确认的 RecyclerListView（meta `0x8E9C418`），并额外 cast 到 QAbstractScrollArea（meta `0x8F1E978`）确认 getter 契约，再核对 QScrollBar 类型、orientation=2、未拖动、有效 min/max/value。仅 `value >= maximum-2` 时产生不可篡改 token，记录 owner/list/bar 身份与 startValue、bottom。`restore(token, owner)` 重新定位同一个列表和滑条；当前 value 仍等于 startValue 才设置最新 maximum。若当前已等于最新 maximum，返回成功但不重复调用 setValue。用户改变滚动位置、开始拖动、对象更换或类型失效时跳过。token 只能由同一个 helper 签发且仅消费一次，防止后续轮询意外重复钉底。

可供宿主校验函数字节的白名单是 `NATIVE_FOLLOW_TAIL_FUNCTION_RVAS = [0x28C390, 0xCE87B0, 0x20B4600, 0x20B34A0]`。`test_native_follow_tail.js` 已通过 16 项离线测试，其中真实 helper 在合成 QObject/QWidget 指针空间中执行 capture/restore，native 工厂只提供白名单模拟函数；覆盖两像素阈值、历史阅读、主动滚动、拖动、自动留底无需重写、列表/滑条更换、伪造与重复 token、销毁状态、父链循环和非垂直滑条。测试没有加载 Frida、附加进程或访问微信内容。真实 MMUI 留底效果仍待主适配器独占验证。

随后主代理报告真实留底未成功，故新增只读 `diagnose(owner)`，不改动留底判定、不用推测替代运行证据。其结果严格固定为 `{stageNumber, chainVtableRvas, areaVtableRva, barVtableRva, sliderState:{min,max,value,orientation,down}}`。未知项为 null；vtable 只输出落在本版 PE SizeOfImage `0xC0AC000` 范围内的模块相对 RVA，不输出堆指针、绝对地址、聊天文本、会话 ID 或异常文本。诊断复用实际 locate 分支，但不签发 token、不调用 setValue。阶段 12 为到顶层仍未匹配 XRecycler，20/21/22 分别为垂直滑条为空/非有效 QWidget/非 QScrollBar；100/101/102/103/104 分别为可留底/不在底部/拖动/范围异常/非垂直。阶段 1/2/3 未继续前进则代表父链/滑条 getter/滑条属性读取异常。完整字典由 `NATIVE_FOLLOW_TAIL_DIAGNOSTIC_STAGES` 导出。

新增 5 项测试验证固定输出结构、类型匹配失败分支、各项留底条件、读取异常及模块外地址抑制；全套现为 **21 项通过**，并明确检查诊断路径没有调用 setValue。真实诊断样本待主代理以 observe-only 模式采集，本报告不预先断言是哪一个条件失败。

**实际只读诊断已定位类型检查错误，并已修正。** 主代理提供的 `native-tail-state.json` 中 stage=12，祖先 2 的 vtable 十进制 `153144136` 即 `0x920CB48`。磁盘上的这个 vtable 第一个函数为 metaObject accessor `0x8F5A50`，返回静态 meta `0x8E9C418`；解析结果明确是 `mmui::RecyclerListView → VirtualScrollArea → QAbstractScrollArea`，不是其派生类 XRecyclerTableView。因此旧的 XRecycler cast 必然失败，不能据此推断不存在滚动容器。祖先 3 (`0x917E7F8`) 是 MessageView，祖先 4 (`0x91D2698`) 是 XVBoxView；全部 19 个实际 vtable 的类型、meta 和继承证据存于 `actual-chat-ancestor-types.json`。

辅助模块现改用上述实际 RecyclerListView meta，getter 前再确认 QAbstractScrollArea；新增诊断阶段 23 表示该基类校验失败。getter 和 setValue 的函数地址不变，仍未在本轮执行真实滚动写入。测试的模拟 cast 已改成独立固定的真实继承链，明确 RecyclerListView 不能 cast 成 XRecyclerTableView；旧错误配置会使成功路径测试失败。含这个回归在内，目前 **22 项全部通过**。待下一轮 observe-only 返回实际 bar 类型和 sliderState 后，再决定是否进行留底写入验收。

## 首次启动已有消息的边界

实际诊断的 19 层父链已静态解码为 `ChatTextItemView → ... → RecyclerListView → MessageView → ...`；类型样本保存在 `actual-chat-ancestor-types.json`。这证明从任意已捕获 owner 可以向上得到消息列表根，再在 UI 线程只读遍历 QObject 子树发现同一视口中已有的文字项。

Qt 5.15 的 `QWidget::find(WId)` 官方实现是 `QWidgetPrivate::mapper ? QWidgetPrivate::mapper->value(id, 0) : nullptr`，但本版 Weixin.dll 没有导出函数或 MOC 方法能无歧义对应这个静态入口。`QApplication::allWidgets()` / `topLevelWidgets()` 也不是 MOC 方法，返回 `QWidgetList`，其函数地址、返回 ABI 和全局容器在本版未核准。`qWindowsWndProc @0x25A1740` 只做 HWND 事件分发，QWindowsWindow 的 `widget()` 是私有 inline，未找到安全的跨 HWND QObject accessor。因此不应猜测 RVA，也不应把全局堆枚举当作启动方案。

若已有一个 binding，QObjectData 提供有限且可复核的发现路径：`d=*(object+8)`，`d+0x10` 是 parent，`*(d+0x18)` 才是 `QList<QObject*> children` 的数据指针；QListData header 为 `ref@0, alloc@4, begin@8, end@12, array@16`，子指针位于 `*(listData + 0x10 + 8*(begin+i))`。本版函数 `0x5C38C0` 直接读取这组偏移，不能把 parent 当作 children。对每个子对象先检查 `d+0x20` 的 isWidget/wasDeleted 位，再用已核实 vtable/meta 过滤 `ChatTextItemView`，设置深度和每节点数量上限，遇到无效/循环即停止。若启动时完全没有 binding，本轮已核准的路径仍需等待首个 setter 或会话切换；本轮没有定位可信的 HWND→Qt root 入口。
