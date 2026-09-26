研究日期：2026-09-22。对象：本机 Windows 微信 **4.1.15.11**。本轮仅检查安装目录的静态文件和公开原始文档/源码；没有打开聊天数据库、读取进程内存、注入、修改微信文件或运行第三方二进制。

**可继续的技术方向已经缩小为 Qt 5.15.14 / MMUI 的私有消息视图与布局适配器。** 本机有直接的消息控件类名与列表标识可供定位。没有找到微信公开的“本机消息显示扩展 API”；这不等于无法开发，而是下一步需要针对当前版本做新的静态逆向。现有透明窗和 `SetParent` 子窗都不能作为已经实现原生消息插入的证据。

本地证据文件是 `C:\Program Files\Tencent\Weixin\4.1.15.11\Weixin.dll`，Windows 文件/产品版本均为 `4.1.15.11`，大小 201,546,288 字节，SHA-256 为 `7d056cf7fb834b5558d6646bfb4e0036aae93568e3f9a04cf1dfc5e79032bcac`。同目录的 `plugin_info.ini` 只列出 RadiumWMPF、XEditor、WeChatOcr、WeChatUtility、XPlayer 的内部组件版本，没有第三方消息渲染插件的接口说明。

下表为直接从磁盘文件提取的静态字符串。偏移是**文件偏移**，不是运行地址或可调用入口；类名存在也不能单独证明继承关系和调用约定。

| 已验证标记 | 首个文件偏移 | 能支持的判断 |
| --- | --- | --- |
| `5.15.14`、`QtCore`、137 处 `QWidget` | `0x8d90f40` / `0x8d42ae1` / `0x839a6f7` | 主模块包含 Qt 5.15.14 与 Widgets 的强证据 |
| `mmui::ChatDetailView` | `0xb1387d0` | 存在聊天详情视图类型，可作为静态交叉引用起点 |
| `chat_message_list` | `0x917d378` | 存在具体消息列表标识；尚未证明它对应 HWND 或公共对象 |
| `mmui::ChatItemView`、`mmui::ChatTextItemView` | `0xb137b10` / `0xb1373a8` | 消息行/文字消息有私有视图类型 |
| `mmui::ChatBubbleFrame`、`mmui::ChatBubbleItemView` | `0xb1376a0` / `0x8d95070` | 气泡框与气泡内容是可分别调查的布局节点 |
| `BaseChatItemViewModel` | `0xb13783c` | 可进一步定位行数据到视图的连接；未确认其与 QAbstractItemModel 的关系 |
| `mmui::ChatSystemInfoItemView` | `0xb137c30` | 客户端有系统提示行的专用视图；不代表已有可外部调用的本地提示插入函数 |
| `mmui::XRecyclerTableView`、`mmui::XSkiaWidegetBase` | `0xb157f18` / `0x8e9a6f8` | 存在回收列表和 Skia 控件基础类型；具体聊天列表是否使用它们仍待交叉引用 |

此外发现 `<XVBoxView ...>` 等内嵌 XML 布局片段与 QtCore 的内部构建路径。安装目录没有独立 Qt DLL、`.qml`、`qmldir`；对主 DLL 的 ASCII 扫描中 `QtQuick`、`QQml`、`QQmlExtensionPlugin`、`.qml`、`qrc:/`、`cef_` 均为零。**推断：优先调查 C++ Qt Widgets/MMUI，暂不投入 DOM/CSS 注入或替换 QML 文件。** 零命中只针对该文件和编码，不能排除压缩资源、动态子模块或其他功能使用浏览器。看到 Chromium 网络组件、`RadiumWMPF.bin` 或 WebView 类也不能据此断言聊天气泡由 CEF 渲染。

Qt 自身确实提供扩展点，但应用级插件需要宿主定义接口并加载；Qt 通用插件用于样式、图像格式、平台集成等。`qt_plugin_instance` 字符串只表明存在 Qt 插件加载相关代码，不能据此把任意 DLL 放入目录便获得消息模型访问权。本轮没有找到微信提供的此类宿主契约。[Qt 5.15 官方插件文档](https://doc.qt.io/qt-5/plugins-howto.html)

公开项目 `NewbieCheng/wechat-uia-keepalive` 的作者描述了微信 4.x 的 Qt/MMUI 无障碍节点激活；在固定提交 `baa73ea672a194868596a79bbb91da81a1216a31`，`a11y_client.py` 使用 `IUIAutomation`、`ElementFromHandle`、`ControlViewWalker` 遍历控件。这是后续**只读定位边界/滚动结构**的候选实验，作者的成功描述并非对本机 4.1.15.11 的独立验证。UIA 暴露控件不会自动提供“向微信内部模型插入一行”的能力。本轮没有运行该工具，也不采用其启动/修改渲染预设流程。[项目原始实现](https://github.com/NewbieCheng/wechat-uia-keepalive/blob/baa73ea672a194868596a79bbb91da81a1216a31/a11y_client.py)

公开 `aixed/WeChat-Hook` 在固定提交 `e905d07ade50d2c6472e4eb3bd4f3fe19cf662c6` 描述的实现是进程内 DLL 代理加载，目标版本为 **4.1.10.27**，功能是消息发送、XML 转发、资料及数据库接口，并明确依赖内部偏移。它能作为“4.x 存在版本相关私有接口适配工作”的证据，不能作为 4.1.15.11 已支持本地原生分析卡片的证据，也不是官方插件 SDK。本轮没有下载或运行它的发行二进制。[项目作者 README](https://github.com/aixed/WeChat-Hook/blob/e905d07ade50d2c6472e4eb3bd4f3fe19cf662c6/README.md)

需要区分三种完全不同的结果：

| 路径 | 是否改变微信真实布局 | 是否是真正聊天记录插入 | 当前证据/工作量 |
| --- | --- | --- | --- |
| 顶层透明窗，或通过 `SetParent` 成为微信的子 HWND | 否；它只覆盖已有像素，不会让原列表为卡片让出高度 | 否 | 已有技术可做视觉叠层；不能满足“原生消息行”的验收 |
| 在实际 MMUI 消息行中增加本地分析区，参与气泡/行高计算及回收 | 若接入实际布局，可以；只是行的本地扩展 | 不新增聊天记录；是实际视图内的注释 | 最贴近“消息下方自动展示而不造假聊天”的研究方向，但需要新的私有布局适配 |
| 调用内部消息模型插入系统提示行/本地虚拟行 | 可能由原列表负责排序、行高和滚动 | 只有接入真实模型才能称原生行；是否入库/同步需另核实 | 仅找到 `ChatSystemInfoItemView` 类型，未找到受支持的构造、插入、删除或持久化接口 |

微软的 `SetParent` 只变更父窗口关系，还要求调用者自行处理 `WS_CHILD` / `WS_POPUP`，跨进程 DPI 模式也有特殊行为。它不会把外部控件转成另一个进程的 QObject 或修改 Qt 的模型/布局，因此 child-window overlay 必须继续明确叫叠层。[Microsoft SetParent 文档](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setparent)

建议按下面的实验顺序继续，前两步可保持只读，后两步属于尚未执行的新适配开发：

1. **固定目标版本并做静态交叉引用。** 以上 SHA-256 作为适配器目标锁，沿 `ChatTextItemView`、`ChatBubbleFrame`、`BaseChatItemViewModel`、`chat_message_list` 的字符串/RTTI/Qt 元对象数据寻找构造、行高计算、绑定和回收路径；沿 `ChatSystemInfoItemView` 判断它是纯视图工厂，还是与消息写入/发送耦合。可以先在磁盘 DLL 的反汇编工程中完成，完全不需要读用户 DB 或进程内存。产出应是具体函数关系、参数形状和版本识别，而不是把字符串偏移当函数地址。
2. **无聊天文本的 UIA 元数据实验。** 仅附着当前微信 HWND，记录控件类、AutomationId、矩形、父子结构和支持的 Pattern，不保存 Name/Value/Text。若已暴露，核对消息列表是否有独立可滚动子树、每行是否有可对应的 UIA 节点。若仅有外壳，记录失败即可；不得把激活失败解读成不存在私有消息视图。此实验只能改善定位/验证，不能实现插入。
3. **先用自有 Qt 5.15 测试宿主验证布局契约。** 制作有列表回收、消息 ID、行高变化和滚动锚点的假数据宿主，验证“现有行底部增加本地 analysis 子区”的寿命、换会话销毁、复用清理、45 秒超时与 DPI 行为。该测试能够验证我们自己的适配协议，不能宣称验证了真实 MMUI ABI。
4. **在完成第 1 步后才选择真实适配方式。** 优先研究实际消息行的布局/绘制扩展，让分析区域增加行高并随原列表滚动，按原消息 ID 绑定；避免构造发件人/系统通知等会被误认为聊天事实的记录。必须新确认 Qt ABI、UI 线程调度、工厂/构造路径、行高失效、回收生命周期及退出卸载。若宿主没有可调用扩展点，这一步将需要进程内代码适配，属于本轮未实施的研究边界。无法仅用 UIA、跨进程 SendMessage 或 SetParent 绕过。

真实验收必须包括：分析区挤出新行高、原有文字不被覆盖；上下滚动时它随对应消息进入/离开视口；历史消息复用不串卡；会话切换清理；停止适配后原聊天内容完整。若只能看见附着于窗口的灰卡，即使视觉上位于消息下方，也仍是 overlay，不能通过“原生布局”的验收。

可重跑的证据采集脚本为同目录 `scan_rendering_static.py`；它只读取上述安装文件，输出 `rendering-static-evidence.json`，包括 22 个标记的计数、文件偏移、版本目录文件清单及插件版本文本。完整结果与本报告放在一起，便于后续适配器研究复核。搜索服务本次持续返回 502，公开资料通过 GitHub API/原始文件与官方文档 HTTPS 原页核对；上述四个外部来源没有把搜索摘要当作实现证据。

**后续静态解析已把“原生子控件”路线推进到具体布局与 setter。** 以下均为同一个 SHA-256 的模块相对 RVA，运行时不能直接当绝对地址，也不是跨版本稳定 API；本轮仍未附加微信进程或调用这些函数。

`parse_qt_chat_meta.py` 按 Qt 5 的 QByteArrayData 字符表和 revision 8 MOC 数据解析了类型、父元对象、方法及属性，并将结果保存为 `qt-chat-meta.json`。元对象给出的完整继承链为：`ChatTextItemView → ChatBubbleReferItemView → ChatBubbleItemView → ChatItemView → XTableCell → QFReuseWidget → QFWidget → QWidget → QObject`。这比单看类型名更明确：目标消息项属于 QWidget/QObject 体系。

| 类型 | staticMetaObject RVA | 已解析出的与实验相关的成员 |
| --- | --- | --- |
| `mmui::ChatTextItemView` | `0x8e79900` | 4 个 public slots：`OnClicked(QMouseEvent*)`、`OnTextSelectChanged(QString)`、`OnInitialSelectionExpired()`、`OnTextLayoutComplete()`；没有本类可写 Text 属性 |
| `mmui::ChatItemView` | `0x8e79990` | 仅本类可写 QColor 属性 `animation_color`；没有 SetText/Refresh slot |
| `mmui::ChatBubbleFrame` | `0x8e79b20` | `sizeChanged(QSize)` 信号；存在尺寸通知，但信号本身不是尺寸修改器 |
| `mmui::XTextView` | `0x8e9a558` | 可读写 QString `Text`、`TextSize`、`AutoWrap`、`PreferTextWidth` 等；`LayoutComplete()` 信号 |
| `mmui::XRecyclerTableView` | `0x8e9c448` | 继承 `RecyclerListView → VirtualScrollArea → QAbstractScrollArea`；RecyclerListView 有 `DidDiffUpdate()` 信号，未暴露本类行高 setter |

最有价值的函数是 **RVA `0x1bc8640`**，反汇编证明它构建现有文字消息内容：

1. 分配 `0x188` 字节，调用 `0x1e8dbb0(this=new_object, parent=null)` 创建原生竖向容器，存入 `ChatTextItemView + 0x500`，设置 objectName 为 `label_xvbox_view`。容器布局的 objectName 为 `label_vbox_layout`。
2. 分配 `0xA20` 字节，调用 `0x1e7a170` 创建 `XTextView`：RCX 为新对象，RDX 指向 `style::Label`，R8 为 null parent。style 来自全局 `0x956ab20` 指针所指结构的 `0x58` 字节拷贝，并按消息方向修改；不能用全零内存代替该结构。分配器调用地址为 `0x74a989c`，属于有失败重试/抛错逻辑的分配函数，不能与任意别的运行库 free 配对。
3. 创建结果在 `0x1bc88fb` 写入 `ChatTextItemView + 0x508`。`0x1bc8968` 又把所属 ChatTextItemView 指针写入 `XTextView + 0x410`，相邻 `+0x408` 为弱引用控制块相关字段。这个反向关系只能在类型和版本确认后用于关联。
4. `0x1bc8e58` 读取 `this+0x500`，调用 `0x5b4d90` 取得 layout；随后 `0x1bc8e6e` 调用 `0x598210(layout, this->text_view)` 把现有 XTextView 加入原生布局。后续 `0x598500(layout, text_view, 0x84)` 设置对齐。`0x598210` 的被调函数包含 QLayout 的父对象校验和子 QWidget 纳入逻辑；这不是 Win32 SetParent 叠层。

因此首个只读运行实验可只在 `0x1bc8640` 返回时收集创建次数、线程 ID、`+0x500/+0x508` 的非空状态和几何数值，不读文字、不改内容。它能验证控件实际出现、位于 UI 线程、参加真实父子树，为后续原生注释控件提供明确的试验对象；无需先拿到 UIA 完整树。

`Text` 属性的写入链已经静态对应到具体目标：`XTextView.static_metacall` RVA `0x8f9950`，`WriteProperty=2`、本类 property index `0` 时分派到 **`0x1e80d40(XTextView*, QString*)`**。后者将 QString 转为内部文字描述，经过 `0x1e7ba70` 调用对象 vtable `+0x180`；本版 XTextView 主 vtable RVA `0x91cfb08` 的该项为 `0x1e81000`，它跳到 **`0x1e81010`**。静态调用约定是 Windows x64：RCX 为对象，RDX 为指向 QString 对象的指针；QString 对象包含 data 指针，转换 helper 读取 data 的 `+4` 长度和 `+0x10` 数据偏移。裸 char 指针或 UTF-16 字符数组都不是 QString 对象；本轮没有构造或传入过任何真实调用参数。

尺寸传播也有实证：`0x1e81010` 的尾部调用 `0x5a1260` 请求绘制更新，然后调用 `0x5b4950 → 0x5abbb0`。后者使父 layout 失效；在相应无布局分支构造类型 `0x4c` 的 LayoutRequest 事件发送到父控件。它也会在固定 min/max 尺寸、隐藏等条件下提前返回。**已确认文字 setter 会请求上层重排；尚未确认微信回收列表会自动更新自己的行高缓存。** 新增 XTextView 子控件后能否让整条消息及后面的消息移动，需要下一阶段的几何实验，不能仅凭 updateGeometry 链作成功承诺。

另外已经排除了一个看似方便却不正确的入口：`ChatTextItemView::OnTextLayoutComplete` 的本类 method index `3` 分派到 `0x1bc9200 → 0x1bcd710`，实际检查 `this+0x550` 的初始选择状态，在 `this+0x508` 上恢复选择并安排定时清理；它并不是一个通用的行高刷新函数。

相关静态反汇编由 `trace_chat_layout.py` 生成，文件名为 `layout-disassembly-*.json`。脚本利用 PE 异常表限定函数边界，对没有 unwind 记录的短跳板单独标为推断边界，避免将相邻函数误认为同一函数。主要证据包括 `layout-disassembly-1bc8640.json`、`layout-disassembly-8890e0-889820-8f9950.json`、`layout-disassembly-1e81010-1e7a170-598270.json` 与 `layout-disassembly-5abbb0-1e81d20-1e81d10.json`。真实运行仍应先核对 DLL 哈希和上述关系；这批结果是可复核的静态定位，不是已经可用的动态适配器。

**行高问题进一步缩小到了动画状态。** 从 QWidget 元数据 `sizeHint` 属性（本类 index 39）的读取分派可确定 vtable `+0x70` 为 `sizeHint`，而 ChatTextItemView 主 vtable `0x9175d78` 的实现为 `0x1bcebf0`。它在 `this+0x4D0` 非空且 `int(this+0x4D8)>0` 时，用普通 QWidget sizeHint 的宽度，但把高度替换为 `+0x4D8`；其余情况完整采用 QWidget 的布局 sizeHint。

这些字段不是已经证实的长期消息高度缓存：`0x1bcecc0` 在 `+0x4D0` 创建 QVariantAnimation，配置 150ms、起止高度；其 valueChanged 回调 `0x1bd3e80` 每帧更新 `+0x4D8` 并调用 `0x5ac4a0` 固定高度。finished 回调 `0x1bd3d20` 清为 -1、恢复最小高度 0/最大高度 0xFFFFFF、请求 updateGeometry。动画类型有被调函数 `0x1b623e0` 内 `QVariantAnimation::setDuration` 日志字符串佐证。回调本身是 Qt slot-object 分派器，参数不是简单的 `(owner*)`，不能误当普通成员函数调用。`0x1bc54b0` 也会清动画及相邻状态，不是无副作用的 cache-clear API。

因此只读探测新增 `+0x4D0` 非空计数、`+0x4D8`、控件 min/maxHeight 和 sizeHint 高度即可。如果正常稳定态是 null/-1，应先用原生布局正常重排，**没有证据支持必须手改这个字段**。只有动画激活态才需要等待结束再做修改，避免与动画同时驱动尺寸。

现有高度变化最后通知走 `0x1bda810(owner)`：当 `byte(owner+0x28C)==0`，取 `*(owner+0x250)`，非空则进入 `0x3cf2250`；后者取该关联对象的 `+0xD0` listener，并调用 listener 的 vtable `+8`，第二参数为关联对象本身。这是有明确静态入口的“向关联对象的观察者通知”链，但 listener 类型及最终是否通知回收列表尚未确认，不能把它保证为无副作用的布局刷新器。证据在 `layout-disassembly-1bcebf0-1e80590-1e80910.json`、`layout-disassembly-1bcecc0-1bd3d20-1bd3e80-1bc54b0.json`、`layout-disassembly-1bda810-1b620c0-1b623e0-5ac2a0-5ac380-5ac4a0.json` 与 `layout-disassembly-3cf2250.json`。

临时 QString 的销毁也已有现成 wrapper，不需要手工 free。**RVA `0x14E0`，参数 RCX=`QString*`，无返回值**，先读取对象的 data 指针；data.ref 为 -1 时返回，为正时做原子递减，仅当归零（或原值为 0）时以元素大小 2、对齐 8 调用 QArrayData 释放函数 `0x38930`。正常返回指令位于 `0x1509`。这个 wrapper 也被 XTextView 的 QString 属性读取分派用来清理 QString 临时值，因此有使用语境佐证。它不会把原 QString 的 8 字节内容清零，不能重复销毁；只应清理已成功构造、属于调用方的临时对象，不能销毁从微信对象上借用的字符串。

读取尺寸无需猜测 QSize 返回 ABI。**RVA `0x5BBFC0` 是 QWidget.static_metacall，签名 `void(QWidget*, int call, int local_id, void** args)`**。本版 `call=1` 经分派表进入 `0x5BC07E`，即 ReadProperty；`args[0]` 为调用方提供的 4 字节 int 输出地址。`local_id=11` 读取 width，12 读取 height，20 读取 minimumHeight，22 读取 maximumHeight。它们是 QWidget 自身的本类属性 index，不是派生类累计属性 index。width/height 分支在函数内直接读取 geometry 并写 int，没有单独 getter 调用，因此应调用完整 MOC wrapper，不能从 `0x5BCD63` 或 `0x5BCD9E` 的中间分支开始执行。这个路径只读取属性，未发现修改控件操作；仍应在已验证的 UI 线程上读取有效、尚未销毁的 QWidget 实例。

**2026-09-23 临时 fixture 复审。** 本轮只读取 `native_view_fixture.js` / `run_native_fixture.py`，执行 Node 的 `--check` 与 Python AST 解析，没有附加微信或调用任何上述原生入口。QString 构造 `0x27F80(out8, utf8, byte_length)` 和销毁 `0x14E0(QString*)` 的搭配、MOC 宽高读数及新加的 `visible` 读取与静态证据一致；`visible` 是 QWidget 自身属性 index 35，结果为 bool，因此读输出缓冲区第一个字节正确。注意 visible 不等于控件矩形与聊天视口相交，仍可能选到被父级裁剪的控件。

最新生命周期修复有效：写入前登记恢复记录；已修改对象不再被 100 项观察缓存淘汰；关联 binding 指针变化会使目标失效；恢复失败保留监听并报告 `stop_pending`；只有真正 `stopped` 的独立事件才结束宿主等待，普通 operation_error 不会冒充停止完成。脚本为每次观察保存 epoch，并校验主 vtable、owner/label 双向关系、binding 与 GUI 线程。上述检查降低复用和过期指针误用，不能证明所有 native 生命周期竞态已经在真实控件上排除。

宿主最终仍有有界失败出口：重复恢复仍未完成时，finally 会卸载/分离，并记录 `restore_confirmed=false` 和失败结果；这不等于已恢复成功。遇到 invalid/stale 对象时脚本不会向旧地址强行写回，而是放弃旧恢复记录。复审后宿主已把结果拆为 `write_restore_passed` 和 `geometry_grew`：前者要求一次写入、一次恢复及无脚本错误，后者同时要求 label 与 owner 的 after.height 大于 before.height；最终 `passed` 还要求卸载和分离成功。`visual_review` 明确保持 pending，几何增加不能取代相邻消息不重叠、位置正确及恢复完整的截图/人工验收。本轮已重新读取并确认上述最新判断分支。

如果 label 已增高但 owner 没变，当前唯一可证明为普通 QWidget 重排请求的完整入口是 **`void updateGeometry(QWidget*)`，RVA `0x5B4950`，RCX 为有效 QWidget**；该入口取 `this+8` 私有对象，以第二参数 0 跳至 `0x5ABBB0`。它请求父布局失效，并非同步强制算出列表行高；setter 已经对 label 调用它，重复调用 label 不能保证解决列表缓存问题。可以把容器/owner 的重排作为后续独立有界实验，但本轮没有建立“依次调用即一定成功”的契约。`0x5B6470` 是普通 QWidget sizeHint 读取：从 QWidget 私有对象 `+0x78` 取 layout，再调用 `0x5996C0` 写 QSize；它只是尺寸提示读取，不应误当 refresh。

因此本轮保留明确待验证项：实际 fixture 的 before/after owner 行高、相邻行移位和恢复；若失败，再沿 `0x1BDA810 → 0x3CF2250 → listener.vtable+8` 确认具体 RecyclerListView 观察者实现。此回调链目前不能作为已核实的强制刷新 API，也没有依据直接改写 `+0x4D8` 或调用选择恢复 slot。相关最小读取证据见 `layout-disassembly-1bc6490-5b6470.json`。
