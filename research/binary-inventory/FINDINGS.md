# Weixin 4.1.15.11 静态二进制线索

读取范围：`C:\Program Files\Tencent\Weixin\4.1.15.11` 中的 29 个安装文件；未加载这些 DLL，未读取运行中进程、聊天数据库或密钥，也未修改安装目录。所有 RVA 仅适用于下面这份精确散列的 DLL。

## 模块与可读资源

- 19 个 x64 PE、3 个 x86 PE、7 个归档或配置文件。逐文件尺寸、架构、SHA-256 见 `modules.csv`；标准/延迟导入、导出、节表、资源树见 `inventory.json`。
- 核心 `Weixin.dll`：201,546,288 字节，x64，image base `0x180000000`，SHA-256 `7d056cf7fb834b5558d6646bfb4e0036aae93568e3f9a04cf1dfc5e79032bcac`。
- 核心 DLL 有 117 个导出，主要属于 mmcronet；其余包括 `WeChatMain`、`SetWeixinCallbackFunc`、`HostStartupExceptionReport`。未发现命名为 `AddLocalMsg`、`InsertSysMsg` 或 `InsertMessage` 的导出函数。
- 标准导入表只有 KERNEL32；还有 39 个延迟导入库，包括 USER32、OLEACC、dwmapi、mmcronet 和内部组件。因此不能把“普通导入表只有 KERNEL32”误判为没有窗口/组件依赖。
- Qt 静态元数据存在：`.qtmetad` 的 `QTMETADATA` 插件头标明主次版本 5/15，包含 QWindowsIntegrationPlugin、QWindowsVistaStylePlugin、QJpegPlugin 等；另有 `.qtmimed`。业务 QWidget 类的 Qt 5 MOC 元数据可直接解码。
- 目录没有独立 Qt DLL、QML、QRC 或 RCC 文件。`.rsrc` 是图标、版本与 manifest。六个 `.bin` 实际是 ZIP 包，主要装载小程序运行时、OCR 模型、媒体/编辑器组件；已只读枚举中央目录，没有安装/运行其中内容。未见可直接编辑的聊天历史 QML 文件。`QQuickWidget` 字符串本身不足以证明微信聊天列表由可替换 QML 驱动。

## 本地原生消息相关字符串

这些是可供反向交叉引用的静态字符串，不是已确认的函数入口。

| 字符串 | Weixin.dll RVA |
|---|---:|
| SystemMessageHandler | `0x9505558` |
| SystemMsgContext | `0x9a77f50` |
| sysmsg | `0x8e035e4` |
| sysmsgtemplate | `0x8ec5ff8` |
| sysmsg XML（subtype + content） | `0x8ec6096` |
| sysmsg XML（type + content） | `0x97ef446` |
| revokemsg | `0x8ec83d0` |
| MessageManager | `0x8f8a788` |
| MessageService / FMessageService | `0x8f8ab90` / `0x8f8ac30` |
| Init ChatMessageStorage | `0x9408670` |
| HistorySysMsgInfo | `0x94085e0` |
| FMessageTable | `0x9421c58` |

`native-string-leads.json` 收录 117 条相关命中，包含文件偏移和 RVA。精确名称 `AddLocalMsg` / `InsertSysMsg` 没有命中；这不表示内部不存在该能力。

## InsertMessage 的 Qt 元数据与静态调用链

已成功解码类名、方法表、参数类型、信号/槽类别及 static_metacall：

| 类 | InsertMessage 类型 | 参数 | staticMetaObject RVA | qt_static_metacall RVA |
|---|---|---|---:|---:|
| mmui::ChatInputView | public slot，局部方法 index 11 | kernel::MessageWrapper | `0x8e7ac68` | `0x88d2e0` |
| mmui::MessageView | signal，局部方法 index 2 | kernel::MessageWrapper | `0x8e7afa8` | `0x88d9f0` |

- ChatInputView 的 moc switch 在 `0x88d3ec` 处理 index 11，读取 Qt 参数数组后，于 `0x88d40c` 跳转到真实槽函数 `0x1bf9ee0`。
- 槽函数边界是 `[0x1bf9ee0, 0x1bfa046)`；在条件满足时从对象 `+0x2a0` 取内部成员，并于 `0x1bf9f31` 把 MessageWrapper 交给 `0x3d9ddb0`。
- MessageView 的信号函数是 `0x88dfa0`。同一连接设置函数 `[0x1c241f0, 0x1c25374)` 内，`0x1c249fb` 取得上述 input slot 地址，`0x1c24a13` 取得此 signal 地址。代码因此支持“MessageView 信号连接到 ChatInputView 槽”的解释。
- 邻近同类槽是 InsertMention、SetReferMessage、Send；这条链指向输入视图处理已有 MessageWrapper。它**不能仅凭 InsertMessage 这个名字就被认定为聊天历史本地消息写入**。引用、重编辑等语义仍需进一步确认；本轮没有执行调用。
- 参数是内部 C++ 对象，不是单纯字符串。尚未确认其构造、引用计数、对象实例及线程上下文，不能把上述 RVA 当作已经验证的文本插入 API。

`ChatMessagePage` 的 MOC 方法表没有 InsertMessage；它包含导航高亮、会话重载、选择变化等方法。`ChatBotSystemMessageItemView` 只显示其类元数据，没有该类自身的 moc 方法。

## 可复核文件

- `inventory.py` / `inventory.json`：29 个安装文件只读清单、PE 解析、目标字符串、ZIP 条目。
- `modules.csv`：简明模块表。
- `qt_metadata.py` / `qt-metadata.json`：Qt 5 QByteArrayData 字符串表、QMetaObject 和方法元数据解码。
- `qt-static-metacalls.txt`：两个 moc 分发函数反汇编。
- `trace_qt_insert.py` / `qt-insert-slot.json` / `qt-insert-slot.txt`：真实 input slot 的静态反汇编。
- `qt-insert-forwarded.json`：下游处理函数的静态反汇编。
- `qt_xrefs.py` / `qt-insert-xrefs.json`：信号/槽地址的 RIP-relative 与直接分支交叉引用。

当前最明确成果是识别出内部消息管理/存储/系统提示线索，以及排除误把输入区 InsertMessage 当成历史插入接口的捷径。针对本地历史消息写入，应继续确认存储层或系统消息生成链；本轮没有做任何实际消息插入验证。
