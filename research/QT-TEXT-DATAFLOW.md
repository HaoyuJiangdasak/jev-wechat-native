**微信 4.1.15.11 原生文字：构造、清理及模型数据流**

2026-09-23。仅静态读取 `Weixin.dll`，SHA-256 `7d056cf7fb834b5558d6646bfb4e0036aae93568e3f9a04cf1dfc5e79032bcac`。本文所有地址为 RVA，不是运行时绝对地址；本子任务未附加微信、读取真实消息或执行以下函数。主任务的运行观测另有报告。

**QString 构造/清理：已核对机器码**

| 功能 | RVA | Windows x64 参数 | 限定 |
| --- | --- | --- | --- |
| UTF-8 → QString | `0x27F80` | RCX=可写 8 字节 QString 对象槽，RDX=UTF-8 字节指针，R8D=非负字节长度；RAX 返回 RCX | 长度为 UTF-8 字节数，不是 UTF-16/JS 字符数，不包括终止 NUL；这里不处理 -1 长度 |
| QString 析构 | `0x14E0` | RCX=上述 QString 对象槽；无返回值需求 | 只对成功构造的对象执行一次；不会清空槽，之后不能再次使用或再次析构 |
| 底层 data 释放 | `0x38930` | RCX=data，EDX=元素大小 2，R8D=对齐 8 | 不是 QString 析构函数，不可跳过引用计数直接调用 |

`0x27F80 → 0x2C4A00 → 0x2C4AA0` 分配 Qt 字符数据，把输入解码到 UTF-16；后者包含 UTF-8 BOM `EF BB BF` 与多字节处理，不是 Latin-1 拷贝。`0x2C4A00` 依据实际 UTF-16 输出长度调整 QString 长度。输入指针为空时 `0x27F80` 写入静态空数据 `0xB039B50`。

`0x14E0` 读取 `[QString]` 得到 data，然后检查 data 首 DWORD 引用计数：`-1` 为静态数据，不释放；`0` 进入释放；其他值用 `lock dec`，只有归零才尾调用 `0x38930(data,2,8)`；返回指令位于 `0x1509`。这是完整清理流程，和正文调用点内联析构相同。

另一个 helper `0x27E30(char*,int)` 返回 data 指针，并包含长度 `-1` 时 strlen 的逻辑；它和带输出参数的 `0x27F80` ABI 不同，不能混用。临时 QString 对象的 8 字节外壳可由调用方保存，payload 必须由 Qt 这条构造/析构链管理。

证据：`layout-disassembly-27f80-27e30-38930.json`、`layout-disassembly-14e0.json`、`storage-wrapper-0x2c4a00.asm.txt`、`storage-wrapper-0x2c4aa0.asm.txt`。leaf 导出器遇到尾跳转结束，所以 `0x1509` 的 ret 另由磁盘字节/反汇编确认。

**原消息到 XTextView 的路径**

`ChatTextItemView` 的实际文字更新入口为 `0x1BC6490(this, QString*)`。入口 RDX 保存到 RDI；普通分支 `0x1BC6C4A..0x1BC6C59` 将原 QString 指针传给 `0x1E80D40(this->field_508, QString*)`，与主任务报告的 caller RVA `0x1BC6C59` 相符。该更新函数还有富文本分支，经过 `0x1E80CB0` 或 XTextView vtable `+0x180`；只观察普通 QString setter 不保证覆盖所有富文本状态。

上游 `0x1BC5590` 使用如下关系：

```text
ChatTextItemView +0x250 / +0x258 = shared binding 的对象 / 控制块
  -> 0x1BC5E20(this, output_shared_ptr)
     dynamic_cast(SourceTypeDescriptor 0xB2D1910, TextInterfaceTypeDescriptor 0xB2D1C80)
  -> TextInterface vtable +0x28(interface, output_QString)
  -> 0x1BC6490(this, QString*)
  -> 普通分支 0x1E80D40(XTextView*, QString*)
```

`this+0x378` **不是消息模型**，是 `ChatBubbleFrame*`。`0x3CE56A0` 读取此指针，`0x1BDBDE0` 读取 frame `+0x1C4`；该值是框构造时传入的样式 bool，受调用参数和 item `+0x308` 共同影响，不能直接作为 isSender。构造器/Qt 元对象证据见 `binary-inventory/sender-flag-constructor.json` 与 `sender-flag-callers.json`。

**具体文字 binding 候选及收发判断**

通过 MSVC RTTI COL/CHD/BCD 静态复原，普通文字候选 type descriptor `0xB2D1950` 有以下子对象：

| 子对象 | 相对完整对象 | vtable RVA | 关键槽 |
| --- | --- | --- | --- |
| source binding | `+0x10` | `0x956B278` | `+0x20 → 0x5C41810` |
| text interface | `+0x5F0` | `0x956B548` | `+0x28 → 0x3D00D20` |

这些是具体候选的布局，**调用方必须先核对当前 binding 的 vtable/RTTI，不能把偏移推广到所有子类型**。`text-binding-rtti.json` 中还有历史/特殊文字模型候选；有的 text interface 偏移为 `0x5A8`。

对上述普通候选，`0x3D00D20` 先从 text interface 减 `0x5E0` 得 source binding，再由 leaf `0x3B4DD0` 得到 `binding+0x120` 的内嵌 UI message。普通正文读取该 UI message 的 `+0xE0` UTF-8 string（size `+0xF0`，capacity `+0xF8`），然后调用 `0x27F80`。该 getter 在某些消息子类型分支会从扩展对象提取文本，所以原始 +0xE0 不能覆盖所有分支。

**明确的 self-sent 路径**是 source binding vtable `+0x20 → 0x5C41810`，它 `RCX += 0x120` 后跳到 `0xA19E60`。后者：

- 若 UI message `+8` DWORD 为 `10000`，返回 false；若 `+0x10` 字符串为空，返回 false。
- 通过 `0x45D10()` 的对象 vtable `+0x20` 取得账号自身标识字符串。
- 将 UI message `+0x10` 字符串与自身标识比较，相等返回 true，否则 false。

因此 true 有“发送者是自己”的直接语义证据；false 同时包含系统类型和字段为空，**不能无条件解释成对方**。分析条件仍应要求普通文字类型、非空正文、成功识别 binding、有效会话身份，再排除 self-sent。

这套 UI message 的 type 在 `+8`、参与者字符串在 `+0x10`，和 CoAdd 存储对象的 type `+0x0C`、字符串 `+0x18` 不同；两份布局不能混用。会话标识/接收者字段尚未完成语义核准，不在本文给出猜测性偏移。

**复用与异步显示边界**

在得到经过核准的 conversation key 之前，不应把不同消息串成全局上下文。一次分析应捕获 owner、`owner+0x250` binding 指针、正文指纹及绑定 generation。应用结果前须在 UI 线程重新验证全部信息，同时检查 `owner+0x508 == label` 与 `label+0x410 == owner`；绑定或正文更新递增 generation，销毁时删除状态。只按 owner 地址缓存会把回收控件中的旧结果显示到新消息上。模型指针也可能被复用，必须与正文/消息身份及 generation 合并验证。

本报告给出了可继续验证的 getter、构造、析构和 self-sent 逻辑，没有宣称已完成运行兼容性或跨会话识别。

**只读候选规则与会话字段的边界**

`text-binding-static-candidates.json` 将 RTTI 中 8 个 source binding 子对象的 vtable、text interface 偏移与 getter 对应起来；8 个 source 子对象的 `+0x20` 槽都精确指向 `0x5C41810`，但 text getter 并不全部相同。该清单只是静态白名单候选，不是对运行对象的观测结果。以实际 `owner+0x250` 的 vtable 匹配清单后，才有依据读取该 binding 的内嵌 UI message `+0x120`；未匹配应跳过分析。

对于已匹配对象，可只读核验 UI message `+8` 类型及 `+0x10` sender std::string，并要求类型为普通文字、sender 非空、正文非空。std::string 为 32 字节 MSVC 布局：size 在 `+0x10`、capacity 在 `+0x18`，capacity 小于 16 时内容在对象内，否则首指针指向内容。应验证 size 不大于 capacity、长度上限与可读范围；文本按 UTF-8 解码。实际正文应使用已观测的 QString getter/setter 数据，而不是跨类型直接读取 `UI message+0xE0`。

暂未证实两端 ID 的完整对应，不能把相邻字符串当作“发送者 / 接收者”然后猜会话。具体排除如下：

- source vtable `+0x38 → 0x22301B0` 返回 `binding+0x170`，即 UI message `+0x50` 字符串；`0x5C3C6C0` 又把此字符串交给 `0xB9E350` 和当前账号 ID 比较，可能是另一层 sender 身份，尚不能称为 conversation key。
- source vtable `+0x40 → 0x3CF16E0` 返回的是 `0x209C50()` 取得的全局静态字符串副本，完全不读取 binding；因此不能作为该条消息的会话 ID。
- source vtable `+0x58 → 0x1A57D50` 返回 `binding+0x130`，即 UI message `+0x10` 的 sender 字符串，和 self-sent 判断来源一致。
- source vtable `+0x88 → 0x5C3D920` 拷贝 `binding+0x190`，即 UI message `+0x70` 的字符串；目前没有会话语义证据。

后续最小运行核验只需报告 binding vtable RVA 及类型计数，不需要保存任何 ID 或正文。上述“无可靠 conversation key 就不合并上下文”和 generation 校验仍是必要边界。原生显示 fixture 的成功不能替代收发 / 会话身份核验。

补充静态证据：`layout-disassembly-5c41810-22301b0-5c3c6c0-3cf2a80.json`、`layout-disassembly-3cf16e0-5c3cd50-1a57d50-5c3d460-5c4bb10-5c45e20-5c3d6e0-3cf17f0-5c3d920.json`、`layout-disassembly-209c50-37c820-a17160.json`。

**第二轮构造路径核验与收束（静态）**

普通候选完整 binding 构造器为 `0x3CFF540(complete, listener, UIMessage*, bool)`：它先构造 QObject，再在完整对象 `+0x10` 调 `0x5C7D4A0`，后者调 `0x5C3C210`。这些构造器逐层保留 RDX 传入的 listener 和 R8 传入的 UIMessage 指针。`0x5C3C210` 在 source binding `+0x120` 调 `0xA58F00` 默认构造 UIMessage；随后通过 vtable `+0x1A8` 更新该 UIMessage。

基类 `+0x1A8 → 0x5C3DE20(binding, UIMessage*)` 在 `0x5C3E218..25` 精确执行 `0xA2BDC0(binding+0x120, supplied_UIMessage)`。后者是逐字段赋值：`+8` 类型/子类型整体复制、`+0x10/+0x30/+0x50/+0x70` std::string 深拷贝。普通文字 override `0x3D01B40` 在 `0x3D01C85..8B` 调该基类更新，再处理文字专属变化。因此 `+0x30`、`+0x70` 的存在和复制已核实，但复制流程本身没有揭示其身份语义；不能据此宣称任何一个是 conversation key。

上层上下文的可信追踪入口是 source binding `+0xD0`：`0x3CF0E40(binding, listener)` 在 `0x3CF1011` 将原始 RDX 保存到此处，未作字符串/消息字段推导。结合 `0x3CF2250` 的 listener vtable `+8(listener,binding)` 通知路径，下一步可据 listener 的实际 vtable/RTTI 追溯列表或会话拥有者。当前证据只证明“构造传入的监听/上层上下文指针”，尚不能把该指针本身当作稳定会话 ID。需要检查它是否跨聊天复用。

本轮未确认 conversation key，也未确认稳定消息 ID。没有给出 `+0xC8`、`+0xD0` 等整数偏移的猜测性 ID 名称。停止继续扩大扫描，下一次最小运行核验建议只收集：

1. 有可见普通文字气泡时，记录 `owner+0x250` binding vtable RVA、`binding+0x120` UIMessage vtable RVA、type 计数。
2. 对已匹配 binding，记录 `binding+0xD0` 的 vtable RVA，并在内存内统计同一聊天的多条消息是否共用这个 listener；仅保存计数/布尔值，不落盘指针、账号 ID 或正文。
3. 用户切换两次聊天后，统计 listener 是否更换或复用；其 vtable 可再用于定位上层会话对象。它若复用，必须继续找其当前 session 属性，不能用 listener 地址做 conversation key。
4. 对 sender/`+0x30/+0x50/+0x70` 只比较“是否等于自己、是否在当前会话内跨收发保持一致”的布尔量。此步骤只提供运行一致性证据，仍需消费调用点或语义验证后才能启用多条上下文。

证据文件：`layout-disassembly-3cff5a0-3cffea8.json`、`layout-disassembly-5c7d4a0.json`、`layout-disassembly-5c3c210.json`、`layout-disassembly-3cf0e40-a58f00.json`、`layout-disassembly-5c3de20-3d01b40.json`、`layout-disassembly-a2bdc0.json`。新脚本 `scan_ui_message_fields.py` 是有界磁盘扫描，并覆盖 disp8 字段编码；未附加进程、未执行目标代码。

**实际类型到会话过滤键（第三轮，已找到静态路径）**

本节更新前两轮会话字段未知的结论。主任务提供的 `native-fixture-result.json` 记录 13 次普通消息更新：source binding vtable 均为 `0x956B278`，type 均为 1，listener vtable 均为 `0x95884E8`，该次采样内 listener 对象基数为 1。该运行结果由主任务生成；本研究仍仅读取静态 DLL 及计数文件。

对实际 listener vtable `0x95884E8`，MSVC COL 的 `offset` 精确为 0，完整 type descriptor 为 `0xB2F8DF0`，因此它是完整对象指针，以下 `+0xA0` 无须减去继承偏移。RTTI 名称在磁盘上不可读，未伪造 C++ 类名。见 `vtable-inspection-95884e8.json`。

会话过滤键的可信数据链是：

```text
owner+0x250 -> source binding (vtable 0x956B278)
  binding+0x120 -> embedded UIMessage
  binding+0xD0  -> listener (vtable 0x95884E8, COL offset 0)

UIMessage +0x70 std::string == listener +0xA0 std::string
```

这里的等式来自程序自身的消息过滤条件，而非仅凭字段位置猜测：

- `0x3E2B8E0(predicate, UIMessage*)` 在栈 `+0x20` 调 `0x1A5B50` 复制消息，再将复制消息 `+0x70`（栈 `+0x90`）与捕获的 listener `+0xA0` 比较 size 和全部字节；返回是否相等。`0x3E2BAB0` 是同样的比较，消息副本在栈 `+0x28`，因此 `+0x70` 位于栈 `+0x98`。
- `0x1A5B50(out, original)` 写 UIMessage vtable `0x8D9C978`，复制 `+8` 类型和同偏移字符串，包括 `+0x70`；该布局与 `0xA58F00` 默认构造器一致。因此过滤代码比较的确实是已定位 UIMessage 的 `+0x70`，不是另一种结构的同数值偏移。
- `0x3E28DE0(listener, owned_string)` 将输入字符串复制至 listener `+0xA0`，并销毁输入临时 string；此函数有所有权副作用，**仅作为静态语义证据，不应为读取键而调用**。
- 实际 listener 的初始化/切换方法 `0x3DE5E90` 保留入口 RDX 字符串，在 `0x3DE66E5..0x3DE67A1` 原样复制并交上述 setter。相同入口字符串首先经过特殊会话分类：`0xB9D850` 精确比较 `qqmail`，`0xB9E2A0` 精确比较 `notifymessage` 等通知会话，`0xB9D4A0` 比较 `newsapp`。这为该字符串是聊天会话用户名/路由键提供了额外语义证据。

建议运行实现仅**读取**这两处 std::string，核对两处值非空、长度/capacity 合法并且全等后，使用该相同值作为不展示的 opaque conversation key；未匹配上述 vtable、类型不对、任一字符串畸形、空值或不相等均跳过。不应使用 listener 地址本身作为 key，也不需要读取不明字段 `+0x30/+0x50` 或 listener `+0x58`。

启用多条上下文前的最后运行验证：同一单聊的自己/对方消息两处键均相等且共同一个值；切换另一聊天后值改变，再切回原聊天值恢复。只输出字段非空/相等计数、角色覆盖、会话键基数及切换布尔结果，不输出实际 ID。静态链已充分确定该比较键，但这些运行一致性检查截至本报告尚未回传。消息本身的稳定 ID 仍未恢复；继续保留 owner/binding/原正文指纹/generation 校验，不能用会话键代替消息身份。

证据：`layout-disassembly-3e28de0-3e2b8e0-3e2bab0.json`、`layout-disassembly-1a5b50-3de5e90.json`、`layout-disassembly-3de7b10-b9d850-b9e2a0-b9d4a0.json`、`text-dataflow-calls-1a5b50-3e28de0.json`。`inspect_native_vtable.py` 可从版本固定的磁盘 DLL 重现 COL/base/slot 解析。
