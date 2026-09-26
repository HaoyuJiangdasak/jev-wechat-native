**Windows 微信 4.x 本地分析消息：可继续验证的源码线索**

2026-09-22；目标版本 4.1.15.11。本轮仅读取公开源码，未运行下载的代码、注入进程、修改客户端，未读取本机聊天数据库或密钥。下面的偏移和对象字段都是公开项目的历史版本证据，不是当前版本的已验证调用参数。

**本轮进展**

找到了比发送 API 更直接的 Windows 4.x 本地写入路径：`EEEEhex/RevokeHook` 定位 `CoReplaceOriginMessageByRevoke`、`DeleteMessages`、`CoAddMessageToDB`，在微信已有的撤回处理流程中，让提示使用新的 SrvID 写入本地记录。`zetaloop/BetterWX` 使用同一方案，并明确提示出现在对应消息下方。

这已提供具体函数名称、字符串特征、PE 静态定位方法、CALL 位置和历史消息布局。尚缺“独立构造任意分析消息并即时刷新”的完整可调用适配；不能把防撤回期间修改已有对象等同于一个随时可调用的 `InsertLocalMessage(text)` API。

源码快照在 `source-notes/`，下载记录见 `source-notes/sources.json`。文本源码使用 `.txt` 后缀保存，未执行。研究基线沿用 aixed，另外扩展了 5 个潜在来源；最终有效主线是 BetterWX → RevokeHook。

**1. 首选静态定位路径：RevokeHook**

固定 commit：`ffb6a899b50ee3e11b4dfbae93d7fde4058f7014`。

| 证据 | 可以复用的分析内容 | 固定来源 |
| --- | --- | --- |
| Config3.json | 4.1.1.00、4.1.7.00 三组加密字符串的精确字节 | [配置](https://github.com/EEEEhex/RevokeHook/blob/ffb6a899b50ee3e11b4dfbae93d7fde4058f7014/Config3.json) |
| CallChainSearchService.cs | `.rdata` 字符串 → `.text` LEA 引用 → `.pdata` 函数区间 → 3 层直接调用图 | [搜索实现](https://github.com/EEEEhex/RevokeHook/blob/ffb6a899b50ee3e11b4dfbae93d7fde4058f7014/RevokeHookUI/RevokeHookUI/Services/CallChainSearchService.cs#L76) |
| MainWindow.xaml.cs | 明确保存的是哪一级 CALL 指令 RVA | [结果回填](https://github.com/EEEEhex/RevokeHook/blob/ffb6a899b50ee3e11b4dfbae93d7fde4058f7014/RevokeHookUI/RevokeHookUI/MainWindow.xaml.cs#L164) |
| Config2.json | 4.1.7–4.1.10.24 的历史 CALL 地址和结构字段 | [历史配置](https://github.com/EEEEhex/RevokeHook/blob/ffb6a899b50ee3e11b4dfbae93d7fde4058f7014/Config2.json) |
| dllmain.cpp | 在本地入库 CALL 前如何读取参数、改 SrvID 和提示文本 | [Add2DB 分支](https://github.com/EEEEhex/RevokeHook/blob/ffb6a899b50ee3e11b4dfbae93d7fde4058f7014/RevokeHook/RevokeHook/dllmain.cpp#L569) |

`Config3` 的三个名称映射已经由搜索源码确认：

- `sig1` → `CoReplaceOriginMessageByRevoke`
- `sig2` → `DeleteMessages`
- `sig3` → `CoAddMessageToDB`

可直接对照实现的静态定位步骤：

1. 在 PE `.rdata` 搜索三组精确字节，不需要先把字符串解密。
2. 找到 `.text` 中目标指向这些字节的 RIP-relative `LEA`；目标 RVA 为 `instruction_rva + 7 + signed_disp32`。
3. 用 PE Exception Directory / `.pdata` 的 `RUNTIME_FUNCTION` 区间取得每个 LEA 所属函数，保留所有候选，不因首个命中就认定唯一。
4. 从 `CoReplaceOriginMessageByRevoke` 候选搜索最多 3 层直接 CALL 图，到 `DeleteMessages` 的 root CALL 前 0x100 字节内须出现参数置零，并在逆序检查时遇到前一个 CALL 即停止。
5. 从同一 origin 搜索到 `CoAddMessageToDB` 的调用链，其 root CALL 必须位于删除链 root CALL 之后。
6. 保存整个调用链和反汇编证据。上游有“首个部分匹配”回退，适配器不应把部分链或多候选当成已验证签名。

**地址种类不能混用。** `MainWindow.xaml.cs` 第 166 行保存 `DelMsgOffset = DeleteMessagesChain.RootCallRva`；第 178 行保存 `Add2DBOffset = AddMessageToDbChain.TargetCallRva`，即最后一层直接调用 `CoAddMessageToDB` 的 **CALL 指令地址**。它们不是可直接调用的函数入口。要得到函数入口，仍需解码该 CALL 的目标。

**2. 消息参数和结构：已知证据与未知边界**

`dllmain.cpp` 当前 Add2DB 分支在 CALL 发生前读取第 3 个参数（R8），当作消息结构；在第 3–8 个参数中启发式查找零值布尔项；从消息对象内查找含“一条”或“a message”的 `std::string`，再查 SrvID。它随后生成新的正数 SrvID、改写提示的短语，并把该布尔参数置为 1。

这不是稳定 C++ ABI 定义。新版本通过启发式搜索是因为字段会移动，不能把它直接改成未经验证的固定函数指针。

| 公开配置版本 | Add2DB CALL RVA | 参数角色 | SrvID / XML 字段偏移 |
| --- | --- | --- | --- |
| 4.1.7.59 | `0x32DE4C6` | arg3=消息，arg5=布尔 | `0x108` / `0x180` |
| 4.1.8.107 | `0x3380286` | arg3=消息，arg5=布尔 | `0x108` / `0x160` |
| 4.1.9.55 | `0x34A43DB` | arg3=消息，arg5=布尔 | `0x148` / `0x1A0` |
| 4.1.10.24 | `0x35ACC9B` | arg3=消息，arg5=布尔 | `0x148` / `0x180` |

同一配置中 4.1.10.24 的 DelMsg CALL RVA 是 `0x234AD6E`。这些地址只用于定位邻近版本的调用关系，不能写入当前 4.1.15.11 的适配表。

代码使用的字符串布局是 16 字节内联缓冲区/指针区域、8 字节 size、8 字节 capacity，总计 0x20。当前查找器只接受 size > 16 的长字符串；这不能证明任意短消息构造方式。长度、分配器、析构和所有权仍须验证。

上游 `GetArgValue` 中的第五参数位于 `[RSP+0x20]`，因为断点位于 **CALL 前**。Windows x64 真正函数入口已经压入返回地址，第五参数应按入口栈布局考虑 `[RSP+0x28]`。移植时不能混用现场。[参数访问代码](https://github.com/EEEEhex/RevokeHook/blob/ffb6a899b50ee3e11b4dfbae93d7fde4058f7014/RevokeHook/RevokeHook/dllmain.cpp#L302)

需要进一步恢复的角色包括 arg1/arg2/arg4、可能新增的后续参数、完整消息类型和会话字段、协程/线程上下文、返回值/异步结果、构造及销毁路径。`Co` 前缀本身不是协程 ABI 的证明。

**3. 可用于交叉验证的较旧机器码特征**

`Config2.json` 针对 4.1.9.30 给出的 Add2DB wrapper 特征：

```text
48 83 EC ?? 4C ?? ?? 48 ?? ??
C6 44 24 ?? 01 C6 44 24 ?? 00
4D ?? ?? 49 ?? ?? E8 ?? ?? ?? ??
48 ?? ?? 48 83 C4 ??
```

配置把匹配起点加 `0x1A` 作为 CALL 位置。该特征可用于当前版本的只读候选扫描和反汇编检查；不意味着字节命中就能调用或修改。

较旧 `BetterWX/revoke.py` 的注释给出语义链：

```text
AddRevokeTipToDB
  -> AddMessageToDB_Arg0(...)
  -> CoAddMessageToDB(a1, a2, a3, a4, 0)
```

该脚本跳过原消息删除、给提示使用不同 SrvID，并把入库参数 0 改成 1，以允许新 ID。[固定源码](https://github.com/zetaloop/BetterWX/blob/f3c5f7927ba5014d22e50d8d25b524f2a823d56b/revoke.py)

BetterWX README 指定 Windows 4.0.6.26，并明确其提示刷新有限制：远程撤回需要重新进入聊天才出现；自己撤回时保留的原消息也可能需要重新进入才刷新。**本地入库成功和实时渲染是两个需要分别验证的环节。** [固定 README](https://github.com/zetaloop/BetterWX/blob/f3c5f7927ba5014d22e50d8d25b524f2a823d56b/README.md)

**4. aixed：作为消息构造对照，不作为本地插入入口**

固定 commit `e905d07ade50d2c6472e4eb3bd4f3fe19cf662c6` 的 `src/wx_send.cpp` 显示：

- `BuildTextMessage(uint64_t* ptr, const std::string& text, const std::string& wxid)` 初始化消息，构造地址为 `Weixin.dll + txt_message_ctr`，消息类型为 1。
- `SendText` 包装对象后调用 `send_message(arg1, arg2)`；共享声明使用通用转换，不能据此认为已恢复准确的底层函数签名。
- `TextMessage` 的公开布局包含 receiver=`0xB0`、type=`0xD8`、content=`0x708`，但它是发送流程对象，和 RevokeHook 的入库对象没有证明为同一类型。
- `include/global.h` 对其目标 4.1.10.27 给出 `txt_message_ctr=0x6B2C30`、`txt_message_vtbl=0x8279358`、`send_message=0x1677A30`。这些可作为旧版本反汇编对照；不能用更换 type 或跳过网络函数的猜测来声称本地插入成立。

[消息构造与发送源码](https://github.com/aixed/WeChat-Hook/blob/e905d07ade50d2c6472e4eb3bd4f3fe19cf662c6/src/wx_send.cpp#L409)、[字段布局](https://github.com/aixed/WeChat-Hook/blob/e905d07ade50d2c6472e4eb3bd4f3fe19cf662c6/src/wx_send.cpp#L134)、[偏移定义](https://github.com/aixed/WeChat-Hook/blob/e905d07ade50d2c6472e4eb3bd4f3fe19cf662c6/include/global.h)

**5. 其他来源的取舍**

| 扩展来源 | 核查结果 |
| --- | --- |
| [CsOH-Lawrence/RevokeMsgPatcher_NewWechatUpdated](https://github.com/CsOH-Lawrence/RevokeMsgPatcher_NewWechatUpdated/tree/69706db46f04238197465ea680fd9c580d94ee83) | 公开 `patch.json` 有 4.1.12.0 起的防撤回特征，也有旧版入库 bool 修改；没有据此恢复出可调用的任意文本插入接口。版本范围不能当成当前兼容性验证。 |
| [CrackerCat/wechat_anti_revoke](https://github.com/CrackerCat/wechat_anti_revoke/tree/d4e9fb729958e461a514c8d0d288a22c3526829c) | README 的安装示例为 3.9.12.37，描述修改撤回 XML 的方案；没有成为本轮 4.x 独立插入路径。 |
| [afaa1991/BetterWX-UI](https://github.com/afaa1991/BetterWX-UI/tree/6c6237529bf6aa2a1b4ea30ecc3156ec5264395d) | 本次固定版本只剩“已移除的项目”，没有可复核实现。 |
| [zetaloop/BetterWX](https://github.com/zetaloop/BetterWX/tree/f3c5f7927ba5014d22e50d8d25b524f2a823d56b) | 指向原始 RevokeHook，并提供本地提示入库及刷新限制的证据。 |
| [EEEEhex/RevokeHook](https://github.com/EEEEhex/RevokeHook/tree/ffb6a899b50ee3e11b4dfbae93d7fde4058f7014) | 最有用的公开原始实现，提供调用链、配置、对象现场的分析依据。 |

RevokeHook README 引用的作者[逆向文章](https://bbs.kanxue.com/thread-286611.htm)本次返回网关 504，未将未读文章内容用作结论。上述技术细节来自已成功读取的固定 GitHub 源码。

**可继续验证的具体交付物**

下一步只读静态分析应产出当前 4.1.15.11 的三个函数候选、每条 LEA 引用、`.pdata` 范围、完整直接调用链及最终 Add2DB CALL 的前后指令，连同客户端文件哈希保存。先核实消息参数怎样被使用，再向上追创建本地系统提示对象的函数，向下追入库后通知会话模型/界面刷新的路径；明确排除 SendText/SendXML 分发路径。

这些静态结果能判断是否有足够依据实现“本机分析消息适配器”。截至本报告，独立原生插入、当前版本 ABI、立即刷新和完整不外发属性仍未经过运行验证。
