# 跨版本重新定位（reanchor）

微信会自动升级，并删除旧版本目录。任何把地址写死在源码里的做法，都会在升级后失效 ——
而且是在错误的地址上读写内存，后果比直接崩溃更糟。

本项目的做法是：**地址不写在源码里，而是写在 `app/native_anchors.json`** ——
一份针对某一个具体 `Weixin.dll` 解出的「语义地址表」。升级后重新解一次即可，
不需要改任何适配器代码。

本文说明这套定位是怎么做出来的，以及为什么它能跨重新编译（recompile）成立。

---

## 一、为什么旧地址不能直接用

拿 4.1.15.11 的 46 个函数锚点，去 4.1.15.13 上逐个核对，结果：

- **只有 9 个**仍在原来的 RVA 上，且函数体字节完全一致（这些多是 Qt 底层工具函数）。
- **其余 37 个**已不在原地址。

偏移增量**毫无规律**，从 0 到 5120 字节不等：

| 函数 | 旧 RVA | 新 RVA | 增量 |
| --- | --- | --- | --- |
| Qt 析构 | `0x14e0` | `0x14e0` | 0 |
| ChatTextItemView 更新 | `0x1bc6490` | `0x1bc9be0` | +0x3750 |
| 文字 setter | `0x1e80d40` | `0x1e84750` | +0x4690 |
| 会话切换初始化 | `0x3de5e90` | `0x3de8ed0` | +0x3040 |
| 自身发送判断 | `0x5c41810` | `0x5c44110` | +0x2900 |

这说明新版是**重新编译**（recompile）而不是重新链接（relink）—— 函数顺序和大小
都变了。所以**不能靠加一个常数偏移**解决。

## 二、核心思路：认形状，不认地址

关键观察：重新编译会改变函数的**位置和大小**，但不会改变函数**做什么**。
指令的编码形态里，只有一部分字段会随重新编译而漂移：

| 会漂移的字段 | 原因 |
| --- | --- |
| `call`/`jmp` 的 rel32 位移 | 被调用函数换了位置 |
| rip 相对寻址的 disp32 | 引用的数据换了位置 |

| 不会漂移的部分 | 原因 |
| --- | --- |
| opcode | 代码逻辑没变 |
| ModRM / SIB | 寄存器分配通常稳定 |
| **小的立即数** | 栈帧大小、结构体偏移 —— 这些是**契约**，改了程序就坏 |

于是有两条可用的签名，**从强到弱依次尝试**：

### 1. 掩码字节（masked bytes）—— 最强

把旧函数的机器码取出来，**把会漂移的字段清零**，剩下的就是签名：

```
原始:  48 8B 41 08  48 8B 80 20 02 00 00  C3          mov rax,[rcx+8]; mov rax,[rax+0x220]; ret
                                  ^^^^^^^^^^
                                  这是结构体偏移，是契约 → 保留

原始:  E8 6E CA 29 00                                  call <某个地址>
       ^^^^^^^^^^^^^^
       这是调用位移，会漂移 → 清零

签名:  48 8B 41 08  48 8B 80 20 02 00 00  C3
```

零化之后，签名在新版本里**逐字节**匹配。这比「指令形状」强得多，因为它还锁定了
指令编码方式。

### 2. 指令形状（instruction shape）—— 兜底

当字节不再逐字相同时（比如寄存器分配变了），退一步只比指令**形状**：
助记符 + 操作数，其中**大立即数折叠成 `BIG`**、小立即数保留。

```
push rsi                                     ← opcode 层，稳定
sub rsp, 0x20                                ← 小立即数保留（栈帧是契约）
je BIG                                       ← 跳转目标会漂移 → 折叠
call BIG                                     ← 同上
mov rsi, rcx
```

匹配时按**前缀长度**排序，最长匹配优先。

### 3. 恒等（identity）—— 先试这个

不少 Qt 底层函数（`QString` 构造/析构等）在新版里地址和字节**都没变**。
先直接在原 RVA 上核对，命中就不用再搜。实测 4.1.15.13 上有 11 个函数属于这种情况。

---

## 三、vtable 怎么找

vtable 比函数难：**MSVC 已从这一版里剥掉了 RTTI 名字**（磁盘上读不到类名），
而且有 151 个 vtable 的基类数量相同，光靠「像 vtable」无法区分。

用了三种互补的方法：

### 1. 构造器内的相对位置（主力）

旧记录里保存了「哪个构造器的哪条 `lea` 装载了哪个 vtable」：

```json
{ "from": "0x3cff5ae",     "rva": "0x956b278" }
   ↑ lea 指令所在位置          ↑ 它装载的 vtable
```

重新编译会移动构造器，但**不会重排构造器内部的装载顺序**。所以：

```
新 vtable = 在新构造器的 (原偏移) 处读 lea 的目标
```

实测这套关系在新版上**整体平移 +0x20C0**，一次就解出了 binding / textInterface
等 5 个 vtable。

### 2. RTTI COL 校验（必做的验证）

每个定位结果都要过一遍 MSVC 的 Complete Object Locator 校验：
vtable 前面 8 字节应当指向一个 COL，而该 COL 的 `self` 指针应当指回它自己。

```python
sig, offset, pcd, ptd, pchd, self_rva = unpack('<IIIIII', col)
assert sig == 1 and self_rva == col      # 不成立就不是真 vtable
```

这一步能挡掉「碰巧指到某处」的假阳性。

### 3. Qt metaobject 反查（用于没有构造器记录的）

Qt 的元对象在磁盘上**保留了可读的类名字符串**，这是 MSVC RTTI 剥名之后少数还能用的
身份信息。定位链条：

```
moc 字符串表 → QMetaObject → qt_metacast 函数 → vtable 的 slot 0
```

`slot 0` 是 `metaObject()`，反汇编它就能看到它 `lea` 的是哪个元对象：

```
mov rcx, qword ptr [rcx + 8]
cmp qword ptr [rcx + 0x28], 0
jne 0x180270aa0
lea rax, [rip + 0x85f1eba]        → 0x8e7b920  解出类名 = mmui::ChatTextItemView
ret
```

`ownerVtable` 就是这么解出来的 —— 它没有任何构造器记录，只能靠
「slot 0 指向 `ChatTextItemView` 的元对象」来定位。

**注意**：派生类会**继承同一个** `metaObject()`，所以会有多个 vtable 共享这个指纹。
必须再用「类自己是最不派生的那个」来收窄：

```
候选按 (COL 偏移, 基类数) 排序，取最小
```

---

## 四、重新定位的完整流程

```bash
cd tools

# 1) 从既有记录解出新版的语义地址
python resolve_anchors.py --dll "C:\Program Files\Tencent\Weixin\<新版本>\Weixin.dll" \
                          --out resolved.json

# 2) 加上序言字节与哈希，生成适配器能直接读的锚点表
python emit_adapter_anchors.py --resolved resolved.json \
                          --dll "C:\Program Files\Tencent\Weixin\<新版本>\Weixin.dll" \
                          --out ../app/native_anchors.json --version <新版本号>
```

第 1 步会打印每个锚点是用哪一层签名解出来的、匹配了多少条指令。
**若匹配度偏低或出现歧义，说明新版改动较大，需要人工核对后再启用。**

`tools/records/` 里的记录是上一次解析留下的，**重新解析依赖它们，不要删除**。
它们是纯静态反汇编，不含任何聊天内容。

---

## 五、失败时怎么办（fail closed）

适配器**不允许**在不确定的情况下运行。三道闸门：

1. **DLL 哈希**：`native_host.py` 比对 `native_anchors.json` 里记录的 SHA-256，
   不一致直接拒绝启动。
2. **函数序言字节**：加载脚本后，逐个核对每个函数前 24 字节是否与解出时一致，
   不符则抛出 `CodeMismatch`。
3. **vtable 运行时校验**：每次使用前都要核对对象的 vtable 指针确实等于解出的值，
   不符就跳过该条消息，绝不硬写。

设计取向很明确：**宁可拒绝工作，也不要在错误的偏移上读写内存**。
在一个 200 MB 的 DLL 里用错偏移，读到的是无关数据，写的话可能直接损坏微信。

---

## 六、这套方法可以用在别处

「工具升级后，如何自动保住插桩地址」是个通用问题，不限于微信。同样的思路适用于：

- 自己维护的闭源二进制的版本升级回归
- 单机游戏的 mod（游戏更新后偏移失效）
- 安全研究 / CTF 中对抗重新编译

关键是三步：**认形状而非地址 → 用结构关系补足 → 用独立证据校验**。

---

## 附：证据留存

- `records/layout-disassembly-*.json` —— 函数反汇编记录（重定位的输入）
- `records/storage-wrapper-*.asm.txt` —— 原始机器码（掩码签名的来源）
- `docs/QT-TEXT-DATAFLOW.md` —— 文字从消息模型到显示控件的完整数据流
- `docs/STABLE-MESSAGE-KEY-STATIC.md` —— 消息身份键的静态依据
- `docs/NATIVE-GEOMETRY.md` —— 控件几何计算
- `docs/FINAL-VALIDATION.md` / `NEXT-VALIDATION.md` —— 现场验证记录与遗留项
