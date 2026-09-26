# Jev 微信原生分析

在微信聊天界面里，直接在对方消息的气泡内显示一段结构化解读：这句话可能是什么意思、依据是什么、有什么风险、可以怎么回应。

程序只做**理解**，不生成回复、不发送消息、不写入微信数据库。所有分析结果只在本地运行期间显示。

> **这是本地适配版，不是原项目作者出品，也未获得微信或 TypeSafe 的认证或背书。**
> 上游判断内核见 [jev-chat/jev-chat-windows](https://github.com/jev-chat/jev-chat-windows)（MIT）。

---

## 它做什么

打开一个包含对方文字消息的会话，程序在该消息的气泡内追加一张分析卡片。卡片里包含：

- **原话解读** —— 这句话可以怎么理解，以及这样理解的依据
- **概率** —— 该解读有多确定
- **决策影响** —— 如果按这个理解行动，会带来什么
- **风险参考** —— 需要注意的地方
- **行动建议** —— 可以怎么回应

判断由官方 [TypeSafe](https://typesafe.ai) 的 `jev` 系列「System One」模型完成。这类模型不生成文本，只返回**结构化的判断和概率分布**，因此不会自由发挥编造内容。

## 它不做什么

这是本项目最重要的部分，请务必读完：

| | |
| --- | --- |
| **不发送消息** | 不调用微信的发送接口，不会替你跟对方说话 |
| **不写入聊天数据库** | 不修改微信的任何本地数据，分析卡片不是聊天记录 |
| **不生成回复** | 只做理解，不做代笔 |
| **不注册开机自启** | 需要你手动启动 |
| **不保存历史** | 聊天截图、正文、分析结果只存在于内存，退出即消失 |

原生注释是**运行时注入显示层**的结果，不是往聊天记录里插消息。关掉程序，微信恢复原样。

## 使用边界（务必理解）

1. **只适用于经过核验的微信版本。** 程序内置锚点表（`app/native_anchors.json`），
   记录了它适配的那一个 `Weixin.dll` 的哈希。微信升级后哈希不匹配，程序会**拒绝启动**，
   而不会在错误的地址上读写。升级后需要重新适配（见下文）。

2. **冷启动时，如果当前会话完全静止**，需要有一条新消息到达或切换一次会话，
   触发首次原生文字更新后，才会建立绑定并开始自动分析。

3. **仅支持文字消息。** 图片、语音、文件不能可靠分析。

4. **分析内容会发送到你配置的第三方 API**（TypeSafe）。这意味着参与对话的对方消息
   会被发送到该服务。请自行确认这对你、以及对对方是可以接受的。

5. **请只分析你自己的对话。** 这不是用来监视别人聊天的工具。

---

## 快速开始

### 环境要求

- Windows 10 / 11 x64
- Python 3.11（建议用独立环境，不要替换系统 Python）
- 微信 PC 版，版本需与 `app/native_anchors.json` 中记录的版本一致
- 一个 TypeSafe API Key（[typesafe.ai](https://typesafe.ai)）

> **请务必用 Python 3.11。** `frida` 目前只为 3.11 及更早版本提供 Windows 轮子。
> 在 3.13 / 3.14 下 `pip install` 会报 `Could not find a version that satisfies
> the requirement frida==17.18.0 (from versions: none)` —— 这**不是网络问题**，
> 而是 pip 把不兼容的版本静默过滤掉了，看起来很像镜像连不上，容易误判。

### 安装

```bash
git clone https://github.com/HaoyuJiangdasak/jev-wechat-native.git
cd jev-wechat-native

python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

> `frida` 是二进制包，体积较大（约 127 MB），**不随仓库分发**，由上面的 pip 安装。

### 配置密钥

密钥不写入任何配置文件，只放在你的用户环境变量里：

```cmd
setx JEV_API_KEY "你的 TypeSafe API Key"
```

设置后**重新打开一个终端**使其生效。程序启动时从环境变量读取。

### 运行

```bash
python app/native_tray.py
```

托盘图标出现后，打开一个包含对方文字消息的微信会话即可。托盘菜单提供暂停、继续和退出；
退出时会先请求恢复原始聊天显示。

---

## 微信升级后怎么办

微信会自动升级并删除旧版本目录，这会让所有硬编码的地址失效。本项目因此**不把地址写在源码里**，
而是放在 `app/native_anchors.json` —— 一份针对某一个具体 `Weixin.dll` 解出的语义地址表。

升级后重新解一次即可，**不需要改任何代码**：

```bash
cd tools
python resolve_anchors.py --dll "C:\Program Files\Tencent\Weixin\<新版本>\Weixin.dll" \
                          --out resolved.json
python emit_adapter_anchors.py --resolved resolved.json \
                          --dll "C:\Program Files\Tencent\Weixin\<新版本>\Weixin.dll" \
                          --out ../app/native_anchors.json --version <新版本号>
```

`tools/records/` 里保存了上一次解析所用的反汇编记录，重新解析依赖它们，请不要删除。

原理和验证方法见 [docs/REANCHOR.md](docs/REANCHOR.md)。

---

## 项目结构

```
app/
  native_tray.py            托盘入口
  native_host.py            生命周期与兼容性校验（哈希、序言字节）
  native_adapter.js         原生显示适配：绑定消息、写入注释、恢复
  native_follow_tail.js     滚动条跟随（写入后保持视图位置）
  native_geometry.js        控件几何计算（不含地址，与微信版本无关）
  native_anchors.json       ★ 针对某个 Weixin.dll 解出的地址表
  native_analysis.py        调度：请求排队、结果去重、投递确认
  probe_native_views.py     独立的只读诊断工具
  engine/                   判断内核（上游 MIT 代码的本地修改版）
  tests/                    离线测试
tools/
  resolve_anchors.py        ★ 跨版本重新定位地址
  emit_adapter_anchors.py   ★ 生成 native_anchors.json
  records/                  重新定位所需的既有反汇编记录
docs/                       研究与验证记录
```

## 测试

离线测试不需要微信、不需要 API、不附加任何进程：

```bash
# Python（50 项）
python -m unittest discover -s app/tests -p "test_*.py"

# JavaScript（73 项：留底 43、几何 11、适配器 19）
node app/native_follow_tail.test.js
node app/native_geometry.test.js
node app/native_adapter.test.js
```

JS 测试会读取真实的 `native_anchors.json`，因此覆盖的就是实际发货的地址。

---

## 许可与归属

- **判断内核**（`app/engine/`）：[jev-chat/jev-chat-windows](https://github.com/jev-chat/jev-chat-windows)
  v0.1.9 的本地修改版，MIT。原始 `LICENSE` 与 `NOTICE` 一并保留。
- **原生显示适配、调度、托盘、重定位工具**：本仓库原创。
- **Frida**（[frida.re](https://frida.re)）与 **pefile**：经 pip 安装的第三方库，未随仓库分发。

本仓库不声称获得微信、TypeSafe 或上游作者的认证或背书。

## 免责声明

本项目仅用于分析**你本人参与**的对话，帮助你更好地理解沟通内容。使用者应自行遵守
所在地法律法规及微信服务条款。作者不对使用者的任何行为或后果负责。请勿将其用于
监视他人、侵犯隐私或其他不当用途。
