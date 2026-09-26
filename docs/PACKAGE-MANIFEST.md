# 原生适配包的构建约定

`package_native.py` 默认只构建 `outputs/JevDialogueNative/`，不会启动托盘、host、微信或调用 API。现有输出目录会拒绝覆盖，失败的 staging 目录保留供排查。

| 路径 | 内容 |
| --- | --- |
| `app/` | 原生 host、分析调度、adapter、geometry、follow_tail、tray、路径/哈希 guard 和 binding 白名单 |
| `app/engine/core/` | 当前修改后的 Jev 分析核心 Python 源码 |
| `app/engine/app/settings.py` | 既有设置模块；打包时不导入、不读取密钥 |
| `app/engine/config.json` | 新建通用沟通、TypeSafe 官方接口、jev-latest、仅分析配置 |
| `app/engine/LICENSE`、`NOTICE` | 上游原文，保留署名与来源 |
| `app/tool-libs/` | 现有 Frida、pefile、ordlookup 及原始 dist-info/许可证 |
| `licenses/runtime/` | 已有 Python 许可证、依赖锁及来源记录 |
| `README.md`、`NOTICE.md` | 本地适配性质、启动入口、运行环境模式和来源说明 |
| `manifest.json` | 文件 SHA-256/大小、上游 revision、本地修改标记与构建状态 |

默认运行环境复用 `outputs/JevDialogue/runtime`，不复制、不重复下载。该模式只适合当前电脑，需保留原运行环境目录。`--copy-runtime` 可从同一本地环境复制 Python、Lib、DLLs 和许可证，形成独立 runtime 目录；不会运行 pip。

默认构建命令：

```powershell
& 'outputs/JevDialogue/runtime/python.exe' 'work/native-adapter-research/package_native.py'
```

`--install-shortcut` 仅在显式使用时新增桌面 `Jev 微信原生分析.lnk`，目标是所选 runtime 的 `pythonw.exe`，参数为包内 `app/native_tray.py`。已有同名链接会拒绝修改；不会建立开机启动、不会启动链接。

本次仅准备脚本，尚未执行构建或创建快捷方式。Manifest 默认状态为 `built_not_started_or_end_to_end_validated`；构建成功不能替代现场连接、显示、切换聊天及退出恢复验收。

包内不包含 API 密钥、原微信程序/DLL、聊天数据库、运行快照、截图或真实 API 返回。源码采用明确文件白名单，engine 配置新建，不拷贝开发目录现有 config.json。
