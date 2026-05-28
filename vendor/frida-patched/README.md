# vendor/frida-patched

自构建的 frida-server (Android arm64) — 集成多项 bug 修复 + 反检测 patches, 从源码编译.

## 当前版本

| 文件 | 体积 | 基线 | 说明 |
|---|---:|---|---|
| `miku-trace-server-17.9.11` | 51MB | frida 17.9.11 | **最新**: 全量 patches (见下) |
| `frida-server-17-patched`   | 53MB | frida 17.9.x  | 旧 — 仅 codeslab fallback |
| `frida-server-17-stealth`   | 53MB | frida 17.9.x  | 旧 — codeslab + sed 重命名 |

**新项目请用 `miku-trace-server-17.9.11`**.

## 集成 Patches

基于 frida 17.9.11 tag, 集成了以下修复和反检测 patches:

### 1. Stalker Literal Pool Overflow Fix (PR #1113)

来源: [frida-gum PR #1113](https://github.com/frida/frida-gum/pull/1113)

ARM64 + ARM32 Stalker `is_out_of_space()` 未计算 pending literal pool 大小, 导致 code slab 写越界 → mapper crash. 本修复让 `is_out_of_space()` 在检查剩余空间时纳入 `cw->literal_refs.length * sizeof(guint64) + 4` 的 pending pool 大小.

同时增加了 PR 评审建议的 `literal_refs.data != NULL && literal_refs.length > 0` 安全 check.

### 2. Code Slab Fallback Patch (codeslab)

来源: 自研 (`gummemory-posix.patch`)

解决 Android 14+/ARM64 高位 ASLR 下所有 near-allocation free range 被占满时 `gum_memory_allocate_near()` 返回 NULL → `g_assert()` → SIGTRAP. 添加 unconstrained fallback allocation.

相关 issues: [frida-gum#707](https://github.com/frida/frida-gum/issues/707), [frida-gum#793](https://github.com/frida/frida-gum/issues/793), [frida#2819](https://github.com/frida/frida/issues/2819)

### 3. Anti-Detect 重命名 (frida → miku)

来源: `anti-detect-rename.sh` (12 项 sed 替换)

重命名 target 进程内可见的 frida 特征字符串:

| 原 | 新 | 文件 |
|---|---|---|
| `g_set_prgname("frida")` | `("miku")` | gum/gum.c |
| `"frida-main-loop"` 线程名 | `"miku-main-loop"` | frida-glue.c |
| `"frida-agent-container"` | `"miku-agent-cont"` | agent-container.vala |
| `"gum-js-loop"` 线程名 | `"miku-js-loop"` | gumscriptscheduler.c |
| `"frida-gadget"` 线程名 | `"miku-gadget"` | gadget-glue.c |
| `"re.frida.server"` unix dir | `"re.miku.server"` | server.vala |
| `"frida:"` socket prefix | `"miku:"` | droidy/injector.vala |
| `/data/local/tmp/frida-*` paths | `/data/local/tmp/miku-*` | 多文件 |
| `re.frida.helper` nice-name | `re.miku.helper` | droidy-host-session.vala |

### 4. Florida Anti-Detection Patches (frida-core)

来源: [Ylarod/Florida](https://github.com/Ylarod/Florida) (5 patches applied)

| Patch | 功能 |
|---|---|
| 0001: string_frida_rpc | `"frida:rpc"` → Base64 编码运行时解码, 防止字符串扫描 |
| 0002: frida_agent_so   | agent SO 文件名随机化 (UUID) |
| 0006: protocol_unexpected_command | 协议未知命令响应指纹消除 |
| 0008: pool-frida       | 线程池名前缀去特征 |
| 0009: memfd-name-jit-cache | memfd 名称从 `frida-*` → `jit-cache` 伪装 |

### 5. frida_agent_main 符号名重命名

来源: Florida 0003 (手动应用, 解决行号冲突)

所有 `"frida_agent_main"` 入口符号 → `"main"`, 防止 SO 符号表扫描检测 frida agent 注入.

### 参考但未直接应用

- [taisuii/rusda](https://github.com/taisuii/rusda): XOR 字符串混淆方案 (需要添加 Obfuscate.vala helper class, 对 17.9.11 代码差异大, 未集成. Florida 的 Base64 方案已覆盖核心 frida:rpc 字符串)
- [AeonLucid/strongR-frida](https://github.com/AeonLucid/strongR-frida): Florida 是其增强分支, 我们直接用 Florida patches

## 安装到设备

```bash
./install-stealth.sh         # → /data/local/tmp/.miku-srv  + adb forward tcp:6699 → 27042
./install-stealth.sh 6688    # 自定义本地端口
```

## 从源码构建

```bash
# macOS ARM64 (推荐, 需要 meson/ninja/go/node/git/patch + NDK r29)
./build-from-source-mac.sh           # 完整: clone → patch → configure → make
./build-from-source-mac.sh patch     # 仅 patch
./build-from-source-mac.sh make      # 仅 (重) make
./build-from-source-mac.sh clean     # 删 build artifact 保留源码
./build-from-source-mac.sh distclean # 全删

# Linux (旧脚本, 需要 NDK zip 下载)
./build-from-source.sh
```

工作目录: `<repo>/build/frida-build/` (gitignored), 包含:
- `frida/` — frida 17.9.11 源码 (`--depth 1`)
- frida 会自动下载 toolchain + SDK 到 `frida/deps/`
- 需要 `ANDROID_NDK_ROOT` 指向 NDK r29

代理设置: `export https_proxy=http://127.0.0.1:7897` 或脚本自动检测.

## 兼容性

- 构建环境: macOS 14+ ARM64 (Apple Silicon)
- 目标设备: Pixel 7 (Tensor G2), Android SDK 36
- 兼容: Android 12+ arm64 (patch 在 backend-posix, 不依赖特定内核)
- Host 端: stock frida-python / frida-tools 即可 (D-Bus wire protocol 未改)

## 不改的 (host 兼容)

- D-Bus interface 名: `re.frida.HostSession17`, `re.frida.AgentSession17` — wire protocol
- host 端 Python 交互 — 不改 frida-python

## 文件清单

| 文件 | 说明 |
|---|---|
| `miku-trace-server-17.9.11`  | **最新** binary — 全量 patches |
| `frida-server-17-patched`    | 旧 — 仅 codeslab fallback |
| `frida-server-17-stealth`    | 旧 — codeslab + sed 重命名 |
| `gummemory-posix.patch`      | codeslab fallback patch (可供参考) |
| `anti-detect-rename.sh`      | 反检测重命名脚本 (sed-based, idempotent) |
| `build-from-source-mac.sh`   | macOS 一键构建脚本 |
| `build-from-source.sh`       | Linux 一键构建脚本 |
| `install.sh`                 | 安装旧 patched 版 |
| `install-stealth.sh`         | 安装 stealth 版到设备 |
| `SHA256SUMS`                 | 完整性校验 |

## 上游引用

- [frida-gum PR #1113](https://github.com/frida/frida-gum/pull/1113) — Stalker literal pool overflow fix (本项目提交)
- [frida #3751](https://github.com/frida/frida/issues/3751) — Stalker ARM64 literal pool overflow crash (本项目报告)
- [frida-gum #707](https://github.com/frida/frida-gum/issues/707) — code slab allocation 失败报告
- [frida-gum #793](https://github.com/frida/frida-gum/issues/793) — 同上, OLLVM 大库 trace
- [frida #2819](https://github.com/frida/frida/issues/2819) — Android 14 + Stalker 多线程 SIGTRAP
- [Ylarod/Florida](https://github.com/Ylarod/Florida) — anti-detection patches
- [taisuii/rusda](https://github.com/taisuii/rusda) — XOR obfuscation 参考
