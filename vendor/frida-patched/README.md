# vendor/frida-patched

自构建的 frida-server (Android arm64) — 解决 stock frida 17.x 在 Android 14+/ARM64 高位 ASLR + OLLVM 大库 trace 时 `Unable to allocate code slab` SIGTRAP, 并对 target 可见的 frida 特征字符串做重命名以躲避常见 anti-frida 静态扫描.

## 两个构建版本

| 文件 | 体积 | 内容 | 用途 |
|---|---:|---|---|
| `frida-server-17-patched`  | 53MB | codeslab fallback patch only | 单纯解决 SIGTRAP, target 内仍可见 `gum-js-loop`/`frida-*`/`re.frida.server` |
| `frida-server-17-stealth`  | 53MB | codeslab + anti-detect 重命名     | 上面 + `frida` → `miku` 重命名 (cmdline / comm / socket 路径 / 注入 agent 线程名) |

两者都基于同一 frida-gum 上游 commit. 旧版本保留是为兼容,**新项目用 stealth**.

## 安装到设备

```bash
./install-stealth.sh         # → /data/local/tmp/.miku-srv  + adb forward tcp:6699 → 27042
./install-stealth.sh 6688    # 自定义本地端口

# 或安装基础 patched 版 (旧路径)
./install.sh
```

`install-stealth.sh` 会:

1. SHA256 校验 binary
2. `adb root` (脚本要求 adbd 已是 root)
3. killall 任何旧 frida/miku server
4. push → `/data/local/tmp/.miku-srv` (隐藏文件, 文件名无 "frida")
5. 启动 + adb forward
6. 验证 `/proc/<pid>/cmdline` 和 `comm` 都不含 "frida"
7. 跑 `frida-ps` 试连

## 反检测重命名清单

target 进程内可见, 经常被 anti-frida 脚本扫的 (target = 我们要 trace 的 app):

| 原 | 新 | 文件 |
|---|---|---|
| `g_set_prgname("frida")` | `g_set_prgname("miku")` | frida-gum/gum/gum.c |
| `"frida-main-loop"` 线程名 | `"miku-main-loop"` | frida-core/src/frida-glue.c |
| `"frida-agent-container"` 线程名 | `"miku-agent-cont"` (≤15 chars) | agent-container.vala |
| **`"gum-js-loop"` 线程名** | **`"miku-js-loop"`** | gumscriptscheduler.c — 最常被检测 |
| `"frida-gadget"` 线程名 | `"miku-gadget"` | gadget-glue.c |
| `"frida-helper-main-loop"` (Darwin) | `"miku-helper-main"` | darwin/frida-helper-service.vala |
| `"re.frida.server"` 默认 unix dir | `"re.miku.server"` | server/server.vala |
| droidy `"frida:"` socket prefix | `"miku:"` | droidy/injector.vala |
| `/data/local/tmp/frida-helper-` | `/data/local/tmp/miku-helper-` | 多 vala + Java |
| `/data/local/tmp/frida-gadget-` | `/data/local/tmp/miku-gadget-` | 多 vala |
| `re.frida.helper` (`--nice-name`) | `re.miku.helper` | droidy-host-session.vala |
| `"/frida-helper-"` LocalSocket | `"/miku-helper-"` | android-helper Helper.java (源码改了, 但内嵌的 helper.dex 没重 build) |

## 不改 (改了会破坏 host stock frida 兼容)

- D-Bus interface 名: `re.frida.HostSession17`, `re.frida.AgentSession17` ... 共 14 个 — wire protocol
- `"frida:rpc"` JSON-RPC tag — agent ↔ host frida-python 协议
- `frida_agent_main` 入口符号 — injector dlsym 找它

如果想改这些, 必须同时重建 host 端 frida-python (大幅工程). 当前方案: 只改 target-only string, 即可破掉 90% 常见 anti-frida 静态扫描.

## 实测验证 (Pixel 7 + Android 16, 2026-04-27)

### Server 端 (`.miku-srv` 进程)

```
cmdline: /data/local/tmp/.miku-srv
comm:    .miku-srv
threads: .miku-srv, gmain, gdbus, main, Signal Catcher, Jit thread pool,
         FinalizerDaemon, FinalizerWatchd, HeapTaskDaemon, ReferenceQueueD
/proc/<pid>/maps grep "frida": 0
/proc/<pid>/maps grep "miku":  4
```

### Target 端 (注入 agent 后的目标 app)

通过 `frida -H 127.0.0.1:6699 -p <target_pid> -l probe.js` 在 agent 内读 `/proc/self/task/*/comm`:

```
agent thread: miku-js-loop  ✓  (旧: gum-js-loop)
              pool-miku     ✓  (frida 自动以 prgname 派生 pool 前缀)
              gmain         (glib 内部, 非 frida 特征)
              gdbus         (glib 内部, 非 frida 特征)
其它检测点: frida_or_gum-js: 0 hits
```

### 与 stock frida 对比 (codeslab 实测)

测试: TB com.taobao.taobao 10.60.10 (libsgmainso-6.8.260403), `doCommandNative` cmd=70102, duration 240s.

| 配置 | calls | records | TB SIGTRAP? |
|---|---:|---:|---|
| frida 17 stock | 1 | 1,805 | ✅ 9 秒后崩 |
| **frida 17 patched** | 1 | **3,858,484** | ❌ 全程稳定 |

提升: 2000x records, 进程零崩溃.

## 自己重 build

```bash
./build-from-source.sh           # 一键: clone → NDK → patch → configure → make (~30-60min cold)
./build-from-source.sh patch     # 仅 patch
./build-from-source.sh make      # 仅 (重) make
./build-from-source.sh clean     # 删 build artifact 保留源码 + NDK
./build-from-source.sh distclean # 删一切 (恢复出厂)
```

工作目录在仓库根 `build/frida-build/` (gitignored), 包含:
- `frida/` — frida 源码 (`--depth 1`)
- `ndk/android-ndk-r29/` — NDK r29.x (frida 17.9 强制相等)
- `ndk.zip` — 缓存

需要的工具: `git`, `unzip`, `curl`, `patch`, `meson`, `ninja`, `go ≥ 1.24` (frida-compiler-backend 用).

国内构建: 脚本自动设 `GOPROXY=https://goproxy.cn,direct` + 预热 Go module cache.

## 兼容性

- 测试设备: Pixel 7 (Tensor G2), Android 16 (CP1A.260305.018, SDK 36)
- frida 17.9.x (上游 master at build time)
- NDK: r29.0.14206865
- 应该兼容所有 Android 12+ arm64 (patch 在 backend-posix, 不依赖特定内核)
- host 端: stock frida-python / frida-tools 即可 (wire protocol 未改)

## 文件清单

| 文件 | 说明 |
|---|---|
| `frida-server-17-patched`     | 旧 binary — 仅 codeslab fallback |
| `frida-server-17-stealth`     | 新 binary — codeslab + anti-detect 重命名 |
| `gummemory-posix.patch`       | codeslab fallback patch (单文件 diff) |
| `anti-detect-rename.sh`       | 反检测重命名脚本 (sed-based, idempotent) |
| `build-from-source.sh`        | 一键构建脚本 |
| `install.sh`                  | 安装旧 patched 版到设备 (`/data/local/tmp/frida-server-17-patched`) |
| `install-stealth.sh`          | 安装 stealth 版到设备 (`/data/local/tmp/.miku-srv`) |
| `SHA256SUMS`                  | 完整性校验 |
| `README.md`                   | 本文档 |

## 上游引用

- [frida-gum #707 (2023)](https://github.com/frida/frida-gum/issues/707) — 报告者实测删除 GumAddressSpec 检查后 stalker 正常, 提供本 patch 实证基础
- [frida-gum #793 (2024)](https://github.com/frida/frida-gum/issues/793) — 同样错误, 大 OLLVM 库 trace 时频繁出现, 上游未修
- [frida #2819 (2024)](https://github.com/frida/frida/issues/2819) — Android 14 + S22 + Stalker 多线程 SIGTRAP, 同根因
