# tracer/

> **[English](#english)** | **[中文](#中文)**

---

## English

Frida 17 Stalker full-instruction + full-register trace agent collection.
Works with the patched stealth frida-server
(`vendor/frida-patched/miku-trace-server-17.9.11`, frida 17.9.11) to capture
complete execution traces of JNI native functions in OLLVM-protected
large libraries on ARM64 Android real devices, with dropped=0 integrity guarantee.

### Files

| File | Mode | Purpose |
|---|---|---|
| **`_agent.js`** | **Default (`--mode cmodule`)** | Modular TS agent (frida-compile). CModule + SPSC lock-free ring + on-device file I/O + plugin anti-detect. 1.5M rec/s, dropped=0 |
| `agent_cmodule_v5.js` | `--mode legacy` | Legacy single-file agent (fallback) |
| `src/` | — | TypeScript modular source |

### Modular Architecture (src/)

```
src/
├── agent.ts              Entry: rpc.exports + init + installFnHook
├── core/
│   ├── state.ts          Global STATE singleton + constants + types
│   ├── utils.ts          Utilities (log, getExport, ptrToStringMaybe, syscall names)
│   ├── cmodule.ts        CModule C source generation + compilation (SPSC ring producer)
│   ├── ring.ts           V8 consumer: flush ring to disk + watchdog + ensureTraceDir
│   └── stalker.ts        Stalker.exclude + include-ranges + transform callback
├── sidecar/
│   ├── simd.ts           Optional SIMD/Q register ring + flush
│   └── semantic.ts       Semantic events: libc/syscall/inline-SVC hooks
├── hooks/
│   ├── jni_vtable.ts     JSON-driven JNI vtable Interceptor hooks
│   ├── fork_monitor.ts   fork/vfork/clone event logging
│   └── boundary_diff.ts  Boundary memory diff (external write detection)
└── anti_detect/
    ├── plugin_interface.ts   AntiDetectPlugin interface + registry
    ├── hide_rwx_maps.ts      Hide RWX anonymous pages from /proc/self/maps
    └── patch_suicide.ts      Spec-driven patch of obfuscated tgkill thunks
```

### Build

```bash
cd tracer
npm install          # first time
npm run build        # frida-compile src/agent.ts → _agent.js
npm run watch        # dev mode (auto-recompile on change)
```

### Adding a New Anti-Detect Plugin

1. Create `my_plugin.ts` in `src/anti_detect/`
2. Implement the `AntiDetectPlugin` interface (`id`, `name`, `description`, `install()`)
3. Register in `BUILTIN_PLUGINS` in `plugin_interface.ts`
4. Users enable via `--anti-detect my_plugin`

### Architecture: On-Device File I/O (Default CModule Mode)

```
[target app + frida-agent.so]                  [host]
  │
  │ Stalker.follow(tid, JS transform: putCallout if PC ∈ [tBase, tEnd))
  │
  ▼
on_insn (CModule, 50 ns/insn):
  - SPSC lock-free ring (17 MB, head/tail monotonic in records)
  - Full → spin-wait (≤200ms fallback), dropped=0 guarantee
  - maxRecords hard cap: if max_records > 0 && head >= max_records → return
  │
  ▼
v8 setInterval 10ms:
  - read ring[tail % R .. head % R]
  - File.write → /data/data/<pkg>/cache/.miku/trace_callN_tidT.bin
  - tail = head (advance consumer)
  │
  ▼
trace end (onLeave or maxRecords cap):
  - flush remaining ring + close file
  - send {type:"trace-end", devicePath, records, retval, ms, truncated}
                                                ▼
                                  host adb_pull_device_trace:
                                    adb exec-out 'gzip -1 -c <path>'
                                      ↓ USB stream
                                    | gunzip
                                      ↓
                                    traces/run/calls/.../trace.bin
                                  rm device file
```

**Key points:**

1. **No IPC**: agent does not send blobs to host. Host receives only trace-end metadata.
   Trace data flows through device-local UFS (~500MB/s) → adb gzip pipeline (~320MB/s effective).
2. **SPSC lock-free**: head/tail are monotonic record counters (never reset). CModule writes
   ring[head % R], head += 1; consumer reads ring[tail..head], advances tail = head.
   ARM64 64-bit aligned load/store is single-instruction atomic (TCC doesn't support __atomic_*/inline asm).
3. **Backpressure**: CModule callout detects `head - tail >= ring_recs` (full) → spin-wait
   until v8 advances tail. spin_max ~200ms fallback prevents deadlock.
4. **Gzip pull**: trace.bin has high 0-padding + PC locality, toybox gzip -1 achieves ~26x
   compression. 1.74 GB → 67 MB, pipeline 5.2s (USB 21 MB/s × 15.4x).
5. **maxRecords enforcement**: CModule `on_insn` checks `if (max_records > 0 && h >= max_records) return;`
   Ring heartbeat detects cap hit and auto-finalizes with `truncated: true`.

### Binary Trace Format

Each record is 272 bytes, little-endian:

```
0x000  u64  pc
0x008  u64  x[0..28]    (29 GPRs)
0x0F0  u64  fp           (= x29)
0x0F8  u64  lr           (= x30)
0x100  u64  sp
0x108  u32  nzcv         (NZCV flag bits)
0x10C  u32  inst         (raw 4-byte machine code)
```

Shared by Rust core / server / CLI.

### Optional Sidecars

The default `trace.bin` stores only 272B main records. The following sidecars
must be explicitly enabled and provide supplementary semantic data without
changing the main trace contract.

**SIMD/Q Registers** (`--simd-sidecar`): writes per-call `simd_trace.bin`,
520 bytes per record (trace_idx:u64 + q0..q31).

**Semantic Events** (`--semantic-events`): writes per-call `semantic_events.jsonl`
with inline SVC, syscall wrapper, libc, and JNI vtable events.

### Usage

Entry point is `tracemiku trace ...` from the repo root. Mode options:

```bash
# Default (modular agent)
./tracemiku trace --pkg com.example.app --so libtarget.so \
  --fn-offset 0x57770 --duration 600 --cold-launch --out traces/run1

# Optional: SIMD/Q registers and semantic events
./tracemiku trace ... --simd-sidecar --simd-sample-stride 4 --semantic-events

# Optional: anti-detect plugins
./tracemiku trace ... --anti-detect hide_rwx_maps,patch_suicide
```

### Known Issues

- **Anti-debug thread name detection**: stealth server renames `gum-js-loop` → `miku-js-loop`,
  pool-frida → pool-miku. But frida still creates `gmain` / `gdbus` (glib internal, not frida-specific).
- **Device UFS capacity**: single cold-path 1.7 GB, 14 calls 16 GB. Device cache fills up.
  Default: host pulls then `rm` device file after each call (no accumulation).
- **frida_agent_main symbol** is still scannable by anti-detect (requires re-linking agent.so to change).

---

## 中文

Frida 17 Stalker 全指令 + 全寄存器 trace 的 agent 集合。配合 patched stealth
frida-server (`vendor/frida-patched/miku-trace-server-17.9.11`，frida 17.9.11)
在 ARM64 Android 真机抓 OLLVM 大库 JNI native fn 完整执行轨迹，dropped=0 保完整性。

### 文件

| 文件 | 模式 | 用途 |
|---|---|---|
| **`_agent.js`** | **默认 (`--mode cmodule`)** | 模块化 TS agent (frida-compile 编译). CModule + SPSC lock-free ring + 设备落盘 + 插件化 anti-detect. 1.5M rec/s, dropped=0 |
| `agent_cmodule_v5.js` | `--mode legacy` | 旧版单文件 agent (兼容回退) |
| `src/` | — | TypeScript 模块化源码 |

### 模块化架构 (src/)

```
src/
├── agent.ts              入口: rpc.exports + init + installFnHook
├── core/
│   ├── state.ts          全局 STATE 单例 + 常量 + 类型
│   ├── utils.ts          通用工具 (log, getExport, ptrToStringMaybe, syscall names)
│   ├── cmodule.ts        CModule C 源码生成 + 编译 (SPSC ring producer)
│   ├── ring.ts           V8 consumer: flush ring to disk + watchdog + ensureTraceDir
│   └── stalker.ts        Stalker.exclude + include-ranges + transform callback
├── sidecar/
│   ├── simd.ts           可选 SIMD/Q 寄存器 ring + flush
│   └── semantic.ts       语义事件: libc/syscall/inline-SVC hooks
├── hooks/
│   ├── jni_vtable.ts     JSON-driven JNI vtable Interceptor hooks
│   ├── fork_monitor.ts   fork/vfork/clone event logging
│   └── boundary_diff.ts  Boundary memory diff (external write detection)
└── anti_detect/
    ├── plugin_interface.ts   AntiDetectPlugin 接口 + 注册表
    ├── hide_rwx_maps.ts      隐藏 /proc/self/maps 中的 RWX 匿名页
    └── patch_suicide.ts      Spec-driven patch obfuscated tgkill thunks
```

### 构建

```bash
cd tracer
npm install          # 首次
npm run build        # frida-compile src/agent.ts → _agent.js
npm run watch        # 开发模式 (监听文件变动自动重编译)
```

### 添加新 anti-detect 插件

1. 在 `src/anti_detect/` 创建 `my_plugin.ts`
2. 实现 `AntiDetectPlugin` 接口 (`id`, `name`, `description`, `install()`)
3. 在 `plugin_interface.ts` 的 `BUILTIN_PLUGINS` 注册
4. 用户通过 `--anti-detect my_plugin` 启用

### 架构: 设备落盘 (默认 cmodule 模式)

```
[target app + frida-agent.so]                  [host]
  │
  │ Stalker.follow(tid, JS transform: putCallout if PC ∈ [tBase, tEnd))
  │
  ▼
on_insn (CModule, 50 ns/insn):
  - SPSC lock-free ring (17 MB, head/tail monotonic in records)
  - 写满则 spin-wait (≤200ms 兜底), dropped=0 完整保
  - maxRecords 硬上限: max_records > 0 && head >= max_records → 直接 return
  │
  ▼
v8 setInterval 10ms:
  - read ring[tail % R .. head % R]
  - File.write → /data/data/<pkg>/cache/.miku/trace_callN_tidT.bin
  - tail = head (推进 consumer)
  │
  ▼
trace 结束 (onLeave 或 maxRecords cap):
  - flush 剩余 ring + close 文件
  - send {type:"trace-end", devicePath, records, retval, ms, truncated}
                                                ▼
                                  host adb_pull_device_trace:
                                    adb exec-out 'gzip -1 -c <path>'
                                      ↓ USB stream
                                    | gunzip
                                      ↓
                                    traces/run/calls/.../trace.bin
                                  rm device file
```

**关键点:**

1. **不走 IPC**: agent 不 send blob 给 host. host 收的只是 trace-end metadata.
   trace data 走设备本地 UFS (~500MB/s) → adb gzip pipeline (~320MB/s effective).
2. **SPSC lock-free**: head/tail 是 monotonic records 计数 (不 reset). cmodule 写
   ring[head % R], head += 1; consumer 读 ring[tail..head], 推进 tail = head.
   ARM64 64-bit aligned load/store 是单指令原子.
3. **Backpressure**: cmodule callout 检测 `head - tail >= ring_recs` (满) → 自旋
   等 v8 推进 tail. spin_max ~200ms 兜底防 deadlock.
4. **Gzip pull**: trace.bin 大量 0 padding + PC 局部性, toybox gzip -1
   压缩比 ~26x, 1.74 GB → 67 MB. pipeline 实测 1.74 GB pull 5.2s.
5. **maxRecords 强制执行**: CModule `on_insn` 入口检查 `if (max_records > 0 && h >= max_records) return;`
   心跳定时器检测到 cap 命中后自动 finalize call，带 `truncated: true` 标记。

### 二进制 trace 格式

每条记录 272 字节, little-endian:

```
0x000  u64  pc
0x008  u64  x[0..28]    (29 个 GPR)
0x0F0  u64  fp           (= x29)
0x0F8  u64  lr           (= x30)
0x100  u64  sp
0x108  u32  nzcv         (NZCV flag bits; v3/early agent 留 0)
0x10C  u32  inst         (raw 4-byte 机器码)
```

Rust core / server / CLI 共用此格式.

### 可选 sidecar

默认 `trace.bin` 仍只保存 272B 主记录. 下面两个 sidecar 都要显式打开, 用来补
GumTrace 类语义信息, 不改变主 trace 合同.

**SIMD/Q 寄存器** (`--simd-sidecar`): 额外写 per-call `simd_trace.bin`.
每条 sidecar 记录 520 字节 (trace_idx:u64 + q0..q31).
`--simd-sample-stride N` 控制采样步长.

**语义事件** (`--semantic-events`): 额外写 per-call `semantic_events.jsonl`.
事件来源: inline SVC、syscall wrapper、libc、JNI vtable hooks.

### 启动

入口是仓库根的 `tracemiku trace ...`, 详见根 README. 这里只列直接的 mode 选项:

```bash
# 默认 (模块化 agent)
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --duration 600 --cold-launch --out traces/run1

# 可选: 采集 SIMD/Q 寄存器和 syscall/JNI/libc 语义事件
./tracemiku trace ... --simd-sidecar --simd-sample-stride 4 --semantic-events

# 可选: 启用 anti-detect 插件
./tracemiku trace ... --anti-detect hide_rwx_maps,patch_suicide
```

### Deep-trace 模式 (`--trace-deep`)

默认 trace 只 instrument 主 SO + `--include-so` 指定的列表. Deep 模式反过来 — 全
模块 instrument, **per-symbol** `Stalker.exclude` hostile 函数 (linker / libdl /
某些 libc atomic). Boundary diff 是独立能力: `--boundary-diff-patterns` 会在匹配
符号上用 Interceptor 做 ptr-diff, 把传参指针指向的内存变化抓回来.

### JSON-driven JNI hooks

`--jni-hooks tools/hooks/libart_jni.json` 加载一份 JSON spec, agent 据此用
`Interceptor` 装 JNIEnv vtable 上的字符串相关函数. 输出 per-call `jni_hooks.jsonl`.

### Anti-detect 插件

| 插件 ID | 说明 |
|---|---|
| `hide_rwx_maps` | hook libc `open/openat/read/pread64`, 把 anon rwx 行从 `/proc/self/maps` 结果中去掉 |
| `patch_suicide` | 按 `--suicide-patch-spec` JSON spec overwrite 目标 SO 内联 svc#0 (tgkill 自杀) 入口 |

插件通过 `--anti-detect <id1>,<id2>` 或 `antiDetect: ["id1","id2"]` init opts 启用.
新插件只需实现 `AntiDetectPlugin` 接口并注册, 无需改动 agent 核心代码.

### 已知问题

- **anti-debug 检测线程名**: stealth server 把 `gum-js-loop` 改 `miku-js-loop`,
  pool-frida 改 pool-miku. 但 frida 仍创建 `gmain` / `gdbus` (glib 内部, 非 frida 特征).
- **设备 UFS 容量**: 单次 cold-path 1.7 GB, 14 calls 16 GB. 默认每次 trace 完 host pull 后 `rm` device 文件.
- **frida_agent_main symbol** 仍可被 anti-detect 扫到 (改它需要重 link agent.so).
