# tracer/

Frida 17 Stalker 全指令 + 全寄存器 trace 的 agent 集合. 配合 stealth frida-server
(`vendor/frida-patched/frida-server-17-stealth`) 在 ARM64 Android 真机抓 OLLVM 大库
JNI native fn 完整执行轨迹, dropped=0 保完整性.

## 文件

| 文件 | 模式 | 用途 |
|---|---|---|
| **`_agent.js`** | **默认 (`--mode cmodule`)** | 模块化 TS agent (frida-compile 编译). CModule + SPSC lock-free ring + 设备落盘 + 插件化 anti-detect. 1.5M rec/s, dropped=0 |
| `agent_cmodule_v5.js` | `--mode legacy` | 旧版单文件 agent (兼容回退) |
| `src/` | — | TypeScript 模块化源码 |
| `README.md` | — | 本文档 |

## 模块化架构 (src/)

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

## 架构: 设备落盘 (默认 cmodule 模式)

```
[target app + frida-agent.so]                  [host]
  │
  │ Stalker.follow(tid, JS transform: putCallout if PC ∈ [tBase, tEnd))
  │
  ▼
on_insn (CModule, 50 ns/insn):
  - SPSC lock-free ring (17 MB, head/tail monotonic in records)
  - 写满则 spin-wait (≤200ms 兜底), dropped=0 完整保
  │
  ▼
v8 setInterval 10ms:
  - read ring[tail % R .. head % R]
  - File.write → /data/data/<pkg>/cache/.miku/trace_callN_tidT.bin
  - tail = head (推进 consumer)
  │
  ▼
trace 结束 (onLeave):
  - flush 剩余 ring + close 文件
  - send {type:"trace-end", devicePath:"/data/data/.../trace_xxx.bin", records, retval, ms}
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
   ARM64 64-bit aligned load/store 是单指令原子 (TCC 不支持 __atomic_*/inline asm).
   实测 file_size = records × 272 字节精确匹配, 0% race loss.

3. **Backpressure**: cmodule callout 检测 `head - tail >= ring_recs` (满) → 自旋
   等 v8 推进 tail. spin_max ~200ms 兜底防 deadlock. 实测正常 v8 10ms flush 内
   就推进, 几乎不触发 spin.

4. **Gzip pull**: trace.bin 大量 0 padding (reg 不变) + PC 局部性, toybox gzip -1
   实测压缩比 ~26x, 1.74 GB → 67 MB. pipeline `adb exec-out gzip -c | host gunzip`
   流式, 实测 1.74 GB pull 5.2s (USB 物理 21 MB/s × 15.4x).

## 二进制 trace 格式

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

## 可选 sidecar

默认 `trace.bin` 仍只保存 272B 主记录. 下面两个 sidecar 都要显式打开, 用来补
GumTrace 类语义信息, 不改变主 trace 合同.

### SIMD/Q 寄存器 (`--simd-sidecar`)

`--simd-sidecar` 会让 agent 额外写 per-call `simd_trace.bin`. 每条 sidecar 记录
520 字节, little-endian:

```
0x000  u64  trace_idx      对应主 trace.bin 的记录下标
0x008  u8   q0[16]
...
0x1F8  u8   q31[16]
```

默认 `--simd-sample-stride 1` 表示每条指令保存一次 q0-q31. 大 trace 可调高步长,
例如 `--simd-sample-stride 8`, 降低额外 I/O 和磁盘放大.

### 语义事件 (`--semantic-events`)

`--semantic-events` 会额外写 per-call `semantic_events.jsonl`. 事件来源包括:

- `source="inline_svc"`: CModule 在指令流中识别 AArch64 `svc #imm`; 这是执行前
  事件, `ret` 为 `null`, 返回值可在下一条主 trace 记录的 `x0` 中观察.
- `source="syscall_wrapper"` / `source="libc"`: Interceptor hook libc `syscall`,
  `open/openat/read/write/pread64/pwrite64/mmap/mprotect/munmap/ioctl` 等常见 I/O
  入口, 记录参数和返回值.
- `source="jni_vtable"`: 已有 JSON-driven JNI hook 的镜像事件, 方便把 JNI 字符串
  与 syscall/libc 事件放进同一条时间线.

## 启动

入口是仓库根的 `tracemiku trace ...`, 详见根 README. 这里只列直接的 mode 选项:

```bash
# 默认 (模块化 agent)
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 600 \
  --cold-launch --out traces/run1

# 旧版单文件 agent (兼容回退)
./tracemiku trace ... --mode legacy ...

# 可选: 采集 SIMD/Q 寄存器和 syscall/JNI/libc 语义事件
./tracemiku trace ... --simd-sidecar --simd-sample-stride 4 --semantic-events ...

# 可选: 启用 anti-detect 插件
./tracemiku trace ... --anti-detect hide_rwx_maps,patch_suicide ...
```

## Deep-trace 模式 (`--trace-deep`)

默认 trace 只 instrument 主 SO + `--include-so` 指定的列表. Deep 模式反过来 — 全
模块 instrument, **per-symbol** `Stalker.exclude` hostile 函数 (linker / libdl /
某些 libc atomic). Boundary diff 是独立能力: `--boundary-diff-patterns` 会在匹配
符号上用 Interceptor 做 ptr-diff, 把传参指针指向的内存变化抓回来, 写入
`external_writes.bin` (17B 记录 `<Q attr_idx><Q addr><B byte>`) 给 viewer
MemShadow 重建. 它不需要 `--trace-deep`; 非 deep 模式下目标函数所在模块仍会
Stalker.exclude, 只额外挂 Interceptor 抓外部写副作用.

## JSON-driven JNI hooks

`--jni-hooks tools/hooks/libart_jni.json` 加载一份 JSON spec, agent 据此用
`Interceptor` 装 JNIEnv vtable 上的字符串相关函数. 输出走 `type='jni-hooks'` IPC
消息, host 落盘 per-call `jni_hooks.jsonl`, schema = `{id, trace_idx, args:{...}, ret}`.

## Anti-detect 插件

| 插件 ID | 说明 |
|---|---|
| `hide_rwx_maps` | hook libc `open/openat/read/pread64`, 当 fd 指向 `/proc/self/maps` 时把 anon rwx 行 (Frida 8MB block cache) 从结果里去掉 |
| `patch_suicide` | 按 `--suicide-patch-spec` JSON spec overwrite 目标 SO 内联 svc#0 (tgkill 自杀) 入口. 需要版本化 spec 文件 |

插件通过 `--anti-detect <id1>,<id2>` 或 `antiDetect: ["id1","id2"]` init opts 启用.
新插件只需实现 `AntiDetectPlugin` 接口并注册, 无需改动 agent 核心代码.

## 已知问题

- **anti-debug 检测线程名**: stealth server 把 `gum-js-loop` 改 `miku-js-loop`,
  pool-frida 改 pool-miku. 但 frida 仍创建 `gmain` / `gdbus` (glib 内部, 非 frida 特征).
- **设备 UFS 容量**: 单次 cold-path 1.7 GB, 14 calls 16 GB. 设备 cache dir 写满会
  触发 `pm clear` 时 throw. 默认每次 trace 完 host pull 后 `rm` device 文件, 不累积.
- **frida_agent_main symbol** 仍可被 anti-detect 扫到 (改它需要重 link agent.so).
