# tracer/

Frida 17 Stalker 全指令 + 全寄存器 trace 的 agent 集合. 配合 stealth frida-server
(`vendor/frida-patched/frida-server-17-stealth`) 在 ARM64 Android 真机抓 OLLVM 大库
JNI native fn 完整执行轨迹, dropped=0 保完整性.

## 文件

| 文件 | 模式 | 用途 |
|---|---|---|
| **`agent_cmodule_v5.js`** | **默认 (`--mode cmodule`)** | CModule on_insn + SPSC lock-free ring + 设备落盘. 1.5M rec/s, dropped=0, 完整保 |
| `agent_cmodule_v3.js` | `--mode cmodule-v3` | 旧 cmodule, send blob via IPC. IPC 瓶颈 (~5MB/s), 高速 callout 下 91% drop. 留作回归对比. |
| `agent_generic.js` | `--mode js` | JS putCallout, 无 cmodule. ~17K rec/s, dropped=0 (callout 慢匹配 IPC). cmodule 编译失败时自动 fallback. |
| `README.md` | — | 本文档 |

## 架构: v5 设备落盘 (默认 cmodule 模式)

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

**关键点 (vs 上一代 v3):**

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

## 实测性能 (TB libsgmainso `doCommandNative` cmd=70102 cold-launch)

| 模式 | 采集 rate | 完整 6.8M records 时长 | dropped | truncated |
|---|---:|---:|---|---|
| `js` (baseline) | 17K rec/s | 405s | 0 | False |
| `cmodule-v3` | (callout 7.9M/s, IPC 5MB/s) | — | **91% 丢** | False |
| **`cmodule` (v5)** | **1.56M rec/s** | **~7-9s** | **0** | **False** |

14 calls / 67M records / 16 GB raw / 93s wall (43s 采集 + 50s gzip pull) **全 dropped=0**.

总加速: baseline 跑 67M records 需要 ~3940s, v5 = 93.6s, **~42x**.

## 二进制 trace 格式

每条记录 272 字节, little-endian:

```
0x000  u64  pc
0x008  u64  x[0..28]    (29 个 GPR)
0x0F0  u64  fp           (= x29)
0x0F8  u64  lr           (= x30)
0x100  u64  sp
0x108  u32  inst         (raw 4-byte 机器码)
0x10C  u32  pad          (0)
```

viewer / webui 共用此格式, mode (v3/v5/js) 不影响 record 物理大小.

## 启动

入口是仓库根的 `tracemiku trace ...`, 详见根 README. 这里只列直接的 mode 选项:

```bash
# 默认 cmodule (v5, 推荐)
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 600 \
  --cold-launch --out traces/run1

# 强制 js 模式 (cmodule 不可用时)
./tracemiku trace ... --mode js ...

# v3 回归对比
./tracemiku trace ... --mode cmodule-v3 ...
```

## 已知问题

- **anti-debug 检测线程名**: stealth server 把 `gum-js-loop` 改 `miku-js-loop`,
  pool-frida 改 pool-miku. 但 frida 仍创建 `gmain` / `gdbus` (glib 内部, 非 frida 特征).
  详见 `vendor/frida-patched/README.md`.
- **设备 UFS 容量**: 单次 cold-path 1.7 GB, 14 calls 16 GB. 设备 cache dir 写满会
  触发 `pm clear` 时 throwm. 默认每次 trace 完 host pull 后 `rm` device 文件, 不
  累积.
- **frida_agent_main symbol** 仍可被 anti-detect 扫到 (改它需要重 link agent.so).
  当前 trace 工作正常, 后续 stealth 增强可考虑.
