# SIMD 载荷与跨窗口采集边界

## 1. NEON / SIMD 访存字节载荷重建与剩余限制

- **`Record` 与 `simd_trace.bin` 分离**：`trace.bin` 单条 `Record` 固定 272 字节，仅内嵌 GPR/SP/NZCV/PC/指令字；`V0..V31` / `Q0..Q31` 状态由可选 `simd_trace.bin`（520 字节/条：`idx: u64` + `v[32]: 512B`）独立保存。
- **`MemShadow` 重建与采样边界**：存在对应 `idx` 的 `simd_trace.bin` 记录时，`MemShadow` 从标量/向量 SIMD 访存（含 `ldr/str`、`ldp/stp`、`ld1..ld4`/`st1..st4`/`ld1r..ld4r`）重建 `w`/`r` 字节事件并供 `mem-accesses`、`mem-dump`、`find-mem-pattern`、`byte-lineage` 与 `records` 消费；未启用 SIMD 采集或采样步长 `simd_sample_stride > 1` 跳过的记录仍表现为未知字节（`null` / `??`）。`trace-replay` 当前尚未接入 `simd_trace.bin`。

## 2. 调用窗口前初始化与后台线程边界

- **初始化窗口（`--trace-init`）**：默认入口采集仅覆盖目标函数 `onEnter` 至 `onLeave`。启用 `--trace-init`（`entry_boundary="module-init-and-entry"`）可将目标模块 `dlopen` 后的初始化窗口（`JNI_OnLoad`）与首次目标入口调用合并采集（其间暂停 Stalker）；未启用 `--trace-init` 或早于挂钩时刻完成的写入只能由初始快照 `i` 体现，无法关联生产指令。
- **Worker 线程窗口（`--follow-workers`）**：默认仅跟踪 `primaryTid`。启用 `--follow-workers` 时跟踪目标模块内已驻留及新创建的 worker 线程（排除系统与运行时守护线程），按主线程 `[spawnedAtIdx, endedAtIdx]` 窗口将 `worker_trace_tid*.bin` 的写入作为 `x` 事件并入 `MemShadow`；仍为窗口级插值而非跨线程指令级硬件全序（见 [TODO](../TODO.md)）。
