# 内存来源契约

`MemShadow::byte_at(addr, t)` 取 `idx <= t` 的最新事件，无事件时回退初始快照：

| 标记 | 来源 |
|---|---|
| `w` | trace store 的寄存器值（含 `simd_trace.bin` 重建的 NEON/SIMD store） |
| `r` | trace load 的后续寄存器状态（含 `simd_trace.bin` 重建的 NEON/SIMD load） |
| `x` | 捕获边界的外部写事件、经后续读取验证的外部内存拷贝/填充（`memcpy`/`memmove`/`memset`，附 `copy_from` 溯源）或按 `[spawnedAtIdx, endedAtIdx]` 窗口合并的 worker 线程写入 |
| `i` | 调用开始时的初始快照 |
| `??` | 未观测 |

写入者查询忽略 `r`；replay 只用指令之前的 `w/x/i`，不以 load 输出验证自身输入。
未追踪线程的后续写不会自动使旧字节失效。导出（`mem-dump --out`）遇到未知字节或截断时直接失败，不进行填零。
缓存指纹须包含 trace、SIMD sidecar、worker trace、快照和外部写输入。

## 初始快照

`memory_snapshot.bin` 使用小端版本 1：

```text
magic[8] = "TMSNAP\0\0"
version:u32 = 1
region_count:u32
每个 region: base:u64, size:u64, perms:u32, flags:u32, data[size]
```

`perms` 位为 `r=1/w=2/x=4`，当前 `flags=0`。
region 以排序 blob 保存。设备采集选择目标模块及可读匿名/可写区域，按 1MiB 分块
读取并将每块保存为独立 region，不设总量截断。未读到的区域写入
`snapshot_errors.jsonl`，调用标记为不完整；不填充伪造字节。它不是跨线程原子快照。

## 外部写

当前 agent 通过边界差分采集：前 8 个指针参数各读取 256 字节，返回后比较变化；
可写内存中的指针返回值可额外读取 256 字节。事件归到函数进入时的 trace head，不能当作精确写入指令。
默认无匹配函数；启用后按固定批量同步落盘，写盘背压不丢弃已捕获事件。
当未插桩的外部写未被 `external_writes.bin` 捕获时，`MemShadow` 通过比较后续 `r` 事件与最近一次 `w`/`x` 事件（或初始快照）检测 `unlogged_write_gap`，显式暴露 `[prev_write_idx, first_observing_read_idx]` 缺口区间。
尚无通用 syscall/JNI 输出缓冲区捕获。格式见 [数据契约](PER_CALL_TRACE_DESIGN.md)，
开关见采集命令帮助。
