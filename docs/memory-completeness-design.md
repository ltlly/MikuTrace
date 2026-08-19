# 内存完整性设计

trace 记录每条指令的通用寄存器，但不直接记录所有内存字节。MemShadow 通过 trace
store、trace load、外部写和初始快照建立分层字节事实，并对未知保持诚实。

## 来源模型

`MemShadow::byte_at(addr, t)` 返回值、来源种类和来源 idx：

| 种类 | 来源 | 可信含义 |
|---|---|---|
| `w` | 被追踪 store | 精确的用户态写 |
| `r` | 被追踪 load 的下一条寄存器状态 | 精确的已读值 |
| `x` | syscall、JNI 或边界差分外部写 | 在捕获边界观测到的值 |
| `i` | trace 开始时的内存快照 | `t=0` 基线 |
| `??` | 未观测 | 未知，不能按零处理 |

查询顺序是：取 `idx <= t` 的最新事件；没有事件时查初始快照；仍没有则返回 `??`。
后续 trace 写自然覆盖初始快照。

## 初始快照

`--snapshot-mem` 在目标函数进入时采集目标模块和受限的可读匿名区域，受
`--snapshot-max-mb` 控制。文件 `memory_snapshot.bin` 使用小端格式：

```text
magic[8] = "TMSNAP\0\0"
version:u32
region_count:u32
重复 region_count 次：
  base:u64
  size:u64
  perms:u32
  flags:u32
  data[size]
```

快照以排序 region blob 保存，不能把数百 MB 逐字节展开到树结构。只读和初始化一次
的数据可视为可靠基线；未追踪线程在 `t=0` 后修改的内存仍是不可观测边界。

## 外部写

主机和 core 已支持 `external_writes.bin`，每条记录为 17 字节：
`idx:u64 + addr:u64 + byte:u8`。它在 MemShadow 中成为 `x` 层。

尚未完成的是设备端 syscall/JNI 输出缓冲区捕获。实现必须满足：

- ABI 表由 `tools/hooks/` 配置，不把目标偏移写进 agent。
- `read`、`recv`、`stat`、`getrandom` 等按返回值或固定结构长度采集。
- 单次 buffer 和整次调用都有硬上限，默认关闭。
- 捕获失败不影响 trace 主通路，并在元数据中可诊断。
- 使用真实设备对拍输出字节和 MemShadow provenance。

## 消费者规则

- `mem-dump`、`mem-export`、lineage 和 VM 分析必须传播来源与完整度。
- 导出未知区间时可以为文件布局填零，但必须同时返回缺口和 `completeness < 1`。
- 缓存必须包含 trace 指纹及快照/外部写输入，输入变化后失效。
- 完整性阈值只能提示风险，不能把推断升级为事实。
