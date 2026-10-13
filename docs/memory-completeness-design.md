# 内存来源契约

`MemShadow::byte_at(addr, t)` 取 `idx <= t` 的最新事件，无事件时回退初始快照：

| 标记 | 来源 |
|---|---|
| `w` | trace store 的寄存器值 |
| `r` | trace load 的后续寄存器状态 |
| `x` | 捕获边界的外部写事件 |
| `i` | 调用开始时的初始快照 |
| `??` | 未观测 |

写入者查询忽略 `r`；replay 只用指令之前的 `w/x/i`，不以 load 输出验证自身输入。
未追踪线程的后续写不会自动使旧字节失效。导出可为布局填零，但须同时报告缺口和完整度。
缓存指纹须包含 trace、快照和外部写输入。

## 初始快照

`memory_snapshot.bin` 使用小端版本 1：

```text
magic[8] = "TMSNAP\0\0"
version:u32 = 1
region_count:u32
每个 region: base:u64, size:u64, perms:u32, flags:u32, data[size]
```

`perms` 位为 `r=1/w=2/x=4`，当前 `flags=0`。
region 以排序 blob 保存。设备采集选择目标模块及可读匿名/可写区域，单区域最多
64MiB，总量受快照预算限制；未读到的区域不进入快照。它不是跨线程原子快照。

## 外部写

当前 agent 通过边界差分采集：前 8 个指针参数各读取 256 字节，返回后比较变化；
可写内存中的指针返回值可额外读取 256 字节。事件归到函数进入时的 trace head，不能当作精确写入指令。
默认无匹配函数；启用时应设置有限事件预算，当前 `--ext-write-cap=0` 不限量。
尚无通用 syscall/JNI 输出缓冲区捕获。格式见 [数据契约](PER_CALL_TRACE_DESIGN.md)，
开关见采集命令帮助。
