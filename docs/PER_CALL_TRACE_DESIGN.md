# Trace 数据契约

本文件定义设备采集、主机拉取和 Rust 解析共同依赖的稳定格式。修改这里的任何字段都
必须同步修改 agent、host、core、server、测试和迁移逻辑。

## 目录结构

```text
<run>/
  meta.json
  log.txt
  calls/
    call_<序号>_tid<线程>_<记录数>r_<耗时>ms/
      trace.bin
      meta.json
      external_writes.bin      # 可选
      memory_snapshot.bin      # 可选
```

分析命令通常接收单次调用目录，而不是 run 根目录。旧平铺格式只用于读取兼容，不应再
产生新数据。

## `trace.bin`

每条记录固定为 272 字节，小端序，与 `tracemiku-core` 的 `Record` 结构一一对应：

| 字段 | 类型 | 含义 |
|---|---|---|
| `pc` | `u64` | 当前指令地址 |
| `regs[31]` | 31 个 `u64` | 指令执行前的 `x0..x28`、`fp`、`lr` |
| `sp` | `u64` | 栈指针 |
| `nzcv` | `u32` | 条件标志 |
| `inst` | `u32` | ARM64 指令字 |

总计 `33 × 8 + 2 × 4 = 272` 字节，没有保留字段。当前记录不包含 SIMD/FP 寄存器和
内存字节。消费者必须通过 MemShadow 的来源信息判断内存完整性。

## 调用级 `meta.json`

核心字段包括 trace 路径、记录数、线程、目标方法、模块映射、寄存器顺序、是否截断、
sidecar 文件和格式版本。地址在 JSON 中优先使用 `0x` 字符串，计数和长度使用整数。
新增必填字段必须提升版本；新增可选字段必须为旧 trace 提供明确默认行为。

## Sidecar

- `external_writes.bin`：每条 17 字节，依次为 `idx:u64`、`addr:u64`、`byte:u8`，
  在 MemShadow 中标记为 `x`。
- `memory_snapshot.bin`：初始内存快照，格式见 `memory-completeness-design.md`。
- 分析索引 sidecar 必须通过 trace 长度和内容指纹失效，不能复用到另一份 trace。

## 不变量

- 记录数必须与 `trace.bin` 长度严格一致。
- 达到上限时必须设置 `truncated=true`，不能静默丢记录。
- 大小、时间、丢弃数和 sidecar 写入失败必须进入元数据或诊断输出。
- 解析器遇到未知新版本应明确拒绝或走迁移路径，不能猜测字段布局。
