# Trace 数据格式

```text
<run>/meta.json
<run>/log.txt
<run>/calls/call_<序号>_tid<线程>_<记录数>r_<耗时>ms/
  trace.bin
  meta.json
  external_writes.bin    # 可选
  memory_snapshot.bin    # 可选
```

分析命令通常接收单次调用目录。采集中使用 `_pending_call_*`；回传失败保留 pending
和设备 spool，恢复后由 `finalize` 回填元数据并重命名。旧平铺格式仅用于读取兼容。

## trace.bin

小端、每条 272 字节，与 core `Record` 对应；寄存器均为指令执行前状态。

| 字段 | 类型 |
|---|---|
| `pc` | `u64` |
| `regs[31]` | `x0..x28, fp, lr`，各 `u64` |
| `sp` | `u64` |
| `nzcv` | `u32` |
| `inst` | `u32` |

无保留字段，不内嵌 SIMD/FP 或内存字节。记录数须与文件长度一致。

## 元数据与 sidecar

调用级 `meta.json` 保存记录数、线程、目标、模块映射、寄存器顺序、截断/丢弃信息及
sidecar 描述。地址用 `0x` 字符串，计数与长度用整数。旧字段缺失或 `null` 不能视为
已验证完整；格式变更须版本化并测试迁移。

`external_writes.bin` 每条为 `idx:u64 + addr:u64 + byte:u8`，小端 17 字节。
初始快照布局及来源归因见 [内存契约](memory-completeness-design.md)。
采集 sidecar 与可重建的分析缓存不同；后者必须校验输入长度和内容指纹。
