# AI 运行时分析指南

本指南描述通用分析流程。x-sign、VM 和签名算法只作为示例，目标专用偏移与参数应放在
`examples/`，不能进入 core。

## 基本原则

1. 先用静态工具确定模块和偏移，再用 `(SO, 偏移)` 查询运行时事实。
2. 先收集证据，再提出算法假设；未知内存和截断结果不能支撑确定性结论。
3. 优先调用专用 CLI，一次查询尽量返回结构化批量结果，避免逐记录启动进程。
4. 所有结论记录来源：trace、调用目录、idx、PC、模块偏移和 provenance。

## 推荐顺序

```bash
# 1. 确认 trace 与模块
./tracemiku info <call_dir> --json
./tracemiku resolve --so libtarget.so --off 0x1234

# 2. 观察路径和调用
./tracemiku coverage --fn trace:F0
./tracemiku indirect-targets --so libtarget.so --off 0x1234
./tracemiku call-tree

# 3. 查询值与内存
./tracemiku reg-at --reg x0 --so libtarget.so --off 0x1234
./tracemiku mem-dump --addr 0x70000000 --size 256
./tracemiku mem-export --addr 0x70000000 --len 0x100

# 4. 回溯来源
./tracemiku taint-bwd --start 1000 --reg x0
./tracemiku bfs-slice --idx 1000
./tracemiku forward-dep-tree --idx 1000

# 5. 识别算法与 VM 行为
./tracemiku crypto <call_dir>
./tracemiku vm-ops --start 1000 --end 2000
./tracemiku dec <call_dir> --summary
```

具体参数以每个子命令的 `--help` 为准。

## 证据分级

- 已观测事实：trace 指令、寄存器快照、`w/r/x/i` 内存、实际分支目标。
- 有界推断：由明确 ABI、连续 def-use 或多次调用一致性支持的结论。
- 未验证假设：静态相似、算法名称猜测、`??` 内存或被截断范围上的推断。

输出算法还原结果时，必须把这三类分开。密码学常数命中只是候选证据，应同时检查硬件
指令、调用上下文、输入输出长度和数据流。

## 大 trace 纪律

- 使用 `--range`、`--indices`、`--limit`、`--depth` 和扫描上限。
- 检查 `truncated`、`stop_reason`、`completeness` 和 provenance。
- 不把 `??` 当零，不把一次执行的固定值当作跨输入常量。
- 对 VM 分析先识别 dispatcher、状态寄存器、字节码读取和 handler 边，再生成 replay
  plan；目标角色寄存器必须可配置。

## 交付要求

可复现分析至少包含：输入 trace、命令、关键 idx/偏移、证据、反例、仍未知的边界，以及
可运行的验证脚本。样例实现位于 `examples/libsgmainso/` 和 `examples/libdidiwsg/`，
它们是案例，不是产品默认规则。
