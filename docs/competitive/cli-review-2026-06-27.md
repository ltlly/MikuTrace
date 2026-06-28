# CLI 审查 2026-06-27：重合 / 别名 / 交互一致性

> 对 `tracemiku-cli` 90+ 子命令做的一轮审查。结论：命令多但职责清晰，**唯一的真
> bug 是地址解析不一致(已修)**；其余"重合"多是超集+轻量特例或兼容别名，保留合理。

## 已修：地址解析不一致（真 footgun）

老命令(`resolve-trace-addr`/`byte-writer-map`/`output-backtrace`/`resolve-elf-symbol`
等)对裸 `--addr/--off`(无 `0x`)按**十进制**解析；新 P0/P1 命令
(`resolve`/`reg-at`/`mem-export`/`coverage`)按**十六进制**(反汇编器惯例)。同一个
`--addr`，两套结果。

**修复**(commit `8d949e4`)：新增 `parse_addr_str`(hex 默认 / `0x` hex / `d` 前缀
十进制)，接管 8 个 CLI 侧地址解析点；`parse_u64_str`(十进制默认)留给
size/count/idx，所以 `--size 256` 仍是 256。地址类参数全 CLI 统一为 hex 默认。

## 别名：保留（删除会破坏脚本）

- `search-asm` = `search`（`/api/search` 的 legacy 名）。
- `reg-at-idx` = `reg-value-at`（`/api/reg-value-at` 的 legacy 名）。

兼容别名，零维护成本，删除只会破坏既有用法。保留。

## 命名相近但语义不同：保留，文档已澄清

- `reg-at`（**新 P0**，按 `(SO,偏移)`/PC 取寄存器**跨执行的去重值分布**）
  vs `reg-value-at`/`reg-at-idx`（按 `--idx` 取单条记录的寄存器值）。
  一个是"偏移处所有执行的值"，一个是"某条记录的值"。help 已写清。

## 功能重合：超集 + 轻量特例，各有价值，保留

- `resolve --addr`（**新**，trace 模块范围，回带运行时事实 exec_count 等）
  vs `resolve-trace-addr`（同样查 trace 模块范围，但更轻、无运行时事实）。
  `resolve` 是超集；`resolve-trace-addr` 是轻量纯解析。两者都保留，`resolve`
  文档标注为推荐。`resolve-map-addr`(查 /proc maps 文件) 与
  `resolve-elf-symbol`(查 ELF 符号) 是不同数据源，不重合。
- taint/slice 家族：`taint-fwd`/`taint-bwd`(逐指令传播步) vs
  `bfs-slice`(持久依赖 CSR 切片，快) vs `forward-dep-tree`(def→use DAG) vs
  `dep-graph`(种子依赖图)。语义各异，help 互相指引"何时用哪个"。删任何一个
  都丢能力。保留。
- VM 家族：`vm-slice`/`vm-ops`/`vm-backstep`/`vm-backchain`/`vm-backtree`/
  `byte-lineage`——粒度/方向各异（单步/分组/链/树/单字节）。保留。

## wrapper `query` 子集：有意为之

Python `tracemiku query <dir> <sub>` 只暴露高频子命令(records/forward-taint/
backward-taint/strings/cfg/search/func-summary/resolve/indirect-targets/
mem-export/reg-at/coverage)。完整面是 Rust binary。这是 AI 友好的高频入口 +
完整逃生舱的有意分层，非遗漏。

## 一致性收尾(本轮已落实)

- 所有新 P0/P1 命令 + 8 个老地址解析点：地址/偏移 **hex 默认**，`d` 前缀十进制。
- 所有新命令：`(SO,偏移)` 与 PC 双路入口，输出回带坐标，ambiguous/miss/
  no_execution 等状态显式区分。
- lineage 偏移键化覆盖 backward(`taint-bwd`/`bfs-slice`)+forward(`forward-dep-tree`)；
  `byte-lineage` 保留 `--addr`(其种子是运行时内存地址，非代码偏移)。

## 不做（本轮判定）

- 不删别名/重合命令——超集+轻量特例+兼容别名都是合理设计，删除是净损失。
- 不重命名 `reg-at`/`reg-value-at`——刚发布，重命名破坏公开面，收益不抵。
