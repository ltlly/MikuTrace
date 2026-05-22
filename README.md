# traceMiku

> **[English](#english)** | **[中文](#中文)**

---

## English

traceMiku is an Android real-device ARM64 instruction-level trace toolchain.

The analysis v2 cutover is complete: Python `viewer/`, the old FastAPI `webui/`,
and the old pytest parity suite have been removed. Runtime analysis now lives in
Rust crates plus the Solid frontend.

### Layout

```text
tracer/                         Frida device agents
frontend/                       Solid + Vite SPA
rust/crates/tracemiku-core/     trace parser, disasm, CFG, taint, MemShadow, LLIL
rust/crates/tracemiku-server/   axum API server, static frontend, BN sidecar bridge
rust/crates/tracemiku-cli/      Rust JSON CLI wrappers and filesystem commands
tools/hooks/                    JSON hook/type specs
examples/                       sample target metadata/specs
docs/                           design notes and parity history
```

### Quick Start

`./tracemiku` is the top-level convenience wrapper:

```bash
# Capture a trace
./tracemiku trace --pkg com.example.app --so libtarget.so --method nativeFn --out traces/run1

# Lightweight export profiling (no Stalker, no trace.bin)
./tracemiku probe --pkg com.example.app --so libtarget.so --duration 10

# Inspect traces
./tracemiku list traces/run1 --json
./tracemiku info traces/run1/calls/call_001_tid1_100r_1ms --json

# Launch web UI
./tracemiku web traces/run1/calls/call_001_tid1_100r_1ms --port 18900
./tracemiku view traces/run1/calls/call_001_tid1_100r_1ms
```

`web` and `view` both start the Rust v2 server and serve `frontend/dist`.
For BN-backed HLIL, pass the target SO:

```bash
./tracemiku web <call_dir> --so /path/to/libtarget.so
```

The wrapper maps `--so` to `TRACEMIKU_BN_SO`. The BN sidecar command defaults to
`tracemiku-bn-sidecar` and can be overridden with `TRACEMIKU_BN_SIDECAR`.

### Current Web UI

The Solid UI is the primary workflow surface:

- Records are virtualized, keyboard-navigable, and keep stable row identity
  during range refetches.
- Records can show Taint results as a live overlay, either highlighting hits or
  dimming non-hit rows while preserving virtual-scroll layout.
- Records support trace-local row marks from the context menu: color, note,
  strike-through, and dim states persist in browser local storage per trace
  path without changing trace files.
- `g` opens the jump command: `#240` or `240` jumps to a trace index, and
  `0x...` jumps to the first executed record at that PC.
- The CFG panel follows cursor changes when sync is enabled. Manual function
  selection from the Functions tab switches to CFG and pauses sync so the
  selected function is not immediately overwritten by the current cursor.
- Large trace CFGs use a representative overview when Graphviz dot rendering
  would be too expensive. The API reports drawn and hidden edge counts so the
  overview cannot be mistaken for a full graph.
- CFG pan/zoom is interactive; `Ctrl+wheel` zooms around the mouse cursor.
- BN-backed HLIL/Pseudo C follows the current trace PC. If BN has no function
  containing a trace PC, the sidecar can create a user function at the trace
  symbol entry or current PC, then retry HLIL/CFG.

### Rust CLI

The Rust CLI can be run directly during development:

```bash
cd rust
cargo run -p tracemiku-cli -- info <call_dir> --json
cargo run -p tracemiku-cli -- records <call_dir> --start 0 --count 50
cargo run -p tracemiku-cli -- functions <call_dir>
cargo run -p tracemiku-cli -- dec-summary <call_dir>
cargo run -p tracemiku-cli -- dec-fn <call_dir> trace:F0 --tier hot
```

The CLI is also the main LLM-friendly surface for trace analysis. It exposes
typed JSON commands for web API routes plus higher-level provenance tools:

```bash
./tracemiku api <call_dir> /api/backtrace -p idx=443 -p limit=64
rust/target/debug/tracemiku-cli output-map <call_dir> --key x-sign --summary --semantic-writer-map
rust/target/debug/tracemiku-cli output-backtrace <call_dir> --key x-sign
rust/target/debug/tracemiku-cli jni-output-strings <call_dir> --key x-umt
rust/target/debug/tracemiku-cli byte-lineage <call_dir> --addr 0x1234 --before-idx 1000 --compact
rust/target/debug/tracemiku-cli byte-lineage <call_dir> --addr 0x1234 --before-idx 1000 --count 32 --compact
rust/target/debug/tracemiku-cli vm-ops <call_dir> --start 1000 --end 1400 --summary
rust/target/debug/tracemiku-cli vm-ops <call_dir> --start 1000 --end 1400 --replay-plan
```

Recent AI-analysis additions include:

- persistent `trace.bin.analysis-index.v2.bin` index sidecars for repeated
  server opens, with trace-size and content-fingerprint invalidation;
- persistent `trace.bin.analysis-full.v1.bin` whole-trace analysis sidecars
  with CSR dependency rows, memory last-def bytes, register checkpoints, call
  tree reuse, and `/api/analysis-index` compact performance/coverage summaries;
- dependency DAG queries through `/api/dep-graph` and `tracemiku-cli dep-graph`,
  seeded from a trace index, register last-def, or memory-address last writer;
- backward BFS slicing over the persistent dependency CSR via `/api/bfs-slice`
  with multi-seed `idxs/regs/addrs` and `mode=union|intersection` for
  "common ancestors" queries, plus a forward def→use DAG via
  `/api/forward-dep-tree` (peer-trace-tools §1.8/§1.9 algorithms; see
  `docs/peer-trace-tools-implementation.md`). Both routes have CLI
  wrappers `tracemiku-cli bfs-slice` and `tracemiku-cli forward-dep-tree`
  with the same flag surface (`--idx`, `--idxs 1,2`, `--reg`, `--regs`,
  `--addr`, `--addrs`, `--before`, `--data-only`, `--limit`, `--mode`,
  `--depth`);
- GumTrace-style `SCAN_LIMIT_REACHED` watchdog on `/api/forward-taint` and
  `/api/backward-taint` (`scan_limit=` query, `stop_reason` in the
  response). CLI: `tracemiku-cli taint-fwd ... --scan-limit N` and
  `taint-bwd ... --scan-limit N`. Pass 0 to disable the watchdog;
- taint provenance graph expressions, Records taint-only filtering, JSON/TXT
  taint export, a Records minimap, call-frame folding, and local function
  renames for large-trace navigation;
- output-driven workflows from JNI strings or known bytes back to memory
  writers, Base64 groups, semantic byte formulas, and VM backchains;
- batched `byte-lineage --count` with compact `frontier_groups`, step stats,
  repeated-value summaries, stable pointer loop hints, call-return boundaries,
  syscall-return boundaries, and bytecode-read frontiers;
- generic VM dynamic-trace helpers (`vm-slice`, `vm-ops`, `vm-backstep`,
  `vm-backchain`, `vm-backtree`) with configurable role registers instead of
  target-specific assumptions;
- replay-plan export and verification through
  `tools/vm_replay_plan_eval.py --emit-python` and
  `--verify-emitted-python`, so an AI agent can turn observed VM effects into
  editable Python scaffolding before replacing trace fallbacks with proven
  parameters;
- memory/JNI helpers such as `find-mem-pattern`, `byte-writer-map`,
  `mem-dump`, `mem-writes-in-range`, `jni-output-strings`, and
  `scan-jni-output-strings`.
- `crypto-scan` covers common crypto/hash magic constants beyond IVs, including
  MD5/SHA round constants, AES/SM3/SM4 tables, CRC32C, FNV, Murmur3, xxHash,
  Poly1305, ChaCha20, and RC4 identity-table markers.

The current `libsgmainso`/`x-sign` reconstruction is tracked as an example, not
as hardcoded tool behavior. The partial simulator in
`examples/libsgmainso/xsign_partial_sim.py` now reproduces the current
call_001 trace model and emits `completion_audit.goal_complete == false` until
the remaining VM bytecode/table frontiers are lifted into portable inputs. The
latest trace evidence also classifies `x-umt` as a companion output over the
same scratch payload stream, rather than as a separate magic secret.
See `docs/ai-cli-xsign-workflow.md` and `docs/xsign-reconstruction-progress.md`
for the detailed workflow and proof log.

### Development

```bash
make fmt
make test-v2
make test-device   # NDK cross-compile + adb push + trace + verify
make smoke-web RUN=traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms SMOKE_ARGS='--all-surfaces'
make smoke-ui BASE=http://127.0.0.1:18900 UI_SMOKE_ARGS='--browser chromium --executable /path/to/chrome'
```

`make test-v2` runs the Python wrapper syntax check, Rust fmt check, Rust
core/server/CLI tests, and the Solid frontend production build.
`make smoke-web` runs the live Rust server API/perf gate. `make smoke-ui` runs
the Playwright browser event smoke against an already running web server.
`make test-device` cross-compiles an ARM64 test binary, pushes to device, traces
it, and verifies the trace output is valid (requires NDK + adb device).

The Rust server serves API routes under `/api/*`, `/openapi.json`, `/ws/jobs`,
and falls back to the built SPA in `frontend/dist`.

### Documentation

Current source-of-truth docs are:

- `README.md`: user-facing quick start and current UI behavior.
- `AGENTS.md` / `CLAUDE.md`: repository-local agent rules and workflow.
- `TODO.md`: the only active backlog. Completed implementation plans are not
  kept as live TODOs.
- `REFERENCES.md`: external algorithm/tool references and current test gates.
- `docs/PER_CALL_TRACE_DESIGN.md`: current per-call trace layout and record
  contract.
- `docs/trace-decompiler-design.md`: current decompiler/BN/HLIL route design.
- `docs/ai-cli-xsign-workflow.md`: target-agnostic AI workflow for using CLI
  provenance, VM, memory, JNI, and output-mapping commands.
- `docs/xsign-reconstruction-progress.md`: target-specific example progress
  report for the current `libsgmainso` trace corpus.
- `docs/xsign-algorithm-spec.md`: human-readable spec of the recovered
  call_001 x-sign algorithm — 76-byte layout, head formulas for words
  0/1, the `(boundary << 24) | (xor_state >> 8)` shift register for
  words 2..11, the input parameter list, and what still requires
  extracting from libsgmainso.so.
- `docs/android-analysis-frontier-report.md`: Android analysis pain points,
  product/UI direction, and current bug triage.
- `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`:
  historical Rust/Solid cutover design and parity map.
- `docs/peer-trace-tools-survey.md` / `docs/peer-trace-tools-algorithms.md` /
  `docs/peer-trace-tools-implementation.md`: peer-tool review and the
  current implementation log for the BFS-slice / forward-dep-tree /
  scan-limit / multi-seed work.

### Trace Format

`trace.bin` records are 272 bytes. Per-call directories use:

```text
calls/call_<idx>_tid<T>_<records>r_<ms>ms/
```

Format changes require an explicit meta version bump and migration path.

---

## 中文

traceMiku 是一个安卓真机 ARM64 指令级 trace 全栈工具链。

分析层 v2 迁移已完成：旧版 Python `viewer/`、FastAPI `webui/`、pytest 对等测试套件均已删除。
运行时分析现在完全基于 Rust crates + Solid 前端。

### 目录结构

```text
tracer/                         Frida 设备 agent
frontend/                       Solid + Vite 单页应用
rust/crates/tracemiku-core/     trace 解析、反汇编、CFG、污点、MemShadow、LLIL
rust/crates/tracemiku-server/   axum API 服务器、静态前端、BN sidecar 桥
rust/crates/tracemiku-cli/      Rust JSON CLI 包装和文件系统命令
tools/hooks/                    JSON hook/类型 spec
examples/                       示例目标元数据/spec
docs/                           设计文档和迁移历史
```

### 快速上手

`./tracemiku` 是顶层便捷入口：

```bash
# 采集 trace
./tracemiku trace --pkg com.example.app --so libtarget.so --method nativeFn --out traces/run1

# 轻量级导出函数计数 (不启动 Stalker, 无 trace.bin)
./tracemiku probe --pkg com.example.app --so libtarget.so --duration 10

# 查看 trace
./tracemiku list traces/run1 --json
./tracemiku info traces/run1/calls/call_001_tid1_100r_1ms --json

# 启动 Web UI
./tracemiku web traces/run1/calls/call_001_tid1_100r_1ms --port 18900
./tracemiku view traces/run1/calls/call_001_tid1_100r_1ms
```

`web` 和 `view` 都会启动 Rust v2 服务器并提供 `frontend/dist` 静态文件。
如需 Binary Ninja HLIL 支持，传入目标 SO：

```bash
./tracemiku web <call_dir> --so /path/to/libtarget.so
```

包装器将 `--so` 映射到 `TRACEMIKU_BN_SO`。BN sidecar 命令默认为
`tracemiku-bn-sidecar`，可通过 `TRACEMIKU_BN_SIDECAR` 环境变量覆盖。

### 当前 Web UI

Solid UI 是主要工作面：

- Records 虚拟滚动、键盘导航，在范围重取时保持稳定行标识。
- Records 可叠加污点分析结果实时高亮命中行或淡化非命中行，不影响虚拟滚动布局。
- Records 支持右键菜单的 trace-local 行标记：颜色、笔记、删除线、淡化状态。
  标记持久化在浏览器 localStorage 中（按 trace 路径隔离，不修改 trace 文件）。
- `g` 打开跳转命令：`#240` 或 `240` 跳到 trace 索引，`0x...` 跳到该 PC 首次执行的记录。
- CFG 面板在同步开启时跟随光标。从函数列表手动选择函数会切换到 CFG 并暂停同步，
  避免当前光标立即覆盖手动选择。
- 大 trace CFG 使用代表性概览 SVG；API 报告已绘制和隐藏边数，不会与完整图混淆。
- CFG 平移/缩放交互式操作；`Ctrl+滚轮` 以鼠标为中心缩放。
- BN HLIL/Pseudo C 跟随当前 trace PC。如果 BN 中没有包含该 PC 的函数，
  sidecar 会在 trace 符号入口或当前 PC 创建用户函数后重试。

### Rust CLI

开发期间可直接运行 Rust CLI：

```bash
cd rust
cargo run -p tracemiku-cli -- info <call_dir> --json
cargo run -p tracemiku-cli -- records <call_dir> --start 0 --count 50
cargo run -p tracemiku-cli -- functions <call_dir>
cargo run -p tracemiku-cli -- dec-summary <call_dir>
cargo run -p tracemiku-cli -- dec-fn <call_dir> trace:F0 --tier hot
```

CLI 也是 LLM 友好的 trace 分析主界面，提供带类型的 JSON 命令用于 web API
路由和更高层次的溯源工具：

```bash
./tracemiku api <call_dir> /api/backtrace -p idx=443 -p limit=64
rust/target/debug/tracemiku-cli output-map <call_dir> --key x-sign --summary --semantic-writer-map
rust/target/debug/tracemiku-cli byte-lineage <call_dir> --addr 0x1234 --before-idx 1000 --compact
rust/target/debug/tracemiku-cli vm-ops <call_dir> --start 1000 --end 1400 --summary
```

最近的 AI 分析功能包括：

- 持久化 `analysis-index.v2.bin` / `analysis-full.v1.bin` sidecar 索引，支持指纹失效
- 依赖 DAG 查询 (`/api/dep-graph`, `dep-graph` CLI)，从 trace 索引/寄存器/内存地址出发
- 反向 BFS 切片 (`/api/bfs-slice`)，多种子 union/intersection 模式，用于"共同祖先"查询
- 正向 def→use DAG (`/api/forward-dep-tree`)
- 污点扫描限制看门狗 (`scan_limit`/`stop_reason`)
- 输出驱动工作流：从 JNI 字符串或已知字节追踪到内存写入者
- 通用 VM 动态 trace 辅助工具 (`vm-slice`, `vm-ops`, `vm-backstep`, `vm-backchain`)
- `crypto-scan`：检测常见加密/散列魔数常量（MD5、SHA、AES、SM3/4、CRC32C 等）

### 开发

```bash
make fmt
make test-v2
make test-device   # NDK 交叉编译 + adb push + trace + 验证
make smoke-web RUN=<call_dir> SMOKE_ARGS='--all-surfaces'
make smoke-ui BASE=http://127.0.0.1:18900 UI_SMOKE_ARGS='--browser chromium'
```

`make test-v2` 运行 Python 语法检查、Rust fmt 检查、Rust 各 crate 测试、Solid 前端生产构建。
`make smoke-web` 运行实时 Rust 服务器 API/性能关卡。
`make smoke-ui` 运行 Playwright 浏览器事件冒烟测试。
`make test-device` 交叉编译 ARM64 测试二进制，推送到设备，trace 并验证输出
（需要 NDK + adb 设备连接）。

Rust 服务器在 `/api/*`、`/openapi.json`、`/ws/jobs` 下提供 API，
其余路径回退到 `frontend/dist` 中的构建产物。

### 文档

当前权威文档：

- `README.md`：面向用户的快速上手和当前 UI 行为。
- `AGENTS.md` / `CLAUDE.md`：仓库内 agent 规则和工作流。
- `TODO.md`：唯一的 backlog。完成的实施计划不保留为活跃 TODO。
- `REFERENCES.md`：外部算法/工具引用和当前测试关卡。
- `docs/PER_CALL_TRACE_DESIGN.md`：per-call trace 布局和记录合同。
- `docs/trace-decompiler-design.md`：反编译器/BN/HLIL 路由设计。
- `docs/ai-cli-xsign-workflow.md`：使用 CLI 溯源/VM/内存/JNI 命令的 AI 工作流。

### Trace 格式

`trace.bin` 每条记录 272 字节。Per-call 目录命名：

```text
calls/call_<idx>_tid<T>_<records>r_<ms>ms/
```

格式变更需要显式 meta 版本号升级和迁移路径。
