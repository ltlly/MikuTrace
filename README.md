# traceMiku

traceMiku 是面向 Android 真机 ARM64 的指令级动态追踪和运行时分析工具。它记录真实
执行路径，并提供 CFG、调用树、寄存器与内存查询、污点追踪、数据来源、密码特征扫描、
本地三层 IL 和 Web 交互分析。

项目不试图替代 IDA、Ghidra 或 Binary Ninja。静态工具负责完整代码结构，traceMiku
通过统一的 `(SO, 静态偏移)` 坐标补充真实跳转目标、运行时值、解密后内存和跨函数
数据来源。

## 目录

```text
tracer/                         Frida 设备端采集器
rust/crates/tracemiku-core/     分析语义和数据模型
rust/crates/tracemiku-cli/      JSON CLI
rust/crates/tracemiku-server/   Axum API 与静态站点
frontend/                       Solid Web UI
tools/hooks/                    目标相关 JSON 配置
examples/                       示例配置与算法验证
docs/                           当前契约和专题指南
docs/FEATURES.md                全量功能目录（新人/AI 的功能入口）
```

## 环境

- Python 3.11+ 与 `uv`
- Rust 工具链由 `rust/rust-toolchain.toml` 固定
- Node.js 与 npm
- 真机采集需要 adb、root 和 Frida 17.x

安装前端和采集器依赖：

```bash
npm --prefix frontend install
npm --prefix tracer install
npm --prefix tracer run build
```

`_agent.js` 是默认采集器，由 `tracer/src/` 编译生成；仓库内的
`agent_cmodule_v5.js` 只用于 `--mode legacy` 回退。

## 快速开始

```bash
# 环境诊断
./tracemiku doctor --pkg com.example.app

# 采集指定导出函数
./tracemiku trace --pkg com.example.app --so libtarget.so \
  --method nativeFn --out traces/run1

# 不启用 Stalker 的轻量调用探测
./tracemiku probe --pkg com.example.app --so libtarget.so --duration 10

# 查看采集结果
./tracemiku list traces/run1 --json
./tracemiku info traces/run1/calls/<call_dir> --json

# 启动 Web UI
./tracemiku web traces/run1/calls/<call_dir> --port 18900
```

需要 Binary Ninja HLIL/CFG 时传入目标 SO：

```bash
./tracemiku web <call_dir> --so /path/to/libtarget.so --port 18900
```

## trace 捕获是怎么工作的

默认注入模型是 **attach**；`--spawn` 提供 Frida 原生 spawn-gating 路径。进程定位
优先级：

1. `--attach-pid <pid>`：直接 attach。
2. `--spawn`：行为与 `frida` 直接 spawn 一致——`enable_spawn_gating` →
   `device.spawn(<pkg>)`（进程挂起）→ attach → agent init → `resume`。不
   force-stop、不 `pm clear`；在进程最早执行点完成注入，适合必须在隐私弹窗/
   反调试初始化前就位的目标。
3. `--launch`：`am force-stop`（不清数据）+ monkey 拉起，拿到 pid 后立即 attach；
   适合必须保留登录/本地状态的场景。
4. 只给 `--pkg`：在设备上找已运行的进程后 attach；找不到会列出可能匹配的进程并
   提示先启动 app。fork 出来的子进程由 `--enable-fork-hook` + `--child-trace-mode`
   做 race-attach，不走 spawn-gating。

一次 `trace` 的执行顺序：

```text
参数校验与互斥检查
→ (可选) launch 启动进程；--spawn 走 gating 挂起
→ 选择 agent（默认 tracer/_agent.js，legacy 回退 agent_cmodule_v5.js）
→ 建输出目录 <out>/calls/，写顶层 meta 骨架
→ 加载 --jni-hooks / --suicide-patch-spec 等 JSON spec
→ 组装 AGENT_OPTS，device.attach(pid) → load → init(AGENT_OPTS)
→ agent 编译 CModule，定位目标 SO（未加载则 hook dlopen 等待），
  按 --fn-offset / --export / --method 解析入口并安装 hook
→ --spawn 时 init 完成后 device.resume(pid) 放行进程
→ 入口命中后 Stalker 开始记录，设备端先落盘，host 边采边拉
→ 到 --duration 或 Ctrl-C：stats → force_flush → unload → detach；
  未收尾的调用标 truncated，--spawn 时最后 disable_spawn_gating
→ trace-end 消息驱动 host 拉回 trace.bin/sidecar 并写 per-call meta.json
```

中途被杀可用 `./tracemiku finalize <run>` 扫 `_pending_call_*` 重建 meta。

### 增加反调试怎么改

反调试能力是默认关闭的插件，位于 `tracer/src/anti_detect/`。新增一个：

1. 新建 `tracer/src/anti_detect/<id>.ts`，实现 `AntiDetectPlugin` 接口
   （`id`/`name`/`description`/`install(config)`），hook 和队列必须有上限，
   不能写死包名、SO 版本或固定偏移。
2. 在 `tracer/src/anti_detect/plugin_interface.ts` 的 `BUILTIN_PLUGINS` 注册。
3. 接线：现有三个插件通过专用布尔参数（`--hide-rwx-maps` / `--block-self-kill` /
   `--patch-suicide`）经 `tracemiku` 的 `AGENT_OPTS` 传入；agent 端已有通用的
   `opts.antiDetect` 插件数组加载逻辑，新插件可沿用布尔模式，或给 host 补
   `--anti-detect` 参数后走数组模式。目标相关补丁 spec 放 `tools/hooks/*.json`。
4. `npm --prefix tracer run build` 重新生成 `_agent.js`，再跑 typecheck 与
   `make test-device` 验证。

### 只复用分析部分：对接文件结构

不用 Frida 采集器、只把 `tracemiku` 当作分析后端时，最小对接只需一个 per-call
目录：

```text
<run>/calls/call_<序号>_tid<线程>_<记录数>r_<耗时>ms/
  trace.bin                 # 必填：N × 272 字节记录
  meta.json                 # 必填：至少 {"records": N}
  external_writes.bin       # 可选：每条 17 字节 (idx u64 + addr u64 + byte u8)
  jni_hooks.jsonl           # 可选：JNI 事件 JSONL
  memory_snapshot.bin       # 可选：初始内存快照
<run>/meta.json             # 可选：method/cmd/module/fn_addr 等；缺失也可加载
```

`trace.bin` 每条记录固定 272 字节小端：`pc u64` + `x0..x28/fp/lr` 共 31 个 `u64`
+ `sp u64` + `nzcv u32` + `inst u32`。完整契约见
[Trace 数据契约](docs/PER_CALL_TRACE_DESIGN.md)；最小可运行样例直接看
`scripts/build_smoke_trace.py`（生成的目录能被所有分析命令读取）。

## 面向 AI 的查询

CLI 是首选自动化入口，输出为结构化 JSON。所有分析命令都由统一入口透传，
完整功能目录见 [docs/FEATURES.md](docs/FEATURES.md)，机器可读清单用
`./tracemiku capabilities`：

```bash
./tracemiku capabilities                    # 全部命令/参数/默认值的 JSON
./tracemiku resolve <call_dir> --so libtarget.so --off 0x1234
./tracemiku indirect-targets <call_dir> --so libtarget.so --off 0x1234
./tracemiku reg-at <call_dir> --reg x0 --so libtarget.so --off 0x1234
./tracemiku mem-export <call_dir> --so libtarget.so --off 0x2000 --len 0x100
./tracemiku coverage <call_dir> --fn trace:F0
./tracemiku taint-bwd <call_dir> --start 1000 --reg x0
./tracemiku dec-summary <call_dir>
```

地址和偏移默认按十六进制解析（`10` 即 `0x10`），需要十进制时加 `d` 前缀（`d16`）。
每个命令的参数以 `./tracemiku <cmd> --help` 为准。已有专用命令时不要使用通用
`api`，也不要仅为查询而启动 Web server。

## 分析边界

`MemShadow` 只对观测到的字节负责。来源 `w`、`r`、`x`、`i` 分别表示 trace store、
trace load、外部写和初始快照；`??` 表示未知，绝不能当作零。详情见
[内存完整性设计](docs/memory-completeness-design.md)。

TraceIR、本地 LLIL -> MLIL -> HLIL 和 trace 增强反编译管线均为当前能力，区别见
[反编译架构](docs/trace-decompiler-design.md)。Trace 目录及二进制格式见
[Trace 数据契约](docs/PER_CALL_TRACE_DESIGN.md)。

## 开发与测试

```bash
make test-fast       # Python 检查 + 前端静态审计 + Rust core/CLI
make test-contract   # 契约审计 + CLI/server/core 契约测试 + tracer 格式契约 + CLI/API 一致性
make test-v2         # Rust 全工作区 + 前端构建 + CLI/API 一致性
npm --prefix tracer run typecheck
make test-device     # 需要 Android 设备
```

契约测试（`make test-contract`）是黑盒/公共接口级：CLI 的每个命令输出和 server
的每个 route 都必须在 `scripts/contract_audit.py` 声明的契约测试文件中有 schema
校验与语义断言覆盖；tracer 的 272 字节记录格式有独立的 TS 契约测试；CLI 与 server
同分析结果逐字段一致（`scripts/rust_cli_web_parity.py`）。CLI 输出由
`rust/crates/tracemiku-cli/src/output_types*.rs` 的类型化模型序列化，字段名与结构
是 AI 消费方的稳定契约，改动必须同步更新契约测试。

工程规则见 [AGENTS.md](AGENTS.md)，当前路线图见 [TODO.md](TODO.md)，性能基线见
[BENCHMARKS.md](BENCHMARKS.md)。
