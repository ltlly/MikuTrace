# traceMiku 功能目录

本文件是仓库内全部功能的**单一使用入口**。新人或 AI 接入仓库时先读 [README](../README.md)
（定位与快速开始），再用本文件查“有没有这个功能、该用哪个命令”，最后用
`./tracemiku <cmd> --help` 查参数细节。不要在 README、AGENTS.md 或其他设计文档里
重复维护命令用法；那些文档只做定位、规则与契约说明。

## 阅读规则

- 统一入口：所有子命令都通过 `./tracemiku` 调用。设备采集与少量编排命令由 Python
  层实现，其余 93 个分析命令透传给 Rust CLI（`tracemiku-cli`）。不要直接调用
  `rust/target/*/tracemiku-cli`。
- 机器可读清单：`./tracemiku capabilities` 输出全部命令、参数和默认值的 JSON，
  供 AI/脚本编程式发现能力。新增命令后该清单自动更新（由 clap 生成）。
- 参数事实源：本文件不复制参数细节；以 `./tracemiku <cmd> --help` 为准。
- 地址与偏移默认十六进制（`10` = `0x10`），十进制用 `d` 前缀（`d16` = 16）。
- CLI 优先：存在专用命令时不要用通用 `api`；不要仅为查询启动 Web server。
- 输出契约：字段名、类型和嵌套结构是 AI 消费方的稳定契约，定义在
  `rust/crates/tracemiku-cli/src/output_types*.rs` 并由 `contract_*` 测试锁定。
  对应 JSON schema 在 `docs/schema/`。

## 1. 元数据与入口

| 命令 | 用途 | 备注 |
|---|---|---|
| `capabilities` | 全部命令/参数/默认值的机器可读 JSON | AI 发现能力的首选入口 |
| `completions` | 生成 shell 补全脚本 | `--help` 查看 shell 类型 |
| `stats` | trace 元数据 JSON | |
| `meta` | 原始 `/api/meta` 响应 | 与 `stats` 的差别见各自 `--help` |
| `list` | 列 run 或 run 下的 calls | Python 层实现，默认人类可读表，`--json` 输出 JSON |
| `info` | run/per-call 元信息 | Python 层实现；`--json` 转发 Rust JSON 输出 |
| `bg-status` | 后台反编译任务状态 | 配合 `decomp-status` 使用 |
| `decomp-status` | 反编译任务状态 | |

```bash
./tracemiku capabilities | python3 -m json.tool | head
./tracemiku list traces/run1 --json
./tracemiku info <call_dir> --json
```

## 2. 地址与符号解析（与 IDA/BN/Ghidra 协同）

`(SO, 静态偏移)` 坐标是本项目与静态工具协作的统一语言。

| 命令 | 用途 | 备注 |
|---|---|---|
| `resolve` | (SO,offset) ↔ 绝对 PC 双向解析，并返回执行事实 | `--so` 支持全路径/basename/前缀/子串 |
| `resolve-map-addr` | 对保存的 `/proc/<pid>/maps` 文件解析地址 | |
| `resolve-trace-addr` | 按 trace meta 的模块区间解析地址 | |
| `resolve-elf-symbol` | ELF 虚拟偏移 → 最近符号 | 静态侧辅助 |
| `functions` | 列出函数（symbol 与 trace 来源） | |
| `so-stats` | 各 SO 的 trace 统计 | |

```bash
./tracemiku resolve <call_dir> --so libfoo.so --off 0x1234
./tracemiku resolve <call_dir> --addr 0x7a1234abcd
./tracemiku functions <call_dir>
```

## 3. 记录检索与反汇编搜索

| 命令 | 用途 | 备注 |
|---|---|---|
| `records` | 按区间导出指令记录，可选寄存器列 | `--start/--count/--regs/--indices` |
| `record` | 单条记录 `GET /api/record/{idx}` | |
| `idxs-for-pc` | 某 PC 被执行的 trace 下标集合 | |
| `search-pc` | 按 PC 搜 | |
| `search` | 反汇编/操作数正则搜索 | |
| `search-asm` | `search` 的旧名别名 | |
| `query` | 通用查询路由 `GET /api/query` | 有专用命令时优先专用命令 |
| `asm-tokens-for-pcs` | 批量 PC 的汇编 token | |

```bash
./tracemiku records <call_dir> --start 0 --count 50 --regs x0,x1,sp
./tracemiku record <call_dir> 0
./tracemiku search <call_dir> 'ldr'
```

## 4. 控制流：CFG、路径与间接跳转

| 命令 | 用途 | 备注 |
|---|---|---|
| `cfg` | 函数控制流图数据 | |
| `cfg-svg` | CFG 的 SVG 渲染 | |
| `idxs-for-block` | 块命中次数与所属记录 | |
| `block-for-pc` | PC → 基本块 | |
| `block` | 基本块详情 | |
| `loops` | 循环检测结果 | |
| `coverage` | 函数执行覆盖 + 分支方向塌缩 | 静态“可能双向”的分支在此塌缩为真实方向 |
| `indirect-targets` | `br/blr` 的运行时真实跳转目标分布 | 静态工具拿不到的事实 |
| `backtrace` | 指定位置的调用回溯 | |

```bash
./tracemiku cfg <call_dir> --fn trace:F0
./tracemiku coverage <call_dir> --fn sub_7f10
./tracemiku indirect-targets <call_dir> --so libfoo.so --off 0x1234
```

## 5. 调用关系

| 命令 | 用途 | 备注 |
|---|---|---|
| `call-tree` | 调用树 | `--max-depth` 控制深度 |
| `call-chain` | 命中函数之间的调用链 | |

## 6. 寄存器：运行时值与时序

| 命令 | 用途 | 备注 |
|---|---|---|
| `reg-at` | (SO,offset)/PC 处的寄存器值 + 跨执行去重分布 | 首选点查 |
| `reg-value-at` | 单次执行的寄存器值 | |
| `reg-at-idx` | `reg-value-at` 的旧名别名 | |
| `last-write-of-reg` | 寄存器最近一次被写的位置 | |
| `next-use-of-reg` | 寄存器下一次被读的位置 | |
| `reg-timeline` | 寄存器随 trace 区间变化的时间线 | 最多 `--max-points` 点 |

```bash
./tracemiku reg-at <call_dir> --reg x0 --so libfoo.so --off 0x1234
./tracemiku reg-value-at <call_dir> --idx 1000 --reg x0
./tracemiku last-write-of-reg <call_dir> --idx 1000 --reg x0
```

## 7. 内存：解密后字节与写入来源

| 命令 | 用途 | 备注 |
|---|---|---|
| `mem-dump` | 内存范围 hex dump | 查看当前值 |
| `mem-export` | 按 (SO,offset,len) 导出运行时解密字节 | `--out` 可直接写文件给 IDA/BN/Ghidra loadfile |
| `mem-tenet` | 每个字节的来源（writer idx/初始快照/未知） | 不虚构缺失内存 |
| `mem-diff` | 两段内存差异 | |
| `mem-flow` | 内存写入流 | |
| `last-write-of-addr` | 某地址最后一次写入者 | |
| `idxs-touching-addr` | 触碰某地址的全部记录 | |
| `idxs-touching-range` | 触碰某范围的全部记录 | |
| `find-mem-pattern` | 在 trace 访问过的内存中找字节模式 | |
| `mem-writes-in-range` | 范围内的全部内存写 | |
| `byte-writer-map` | 缓冲区每个字节的最新写入者映射 | 比逐地址查询高效 |

```bash
./tracemiku mem-dump <call_dir> --addr 0x7a12340000 --count 64
./tracemiku mem-export <call_dir> --so libfoo.so --off 0x2000 --len 0x100 --out /tmp/dec.bin
./tracemiku last-write-of-addr <call_dir> --addr 0x7a12340000
./tracemiku mem-tenet <call_dir> --addr 0x7a12340000 --length 32
```

## 8. 污点与依赖（先看“选择指南”再选命令）

| 命令 | 用途 | 备注 |
|---|---|---|
| `taint-fwd` | 从 (start,reg) 正向逐指令传播 | 需要逐步 parent/taint_depth 时用 |
| `taint-bwd` | 从 (start,reg) 反向追来源 | 可选 `--through-mem/--cross-fn-call` |
| `data-chase` | 沿寄存器数据流追踪，跳过 sp/fp/lr 噪声 | |
| `dep-graph` | 依赖图 | |
| `bfs-slice` | 后向 BFS 依赖切片，多种子并/交 | 比 taint 快，只想要“依赖哪些行”时用 |
| `forward-dep-tree` | def→use DAG，某值被谁消费 | `dep-graph/bfs-slice` 的逆方向 |
| `byte-lineage` | 单字节沿内存写与 VM 源寄存器回追 | 输出级分析首选 |

```bash
./tracemiku taint-bwd <call_dir> --start 1000 --reg x0 --max-count 200
./tracemiku bfs-slice <call_dir> --idx 1000 --reg x0
./tracemiku byte-lineage <call_dir> --addr 0x7000 --before-idx 1000 --depth 5
```

## 9. 字符串与 JNI 观察

| 命令 | 用途 | 备注 |
|---|---|---|
| `strings` | 从 trace 观察到的字符串 | |
| `string-provenance` | 某字符串每个字节的来源 | |
| `jni-strings` | JNI NewStringUTF 输出串 | |
| `jni-calls` | JNI 调用列表 | |
| `jni-events` | JNI 事件（含参数/返回值） | |
| `jobj-history` | 指定 JNI jobject 的历史 | |
| `jni-output-strings` | NewStringUTF key/value 对 | |
| `scan-jni-output-strings` | 递归扫描目录下全部 `jni_hooks.jsonl` | run 级批量发现 |

```bash
./tracemiku jni-events <call_dir>
./tracemiku scan-jni-output-strings traces/run1 --key authorization
```

## 10. 输出分析：从最终输出反推生成过程

| 命令 | 用途 | 备注 |
|---|---|---|
| `output-backtrace` | 已知输出字符串/字节 → 逆向回溯报告 | 支持 JNI key 或直接给 value |
| `output-map` | 文本输出/Base64 分组 → writer runs 与语义字节偏移 | |

```bash
./tracemiku output-backtrace <call_dir> --key authorization
./tracemiku output-map <call_dir> --value 'AAECAwQ='
```

## 11. 密码学分析

| 命令 | 用途 | 备注 |
|---|---|---|
| `crypto` | 组合分析：常量扫描 + ARM CE 指令检测 | Python 层入口，转发 Rust |
| `crypto-scan` | 密码学常量指纹扫描 | |
| `hash-finalize-detect` | 检测 hash finalize 模式 | |
| `hash-input-search` | 已知目标摘要反查输入（指定算法组合） | POST |
| `diff-traces` | 多条 trace 的稳定/变化字节对比 | 找输入无关的固定结构 |

```bash
./tracemiku crypto <call_dir>
./tracemiku hash-input-search <call_dir> --target-bytes deadbeef --inputs 0x41 --algos md5,sha1
./tracemiku diff-traces <call_a> <call_b> --show-offsets
```

## 12. VM 与去混淆

VM 分析命令需要显式给出该目标 VM 的寄存器角色（没有跨目标默认值）：

```bash
./tracemiku vm-ops <call_dir> \
  --vm-ip-reg x9 --vm-state-reg x10 --vm-dispatch-reg x11
```

| 命令 | 用途 | 备注 |
|---|---|---|
| `ollvm-detect-vm` | 检测 OLLVM 风格 VM | 不需要寄存器 profile |
| `vm-slice` | 紧凑的 VM 指令记录切片 | 需要 `--vm-ip-reg` 等 |
| `vm-ops` | 把动态记录聚合成虚拟指令（读字节码/槽/分发表） | 需要 `--vm-ip-reg` 等 |
| `vm-backstep` | VM store/load 链的单步回溯 | 需要 `--vm-ip-reg` 等 |
| `vm-backchain` | 迭代 backstep 输出紧凑回链 | 需要 `--vm-ip-reg` 等 |
| `vm-backtree` | VM 上游/前沿的分支回溯树 | 需要 `--vm-ip-reg` 等 |
| `auto-phase-detect` | 自动检测执行阶段 | `--detect-byte-streams` 检测字节流阶段 |

VM profile 参数：`--vm-ip-reg`（指令指针）、`--vm-state-reg`（状态/虚拟寄存器基址）、
`--vm-dispatch-reg`（分发表基址）必填；`--vm-infra-regs` 可选（额外基础设施寄存器）。
`byte-writer-map` / `output-map` / `output-backtrace` 只有在开启 VM 链分析时
（如 `--vm-chain-steps`、`--tree-depth`）才要求这些参数。

## 13. 反编译与 IL

| 命令 | 用途 | 备注 |
|---|---|---|
| `dec-summary` | 反编译 summary | `GET /api/dec/summary` |
| `dec-fn` | 单函数反编译 markdown | `GET /api/dec/fn/{id}` |
| `dec-models` | 反编译模型列表 | |
| `llil-pipeline` | 完整 LLIL→MLIL→HLIL 流水线 | POST |
| `llil-render` | IL 渲染 | POST |
| `hlil-for-pc` | Binary Ninja HLIL（按 PC） | 需要 BN sidecar 与目标 SO |
| `hlil-for-fn` | Binary Ninja HLIL（按函数） | 需要 BN sidecar 与目标 SO |
| `bn-cfg-for-pc` | Binary Ninja CFG（按 PC） | 需要 BN sidecar 与目标 SO |
| `bn-cfg-svg-for-pc` | Binary Ninja CFG 的 SVG | 需要 BN sidecar 与目标 SO |
| `bn-sidecar-status` | BN sidecar 状态 | |
| `decomp-status` / `bg-status` | 反编译任务状态 | 见第 1 节 |

Python 层另有 `./tracemiku dec <call_dir>`：把反编译结果按 tier 落盘成 markdown
目录（`--summary`/`--fn` 可直接打印），是 LLM 消费的 facade；查询单函数 JSON 时
优先 `dec-summary`/`dec-fn`。

```bash
./tracemiku dec-summary <call_dir>
./tracemiku dec-fn <call_dir> --fn trace:F0
./tracemiku dec <call_dir> --summary
```

## 14. 观察点、函数与 fork

| 命令 | 用途 | 备注 |
|---|---|---|
| `watch` | 观察点扫描：`reg-change`/`reg-equals`/`mem-touch` | Python 层入口，转发 Rust |
| `fn-summary` | 函数命中频次与热门块 | `--fn` 必填 |
| `fork-events` | fork 事件（反调试常用） | 采集时需 `--enable-fork-hook` |

## 15. 设备采集层（Python 原生子命令）

这些命令不是查询，而是设备工作流：

| 命令 | 用途 |
|---|---|
| `trace` | Frida 采集；`--so` 必填，入口三选一 `--fn-offset/--export/--method` |
| `probe` | 轻量 Interceptor 导出函数计数，不启动 Stalker、无 trace.bin |
| `doctor` | 采集前置检查（adb/root/frida/SELinux/包名/输出目录） |
| `finalize` | 恢复中断的 trace：扫 `_pending_call_*` 补 meta 并重命名 |
| `web` | 启动 Rust Solid SPA；`--so` 可启用 HLIL 反编译 tab |
| `view` | 旧 Web 查看器，已被 `web` 取代 |
| `query` | 旧版查询包装（`records/backward-taint/...` 语法与透传命令不同），保持兼容；新用法优先直接调用对应透传命令 |
| `api` | 任意 route 兜底；仅当没有专用命令时使用 |

采集入口过滤：`--cmd` 必须与 `--cmd-arg` 一起显式给定（按 JNI 入口整数参数过滤，
无目标默认值）。反检测插件（`--patch-suicide/--hide-rwx-maps/--block-self-kill`）
默认关闭，按需显式开启。

```bash
./tracemiku doctor --pkg com.example.app
./tracemiku trace --pkg com.example.app --so libfoo.so --export sign \
  --out traces/run1
./tracemiku probe --pkg com.example.app --so libfoo.so --duration 10
./tracemiku finalize traces/run1
./tracemiku web <call_dir> --port 18900
```

## 16. 兜底：`api`

只有不存在专用命令时才用：

```bash
./tracemiku api <call_dir> /api/backtrace --method GET -p idx=1000
./tracemiku api <call_dir> /api/llil/render --method POST --json-body '{...}'
```

server 路由与 CLI 命令一一对应（命令表中的 route 即路由名）；需要完整路由表时以
`./tracemiku capabilities` 与 server OpenAPI 为准。仅由 server 暴露、无专用 CLI
命令的接口：

- `/api/llil/llm`：可选 LLM 调用路由（本地分析不依赖 LLM）
- `/v1/chat/completions`：OpenAI 兼容聊天接口
- `/ws/jobs`：任务状态 WebSocket（前端使用）

这些接口通过 `./tracemiku api <call_dir> <route>` 访问。

## 选择指南（防止重复造轮子）

- “某行依赖哪些行” → `bfs-slice`（快）；要逐条传播边与深度 → `taint-bwd`。
- “某值之后被谁消费” → `forward-dep-tree`；单步寄存器来源 → `last-write-of-reg`。
- “最终输出/字符串是怎么算出来的” → `byte-lineage`，或 `output-backtrace`/
  `output-map`（有 Base64/文本结构时）。
- “这个地址最后一次谁写的” → `last-write-of-addr`；缓冲区级映射 → `byte-writer-map`。
- “想要运行时解密后的完整字节” → `mem-export`；只想看某个时刻内存 → `mem-dump`。
- “静态分析说这里有跳转，实际跳哪” → `indirect-targets`；函数级路径 → `coverage`。
- “发现动态 VM 解释器” → 先用 `ollvm-detect-vm` 初筛，再按 profile 用 `vm-ops`
  聚合、`vm-back*` 回溯。
- “给 LLM 准备函数上下文” → `dec <call_dir> --tier hot` 落盘 markdown，或
  `dec-summary`/`dec-fn` 拿 JSON/markdown。

## 17. Web UI 面板

`./tracemiku web <path>` 启动 Solid SPA。面板对应关系（前端只负责交互与显示，
分析全部来自 core/API）：

| 面板 | 功能 |
|---|---|
| Records / Query | 指令流浏览与 JSON 查询 |
| CFG | 函数控制流图（trace 与 BN 两种来源） |
| TraceForPc / Xref | PC 命中与交叉引用 |
| CallTree / Backtrace | 调用树与回溯 |
| Registers / Watchpoints | 寄存器与观察点 |
| Memory / Strings | 内存与字符串及来源 |
| Taint / Slice | 污点与依赖切片 |
| Crypto | 密码学扫描结果 |
| Decompiler / PseudoC / HLIL | 反编译与伪代码 |
| Functions / SO Filter / Meta | 函数、模块与元信息 |
| Forks / Settings | fork 事件与界面设置 |

## 18. tools/ 与 examples/

| 文件 | 用途 | 备注 |
|---|---|---|
| `tools/capture_sign_headers.js` | Frida 脚本：抓 OkHttp/HttpURLConnection 签名头 | 通用头名模式，与采集器独立 |
| `tools/native_sign_hooks_v4.js` | Frida 脚本：native 签名 SO hook 事件 | |
| `tools/native_sign_scan.py` | Python 封装：hook native crypto/签名 SO | |
| `tools/spawn_hook.py` | spawn 注入通用运行器 | `python tools/spawn_hook.py <pkg> <hook.js>` |
| `tools/test_hooks_interact.py` | hook 交互测试辅助 | |
| `tools/vm_replay_plan_eval.py` | 消费 `vm-ops --replay-plan` 输出的独立评估器 | 自带 `--verify-emitted-python` |
| `tools/hooks/*.json` | 目标相关 hook/type spec | 目标配置的唯一允许位置之一 |
| `examples/llm_cookbook.py` | LLM 可选能力示例 | |
| `examples/<target>/` | 目标示例配置与算法验证 | 目标知识只能放这里或 `tools/hooks/` |

## 文档地图（哪份文档负责什么）

| 文档 | 责任范围 |
|---|---|
| `README.md` | 项目定位、环境、快速开始、文档入口 |
| `docs/FEATURES.md`（本文件） | 全量功能目录与命令选择，唯一命令用法汇总 |
| `AGENTS.md` | 工程规则与不可破坏边界（唯一规范） |
| `TODO.md` | 未完成路线图（唯一 backlog） |
| `docs/PER_CALL_TRACE_DESIGN.md` | trace.bin/meta.json 数据契约 |
| `docs/memory-completeness-design.md` | MemShadow 来源模型与消费者规则 |
| `docs/trace-decompiler-design.md` | TraceIR / 本地三层 IL / trace 增强 IL 三条路径 |
| `docs/anti-detection-catalog.md` | 设备采集反检测层次与故障分类 |
| `tracer/README.md` | 设备端 agent 入口与数据通路 |
| `rust/README.md` | Rust 工作区 crate 与开发约束 |
| `BENCHMARKS.md` | 性能与质量基线 |
| `REFERENCES.md` | 外部参考材料 |
| 各命令 `--help` | 参数、默认值与约束的唯一事实源 |

维护规则：新增命令时，capabilities 会随 clap 定义自动更新；同时必须在本文件
对应分组加一行用途说明，并保证示例可执行。删除/改名命令时同步更新本文件。
