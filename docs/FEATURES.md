# traceMiku 功能目录

本文件是仓库内全部功能的**单一使用入口**。新人或 AI 接入仓库时先读 [README](../README.md)
（定位与快速开始），再用本文件查“有没有这个功能、该用哪个命令”，最后用
`./tracemiku <cmd> --help` 查参数细节。不要在 README、AGENTS.md 或其他设计文档里
重复维护命令用法；那些文档只做定位、规则与契约说明。

## 阅读规则

- 统一入口：所有子命令都通过 `./tracemiku` 调用。设备采集与能力发现由 Python
  层实现，全部分析命令透传给 Rust CLI（`tracemiku-cli`）。不要直接调用
  `rust/target/*/tracemiku-cli`。
- 机器可读清单：`./tracemiku capabilities` 返回统一入口的命令摘要，
  `./tracemiku capabilities --command <name>` 返回该命令的完整参数与默认值。
  `schema_version=2`，采集参数来自 argparse，分析参数来自 Rust clap。
- 参数事实源：本文件不复制参数细节；以 `./tracemiku <cmd> --help` 为准。
- 地址与偏移默认十六进制（`10` = `0x10`），十进制用 `d` 前缀（`d16` = 16）。
- 使用专用命令；统一入口不再提供 Web、BN 展示、通用查询包装和旧别名。
- 输出契约：字段名、类型和嵌套结构是 AI 消费方的稳定契约。
  基础响应类型位于 `rust/crates/tracemiku-core/src/analysis/`，组合报告类型位于
  `analysis/reports/output_*.rs`，动态 JSON 同样由 `contract_*` 测试锁定。
  已生成的部分报告 schema 在 `docs/schema/`。
- Rust 执行层失败退出码为 1，stdout 是 `status=error` 与 `error.code/message/details`
  的 JSON（details 可省略）；参数解析错误退出码为 2，诊断写到 stderr。部分旧查询
  仍用结果内 `status=error` 表达失败，消费方还需检查结果状态。

CLI 直接调用 core；静态工具独立使用，通过模块偏移与证据对齐。
架构与边界见 [采集与 CLI 设计](CLI_FIRST_DESIGN.md)。

## 1. 元数据与入口

| 命令 | 用途 | 备注 |
|---|---|---|
| `capabilities` | 统一入口的采集与分析命令摘要 | 指定 `--command` 按需取得参数 |
| `completions` | 生成 shell 补全脚本 | `--help` 查看 shell 类型 |
| `stats` | 单次 trace 的记录数与有界模块映射摘要 | 模块按映射大小排序；执行频次用 `so-stats` |
| `meta` | 单次 trace 的采集元数据与格式信息 | 读取采集上下文；运行完成度用 `info` |
| `list` | 列 run 或 run 下的 calls | `--json` 输出一个 JSON 数组；默认逐行 JSON |
| `info` | run/per-call 元信息与完成度 | Rust 实现，支持 run 与单次调用 |

```bash
./tracemiku capabilities
./tracemiku capabilities --command records
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
| `functions` | 列出函数（symbol 与 trace 来源） | 无反编译可用性字段，不接受 `bn:`/`cfg:` ID |
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
| `record` | 单条记录与寄存器注释详情 | 批量导出用 `records` |
| `idxs-for-pc` | 某 PC 被执行的 trace 下标集合 | |
| `search` | 反汇编/操作数正则搜索 | |

```bash
./tracemiku records <call_dir> --start 0 --count 50 --regs x0,x1,sp
./tracemiku record <call_dir> 0
./tracemiku search <call_dir> 'ldr'
```

## 4. 控制流：CFG、路径与间接跳转

| 命令 | 用途 | 备注 |
|---|---|---|
| `cfg` | 函数控制流图数据 | |
| `idxs-for-block` | 块命中次数与所属记录 | |
| `block-for-pc` | PC → 基本块 | |
| `block` | 基本块详情 | |
| `loops` | 循环检测结果 | |
| `coverage` | 函数执行路径与观测分支分布 | 单向观测不证明另一方向不可能执行 |
| `indirect-targets` | `br/blr` 的运行时真实跳转目标分布 | 静态工具拿不到的事实 |
| `backtrace` | 指定位置的调用回溯 | |

```bash
./tracemiku cfg <call_dir> --fn sym:f_root
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
| `last-write-of-reg` | 寄存器最近一次被写的位置 | |
| `next-use-of-reg` | 寄存器下一次被读的位置 | |
| `reg-timeline` | 寄存器随 trace 区间变化的时间线 | 最多 `--max-points` 点 |

```bash
./tracemiku reg-at <call_dir> --reg x0 --so libfoo.so --off 0x1234
./tracemiku reg-value-at <call_dir> --idx 1000 --reg x0
./tracemiku last-write-of-reg <call_dir> --before 1000 --reg x0
```

## 7. 内存：解密后字节与写入来源

| 命令 | 用途 | 备注 |
|---|---|---|
| `mem-dump` | 内存范围 hex dump | 查看当前值 |
| `mem-export` | 按 (SO,offset,len) 导出运行时解密字节 | `--out` 可直接写文件给 IDA/BN/Ghidra loadfile |
| `mem-tenet` | 每个字节的来源（writer idx/初始快照/未知） | 不虚构缺失内存 |
| `mem-diff` | 相邻 trace 记录间的内存差异 | |
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
| `crypto` | 组合分析：常量扫描 + ARM CE 指令检测 | Rust 专用命令 |
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

## 13. Trace 锚定验证

反编译由外部静态工具承担；本地分析不依赖 Binary Ninja。

| 命令 | 用途 | 备注 |
|---|---|---|
| `trace-replay` | 用真实 pre/post 状态检查 ARM64 指令，返回首个发散/证据缺口与补采建议 | |

### Trace 锚定验证与证据来源

`trace-replay` 直接使用已有 trace，所需内存索引按需构建。

```bash
./tracemiku trace-replay <call_dir> --start 100 --count 200
```

`trace-replay` 的 `mode=per_instruction_anchored_arm64`：每条指令重新锚定捕获的寄存器
前状态，推演已支持的 ARM64 指令，并比较直接后状态。硬上限 10000 条；`checked` 只统计已匹配的
转移。`matched` 表示请求窗口内匹配，`diverged` 表示寄存器/PC 不匹配，`stopped` 表示
缺少证据、语义不支持或达到上限。`stop` 包含 idx、PC、原因、预期/实际值和
`next_capture`。参数无效返回错误，不默默换窗口。

支持范围：NOP、MOVN/MOVZ/MOVK、ADD/SUB（立即数与移位寄存器，含 NZCV）、移位
逻辑运算、ADR/ADRP、普通分支及整数 LDR/STR（无符号偏移、非缩放及 pre/post 写回）。
其他编码明确返回 `unsupported_instruction`，不会假设为无操作。

内存输入只采用此前的 store、外部写和初始快照；绝不拿本次 load 的输出验证自己。
内存来源只沿连续且语义已支持的指令向前回看，最多 10000 条。遇到未知执行边界或
不支持的指令后，边界之前的快照和写入失效；之后的新 store/外部写可逐字节恢复证据。
超出回看上限的来源也视为未知，返回 `capture_memory_before_instruction`。
未知内存、SIMD/FP、syscall、未跟踪的 callee、丢记录和缺失直接后状态都会停止。
当前版本未接入 SIMD sidecar，不验证实际设备内存写入，也不证明完整函数、高级 IL
或未观测路径正确。`metadata_present=false` 的旧 trace 只能进行结构连续性检查，
没有完整采集质量证明；有未定位的 dropped 记录时，所有转移保守视为不确定。

从 `output-backtrace` / `byte-lineage` 找到 writer idx 后，可用 `trace-replay` 检查附近的
指令窗口，再根据 `stop.next_capture` 补采缺失内存或扩大跟踪范围。发现寄存器/PC 发散
时先核对原始编码和指令语义，避免把未验证结论继续传给 AI。

## 14. 观察点、函数与 fork

| 命令 | 用途 | 备注 |
|---|---|---|
| `watch` | 观察点扫描：`reg-change`/`reg-equals`/`mem-touch` | Rust 专用命令 |
| `fn-summary` | 函数命中频次与热门块 | `--fn` 必填 |
| `fork-events` | fork 事件（反调试常用） | 采集时需 `--enable-fork-hook` |

## 15. 设备采集与恢复

`trace/probe/doctor` 由 Python 实现；`finalize` 的恢复语义由 Rust core 提供：

| 命令 | 用途 |
|---|---|
| `trace` | Frida 采集；`--so` 必填，入口三选一 `--fn-offset/--export/--method` |
| `trace --spawn` | Frida 原生 spawn-gating：`device.spawn(pkg)` 挂起 → attach + init → resume；行为与 `frida` 直接 spawn 一致，不 force-stop/不清数据/不点同意 |
| `probe` | 轻量 Interceptor 导出函数计数，不启动 Stalker、无 trace.bin |
| `doctor` | 采集前置检查（adb/root/frida/SELinux/包名/输出目录） |
| `finalize` | 恢复中断的 trace：扫 `_pending_call_*` 补 meta 并重命名 |

采集入口过滤：`--cmd` 必须与 `--cmd-arg` 一起显式给定（按 JNI 入口整数参数过滤，
无目标默认值）。反检测插件（`--patch-suicide/--hide-rwx-maps/--block-self-kill`）
默认关闭，按需显式开启。

```bash
./tracemiku doctor --pkg com.example.app
./tracemiku trace --pkg com.example.app --so libfoo.so --export sign \
  --out traces/run1
./tracemiku probe --pkg com.example.app --so libfoo.so --duration 10
./tracemiku finalize traces/run1
```

## 16. 已移除入口的替代选择

以下入口不再接受调用，也不会出现在能力清单和补全中。旧脚本需显式迁移，未保留
自动转发别名；通用包装中的参数不保证与专用命令逐项相同，以命令帮助为准。

| 已移除入口 | 替代选择或去向 |
|---|---|
| `search-asm` | `search` |
| `search-pc` | `idxs-for-pc`，返回执行下标及分页信息 |
| `asm-tokens-for-pcs` | 展示 token 随 BN 桥接移除；执行指令用 `records`/`record` |
| `reg-at-idx` | `reg-value-at`；按 PC 的多次执行分布用 `reg-at` |
| `api`、`query` | 使用本目录中的专用记录、寄存器、内存、JNI 或污点命令 |
| `web`、`view` | Web 交互退出维护范围 |
| `bg-status`、`decomp-status`、`bn-sidecar-status` | 一次性离线命令不提供 Web 后台状态轮询 |
| `cfg-svg`、`bn-cfg-svg-for-pc` | trace 结构用 `cfg` JSON；图形渲染交给消费者 |
| `hlil-for-pc`、`hlil-for-fn`、`bn-cfg-for-pc` | 静态反编译与 CFG 由外部静态工具提供 |

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
- “给 LLM 准备函数上下文” → 用 `records`/`fn-summary`/`cfg` 拼 JSON，按模块偏移
  与外部静态工具的反编译结果对齐。

## 17. tools/ 与 examples/

### 每个 app 的目标描述与可信插件

`trace` 可加载用户自己的 JSON 目标描述、普通 JS agent 模块和 Python host 模块，
无需改项目源码或重新编译用户脚本。脱敏示例在 `examples/custom_target/`，没有真实
目标偏移或检测补丁；复制到自己的目录并填写自己的 SO/入口/命令号。

```bash
./tracemiku trace --target-profile examples/custom_target/target.json --out traces/demo
# 显式 CLI 参数覆盖 profile：例如切换到已经启动的进程
./tracemiku trace --target-profile /path/to/my/target.json --attach-pid 1234 --out traces/new
./tracemiku trace --pkg com.example.demo --so libdemo.so --export demo_entry \
  --transport frida --max-calls 4 --out traces/raw
```

- `target`：`pkg/so/method/export/fn_offset/cmd/cmd_arg`；`fn_offset` 是十六进制字符串。
  `capture` 提供采集参数默认值；未知字段、错误类型、缺失脚本、重复插件 ID 都报错，
  不静默跳过。相对 JS/Python/JNI spec 路径按 JSON 所在目录解析。
- `agent_plugins`：最多 8 个 `{id,path,config}`。普通 JS 用 `module.exports` 导出
  `apiVersion: 1`；扩展点是同步 `install/onModule/beforeTrace/dispose`，上下文含
  `config` 和有界 `emit`；`onModule` 还含 `module`，`beforeTrace` 含 `args/tid/address`。
  可选 `invoke(ctx)` 由 host 的 `script.exports_sync.plugin_call(id,payload)` 调用。
  原生 Frida API 可用；不自动提供 Java bridge。异步/Java 触发器须由用户显式管理。
- `host_plugin`：一个 `{path,config}`，Python 模块声明 `API_VERSION = 1`；扩展点
  为 `prepare(ctx)`、`on_ready(ctx)`、`finish(ctx)`。`prepare` 在 attach 前，`on_ready`
  在 init/resume 后，`finish` 在 Frida 回传后、unload 前。上下文含 `args/config`，
  后两者还含 `script/session/pid`；`on_ready` 含 `device`。返回值写到 run meta。
  目前 host 的 `finish` 只在 Frida 回传模式调用。
- 两类插件都是**可信任的任意代码，不是沙箱**。不要加载不可信文件。单文件最多
  1MiB、config/host 返回值最多 64KiB；agent 事件最多 200 条、每条 16KiB。
  Python 生命周期等待上限 30 秒；超时采集失败，但 Python 线程不能强杀。
  JS 生命周期要求同步；无法抢占恶意或卡死的 JS/native hook。
- Frida 回传的窗口为 1，二进制块最多 256KiB、文件最多 8GiB、单文件总时限
  180 秒、会话排空最多 900 秒；目录中未封口文件拒绝回传。成功 `.part` 原子提交，
  失败保留 pending 和设备源 spool，退出码 2；不会自动退回 adb shell。
  设备 spool 保留在 app 的 `files/.miku/`，成功也不删除；用户自行管理磁盘。
- 该能力绕过的是 **adb subprocess 回传路径**，不是已证实的通用反检测补丁。
  app 自杀、内核挂死、Frida 断线仍会失败；需要恢复时按 pending `meta.json` 的
  `devicePath` 手工取回对应 `trace.bin`，再执行 `./tracemiku finalize <run>`。
  Frida 模式暂不支持 child race-attach，且不启动 adb child lifecycle poll。

机器发现信息在 `./tracemiku capabilities` 的 `capture_extensions`；参数上限和默认值
以 `./tracemiku trace --help` 为准。无插件时仍支持原来的 CLI 目标参数。

| 文件 | 用途 | 备注 |
|---|---|---|
| `tools/native_sign_hooks_v4.js` | Frida 脚本：native 签名 SO hook 事件 | |
| `tools/spawn_hook.py` | spawn 注入通用运行器 | `python tools/spawn_hook.py <pkg> <hook.js>` |
| `tools/vm_replay_plan_eval.py` | 消费 `vm-ops --replay-plan` 输出的独立评估器 | 自带 `--verify-emitted-python` |
| `tools/hooks/*.json` | 目标相关 hook/type spec（如 `libart_jni.json`） | 目标配置的唯一允许位置之一 |
| `examples/llm_cookbook.py` | LLM 可选能力示例 | |
| `examples/<target>/` | 目标示例配置与算法验证 | 目标知识只能放这里或 `tools/hooks/` |

## 文档地图（哪份文档负责什么）

| 文档 | 责任范围 |
|---|---|
| `README.md` | 项目定位、环境、快速开始、文档入口 |
| `docs/FEATURES.md`（本文件） | 全量功能目录与命令选择，唯一命令用法汇总 |
| `AGENTS.md` | 工程规则与不可破坏边界（唯一规范） |
| `TODO.md` | 未完成路线图（唯一 backlog） |
| `docs/CLI_FIRST_DESIGN.md` | 采集与 CLI 的需求、当前架构及验证边界 |
| `docs/PER_CALL_TRACE_DESIGN.md` | trace.bin/meta.json 数据契约 |
| `docs/memory-completeness-design.md` | MemShadow 来源模型与消费者规则 |
| `docs/anti-detection-catalog.md` | 设备采集反检测层次与故障分类 |
| `tracer/README.md` | 设备端 agent 入口与数据通路 |
| `rust/README.md` | Rust 工作区 crate 与开发约束 |
| `BENCHMARKS.md` | 性能与质量基线 |
| `REFERENCES.md` | 外部参考材料 |
| 各命令 `--help` | 参数、默认值与约束的唯一事实源 |

维护规则：新增命令时，capabilities 会随 clap 定义自动更新；同时必须在本文件
对应分组加一行用途说明，并保证示例可执行。删除/改名命令时同步更新本文件。
