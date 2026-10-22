# 命令目录

## 约定

- 统一入口 `./tracemiku`；`capabilities` 返回命令摘要（schema 2），`capabilities --command <name>` 返回参数；细节查 `<cmd> --help`。
- 分析面向 Android ARM64 trace，不包含 APK 专用命令；各命令是否适用取决于已采集的指令、内存、符号和可选 sidecar。
- `--fn` / `--in-fn` 使用 `functions` 返回项的 `name`（符号名称）。
- 地址/偏移默认十六进制：`10` = `0x10`，`d16` = 十进制 16。分析命令通常接收 `<call_dir>`。
- Rust 分析成功退出 0，输出 JSON；`list` 默认逐行 JSON，`--json` 返回数组；`completions` 输出 shell 源码。
- Rust 执行错误退出 1，stdout 为 `{"status":"error","error":{"code":"…","message":"…"}}`（可带 `error.details`）；参数错误退出 2，诊断在 stderr。部分旧查询退出 0 但结果含 `status=error`，须同时检查。`trace/recover` 输出单个 JSON，诊断在 stderr；`ok` 退出 0，`incomplete/pending/error` 退出 2。
- 输出字段受契约测试约束，部分报告另有 [JSON schema](schema/)。内存来源与缺口见 [内存契约](memory-completeness-design.md)。

## 发现与元数据

| 命令 | 用途 |
|---|---|
| `capabilities` | 命令与参数发现；`stability` 区分稳定入口与试验入口 |
| `completions` | shell 补全 |
| `list` | 枚举 run/calls |
| `info` | run/call 元信息、采集元数据、格式与完成度 |

## 地址与记录

| 命令 | 用途 |
|---|---|
| `resolve` | `(SO, offset)` ↔ PC、执行情况；也可直接查询保存的 maps |
| `functions` | 函数目录；选定函数时附执行频次与热点摘要 |
| `so-stats` | 各 SO 的执行统计 |
| `records` | 按区间（`--start` + `--count`/`--end`）或下标批量读取指令前状态、所选寄存器及执行后效果（`writes_reg`、`mem_access`）；可附完整详情 |
| `pc-hits` | PC 的执行下标与分页 |
| `search` | 反汇编/操作数正则搜索 |

`records` 默认只读取所选记录，不构建索引、符号、CFG 或 MemShadow；`--detail`
才加载注释所需的分析。当下一条记录存在时，每条记录内联输出执行后寄存器变更
`writes_reg`（含 `reg`/`before`/`after`）和内存访问 `mem_access`（含 `r`/`w`、`ea`、`size`、`val`）。
单条和多条查询共享 `records` 数组、返回数与截断字段。
运行 `python3 scripts/benchmark_records.py` 可复测合成 trace 上的单条读取成本，
对照任务是 Python 直接定位读取原始值；此基准不代表完整分析任务。

## 控制流与调用

| 命令 | 用途 |
|---|---|
| `cfg` | 观测到的全局/函数 CFG；可定位块、分页读取执行位置及查看分支统计 |
| `loops` | 观测 CFG 中的循环强连通分量 |
| `indirect-targets` | `br/blr` 的运行时目标分布 |
| `backtrace` | 根据实际 call/ret 重建调用栈；可另附 LR 推测链 |
| `call-tree` | 调用树及执行次数 |

## 寄存器

| 命令 | 用途 |
|---|---|
| `reg-at` | 按 PC/模块偏移查询寄存器的多次执行分布 |
| `last-write-of-reg` | 最近一次寄存器定义 |
| `next-use-of-reg` | 下一次寄存器使用 |
| `reg-timeline` | 寄存器变化时间线，或筛选值等于给定值的记录 |

## 内存

| 命令 | 用途 |
|---|---|
| `mem-dump` | 指定时刻的字节值、完整度；可比较另一时刻或导出文件 |
| `mem-provenance` | 逐字节值来源、最后已观测写入者及连续 writer 区间 |
| `mem-accesses` | 地址范围内的读写历史；统一时间窗口、读写筛选和分页 |
| `last-write-of-addr` | 单地址或多字节（`--size`）最近已观测写入者及 `unlogged_write_gap` 检测 |
| `find-mem-pattern` | 在已观测内存中找字节模式（支持 `--bytes-hex` / `--ascii <STR>`、`--limit` 及瞬态窗口匹配） |

内存快照时刻包含该记录的写入。访问窗口为 `[start,end)`；`mem-accesses` 的
`next_cursor` 是匹配事件序号，续页须保持其他筛选条件一致。外部写入保留独立来源，
无法确定的字节为 `null`。当后续读取（`r`）观测到的字节与最近一次已记录写入（`w`/`x`）不一致时，
`last-write-of-addr` 报告 `unlogged_write_gap`（`prev_write_idx` 到 `first_observing_read_idx` 窗口）。
`find-mem-pattern` 在未固定时刻（`since < 0`）时搜索全时段有效窗口，返回 `first_idx` 与 `overwritten_at_idx`。
`mem-dump` 比较中任一时刻缺值时标为 `unknown`，导出遇到
未知字节或截断时失败，不写入填充值。逐字节区间最多 4096 字节。

## 数据依赖

| 命令 | 用途 |
|---|---|
| `taint-fwd` | 正向逐指令传播，包含 parent/深度 |
| `taint-bwd` | 反向逐指令来源，可穿过内存/函数边界 |
| `bfs-slice` | 多种子依赖集合或图；统一前向/后向、深度与并/交筛选 |
| `byte-lineage` | 单字节沿内存写与源寄存器回追；支持可选 VM 寄存器槽折叠与 `unlogged_write_gap` 边界 |

依赖图箭头始终表示定义→使用，遍历方向不改变边的含义。`byte-lineage` 可选指定
`--vm-ip-reg`、`--vm-state-reg`、`--vm-dispatch-reg`、`--vm-regfile`，标记 `is_vm_reg_slot` / `vm_slot_offset`
并以零逻辑深度开销折叠 VM 寄存器槽传递；遇到未记录外部写入时在 `memory_boundaries` 中报告 `unlogged_write_gap`。
无效种子、深度或节点预算导致的不完整结果显式标记；图最多 2000 个节点和 10000 条边。

## 字符串、JNI 与采集事件

| 命令 | 用途 |
|---|---|
| `strings` | 已观测内存中的可打印字符串 |
| `jni-calls` | JNI 调用识别；可按函数、jobject、时间筛选并预览字符串缓冲区 |
| `events` | 有界读取 JNI hook 或 fork sidecar，不需要 trace.bin |

JNI 调用识别依赖观测到的调用表访问。字符串预览仅包含 NewStringUTF 输入、
GetStringUTFChars 已观测返回和 ReleaseStringUTFChars 输入；`bytes_hex` 保存原始
modified UTF-8，`string` 是 UTF-8 有损显示，`read_stop` 区分 NUL、证据缺失与读取
上限，不保证完整字符串。

`events` 读取 `jni_hooks.jsonl`、`fork_events.jsonl` 或旧 `meta.json` 的 `fork_events`。缺文件返回
`available=false`，坏行/超长行计数单列；每页最多 5000 条，扫描与紧凑 JSON 响应
预算各为 8 MiB。JNI 单行上限 64 KiB，无法在扫描预算内跨过的超长行报错；超预算
的 meta.json 报错。续页原样传回 `next_cursor`；筛选条件与来源须保持一致。

## 输出与密码特征

| 命令 | 用途 |
|---|---|
| `output-backtrace` | 显式提供输出字符串/字节，定位内存与写入来源，可展开污点 |
| `crypto` | 通用常量指纹、ARM CE 指令特征及 `MemShadow` 状态上下文（`detected_contexts`）；输出候选证据 |

`crypto` 对 64 位寄存器高低 32 位按值跳变去重，并在 `MemShadow` 中扫描有状态的
`MD5`、`SHA-1`、`SHA-256`、`SM3`、`ChaCha20` 上下文初始化与最终摘要更新（输出 `detected_contexts`）。
格式转换、摘要验证、静态 ELF 符号查询及一次性报告组合使用现有工具或脚本；
CLI 维护运行时证据与分析语义。

## 试验入口

| 命令 | 用途 |
|---|---|
| `experimental vm-slice` | 按显式 VM 配置标注记录 |
| `experimental vm-ops` | 聚合候选虚拟指令及状态槽效果 |
| `experimental vm-backstep` | VM store/load 链单步回溯 |
| `experimental vm-backchain` | 迭代回链 |
| `experimental vm-backtree` | 分支回溯树 |

这些入口尚待不同解释器与固定任务验证，接口可能变化。须显式指定 IP、状态、分派
寄存器和状态槽宽度；适用于使用这些角色和等宽状态槽的解释器。未知或不对齐的槽位
保留为未知，不自动识别私有字节码。机器清单在 `experimental` 下标记稳定性，
`./tracemiku capabilities --command "experimental vm-ops"` 可单独查看试验子命令参数。

## 状态转移验证

| 命令 | 用途 |
|---|---|
| `trace-replay` | 逐条锚定捕获前态，检查 ARM64 寄存器/PC 转移 |

窗口和内存回看均最多 10000 条。`matched/diverged/stopped` 分别表示窗口匹配、
寄存器/PC 发散、证据不足/语义不支持/达到上限；`checked` 只计匹配转移，
`stop.next_capture` 给出补采建议。内存只使用连续、受支持边界内此前的 store/外部写
及有效初始快照；未知边界之前的来源失效。尚不接入 SIMD sidecar 或验证设备实际写入。
`metadata_present=false` 只做结构连续性检查；未定位的 dropped 使转移保守不确定。

## 采集与恢复

| 命令 | 用途 |
|---|---|
| `trace` | 默认采集一次完整调用，设备封口后压缩回传 |
| `recover` | 按 `recovery.json` 恢复压缩回传，复用已校验分块，不重跑目标 |
| `probe` | Interceptor 函数计数，不产生 trace |
| `doctor` | adb/root/Frida 进程/配置检查，不执行注入 |
| `finalize` | 离线回填派生元数据；未完成回传的目录仍保持 pending |

默认 attach；`--spawn` 在挂起进程中 attach/init 后 resume，`--launch` 则先启动再 attach。
入口由 `--so` 与 `--fn-offset/--export/--method` 三选一指定；`--cmd` 过滤须同时给
`--cmd-arg`。反检测插件默认关闭，patch 需目标 spec。

```bash
./tracemiku trace --pkg com.example.app --so libfoo.so --export sign --out traces/run1
./tracemiku trace --target-profile examples/custom_target/target.json --out traces/demo
./tracemiku recover traces/run1
./tracemiku finalize traces/run1
```

`trace` 等待目标函数自然返回，不设记录条数、调用时长或文件总量上限。固定大小
native 缓冲满后同步写盘，慢盘或磁盘错误阻塞生产线程；不会为追赶生产速度而丢弃记录。
封口后使用 gzip + ADB 分块回传，逐块和逐文件校验 SHA-256。文件与 sidecar 全部验证
后才提交目录。传输仅有无进展超时，失败后运行 `recover`。
结果含每次调用的 `is_complete`，直接采用 core `info` 的判定；文件已回传但采集有
缺口时返回 `incomplete`，数据仍可用于离线分析。

Ctrl+C 结束 host 等待并停止接受新调用，已开始的调用继续在设备采集。host 进程或
控制连接突然断开也不卸载采集器。`recover` 遇到未封口 session 返回 `pending`，不猜测
函数已经结束。设备原件、恢复描述和已校验压缩块保留，方便复核。目标崩溃可能遗留
未落盘的尾批，不能报告完整；采集范围及其他缺口见[格式契约](PER_CALL_TRACE_DESIGN.md)。

### 目标配置与插件

[target.json](../examples/custom_target/target.json) 使用 schema 1：`target` 指定目标，
`capture` 提供默认参数，显式 CLI 参数覆盖 profile；脚本与 JNI spec 路径相对 JSON 解析。
未知字段、错误类型、缺失文件和重复插件 ID 报错。

| 插件 | 接口 |
|---|---|
| `agent_plugins` | 最多 8 个 `{id,path,config}`；普通 JS `module.exports` 声明 `apiVersion: 1`，同步 `install/onModule/beforeTrace/dispose`，可选 `invoke` |
| `host_plugin` | 一个 `{path,config}`；Python `API_VERSION = 1`，`prepare/on_ready/finish`；返回值写 run meta |

agent 上下文含 `config/emit`；`onModule` 含 `module`，`beforeTrace` 含 `args/tid/address`。
采集前与采集中产生的 agent 生命周期事件保存在调用目录的 `target_plugin_events.jsonl`。
host 可调用 `script.exports_sync.plugin_call(id,payload)`；Java bridge 不自动注入。
host 的 `prepare` 在 attach 前，`on_ready` 在 init/resume 后，`finish` 在退出采集等待后、
压缩回传前执行；连接已断开时跳过。上下文含 `args/config`，后两者还有
`script/session/pid`，`on_ready` 另含 `device`。`script` 为可卸载控制桥，支持
`plugin_call/stats/stop_capture`；不承载 trace 或 sidecar 的唯一副本。

插件执行任意可信代码，无沙箱。单文件限 1MiB，config/host 返回值限 64KiB；agent
事件限 200 条、`detail` JSON 文本限 16384 个 UTF-16 码元。Python 生命周期等待 30 秒后失败，不能强杀线程；JS 卡死无法抢占。

### 采集器离线验证

`make test-offline-arm64` 使用 QEMU、ARM64 musl GumJS devkit 和生产 agent/native writer，
从原始 ELF 核对每条 PC/opcode、GPR 路径、SIMD 哨兵与索引，再经统一 CLI 判断完整性。
需预先准备与设备 Frida 同版的 devkit、musl 交叉工具链和 QEMU；不会自动安装依赖。
按[工具链示例](../tracer/tests/arm64_toolchain.example.json)配置编译器、链接参数及 QEMU
加载器路径，所有字段均为 argv 数组，不经 shell 展开。

```bash
make test-offline-arm64 OFFLINE_ARGS='--devkit /path/to/gumjs-devkit --toolchain /path/to/toolchain.json'
make test-disk-full
```

后者要求 Linux 允许用户/挂载命名空间，在私有 1MiB tmpfs 中触发真实 `ENOSPC`，
验证生产线程阻塞、释放空间后续写及逐条 GPR/SIMD 一致性。两者均保留或输出失败
证据；ARM64 测试结果保存在输出目录，磁盘测试临时卷自动卸载。离线测试不替代 Android
真机、物理 USB、目标崩溃及实际存储介质验证。

## 分析示例

```bash
./tracemiku resolve <call_dir> --so libfoo.so --off 0x1234
./tracemiku records <call_dir> --start 0 --count 50 --regs x0,x1,sp
./tracemiku reg-at <call_dir> --reg x0 --so libfoo.so --off 0x1234
./tracemiku mem-dump <call_dir> --so libfoo.so --off 0x2000 --count 256 --out /tmp/dec.bin
./tracemiku records <call_dir> --indices 100,105 --regs x0,sp
./tracemiku cfg <call_dir> --pc 0x1234 --hits --coverage
./tracemiku mem-accesses <call_dir> --addr 0x7000 --size 16 --kind write --start 100 --end 200
./tracemiku mem-dump <call_dir> --addr 0x7000 --count 16 --at 199 --compare-at 99
./tracemiku bfs-slice <call_dir> --idx 1000 --direction forward --view graph
./tracemiku jni-calls <call_dir> --strings --limit 20
./tracemiku events <call_dir> --source jni --id NewStringUTF
./tracemiku output-backtrace <call_dir> --bytes-hex aabbccdd
./tracemiku experimental vm-ops <call_dir> --start 0 --vm-ip-reg x9 --vm-state-reg x10 --vm-dispatch-reg x11 --vm-slot-bytes 8
./tracemiku trace-replay <call_dir> --start 100 --count 200
```

目标脚本在 `tools/hooks/` 和 `examples/<target>/`；
[llm_cookbook.py](../examples/llm_cookbook.py) 演示 CLI 编排，
[vm_replay_plan_eval.py](../tools/vm_replay_plan_eval.py) 消费 `experimental vm-ops --replay-plan`。
