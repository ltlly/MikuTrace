# 命令目录

## 约定

- 统一入口 `./tracemiku`；`capabilities` 返回命令摘要（schema 2），`capabilities --command <name>` 返回参数；细节查 `<cmd> --help`。
- 分析面向 Android ARM64 trace，不包含 APK 专用命令；各命令是否适用取决于已采集的指令、内存、符号和可选 sidecar。
- `--fn` / `--in-fn` 使用 `functions` 返回项的 `name`（符号名称）。
- 地址/偏移默认十六进制：`10` = `0x10`，`d16` = 十进制 16。分析命令通常接收 `<call_dir>`。
- Rust 分析成功退出 0，输出 JSON；`list` 默认逐行 JSON，`--json` 返回数组；`completions` 输出 shell 源码。
- Rust 执行错误退出 1，stdout 为 `{"status":"error","error":{"code":"…","message":"…"}}`（可带 `error.details`）；参数错误退出 2，诊断在 stderr。部分旧查询退出 0 但结果含 `status=error`，须同时检查；host 采集沿用自己的诊断和退出码。
- 输出字段受契约测试约束，部分报告另有 [JSON schema](schema/)。内存来源与缺口见 [内存契约](memory-completeness-design.md)。

## 发现与元数据

| 命令 | 用途 |
|---|---|
| `capabilities` | 命令与参数发现 |
| `completions` | shell 补全 |
| `list` | 枚举 run/calls |
| `info` | run/call 元信息与完成度 |
| `meta` | 采集元数据与格式 |

## 地址与记录

| 命令 | 用途 |
|---|---|
| `resolve` | `(SO, offset)` ↔ PC，并查询执行情况 |
| `resolve-map-addr` | 按保存的 `/proc/<pid>/maps` 解析地址 |
| `resolve-elf-symbol` | ELF 偏移对应的最近符号 |
| `functions` | 符号与 trace 函数目录 |
| `so-stats` | 各 SO 的执行统计 |
| `records` | 批量指令与可选寄存器列 |
| `record` | 单条记录与寄存器注释 |
| `pc-hits` | PC 的执行下标与分页 |
| `search` | 反汇编/操作数正则搜索 |

## 控制流与调用

| 命令 | 用途 |
|---|---|
| `cfg` | 观测到的全局或指定函数 CFG |
| `block-hits` | 块命中次数与记录 |
| `block` | 包含给定 PC 的基本块详情 |
| `loops` | 循环检测 |
| `branch-coverage` | 函数执行路径与分支分布 |
| `indirect-targets` | `br/blr` 的运行时目标分布 |
| `backtrace` | 指定记录的调用回溯 |
| `call-tree` | 调用树 |
| `call-chain` | 命中函数之间的调用链 |

## 寄存器

| 命令 | 用途 |
|---|---|
| `reg-at` | 按 PC/模块偏移查询寄存器的多次执行分布 |
| `reg-value-at` | 指定记录的寄存器值 |
| `last-write-of-reg` | 最近一次寄存器定义 |
| `next-use-of-reg` | 下一次寄存器使用 |
| `reg-timeline` | 寄存器时间线 |

## 内存

| 命令 | 用途 |
|---|---|
| `mem-dump` | 指定时刻的 hex dump |
| `mem-export` | 按模块偏移导出运行时字节及完整度 |
| `mem-provenance` | 逐字节来源与 writer idx |
| `mem-diff` | 相邻记录间的内存差异 |
| `mem-flow` | 内存写入流 |
| `last-write-of-addr` | 单地址最近写入者 |
| `mem-accesses` | 单地址的访问记录 |
| `mem-range-accesses` | 范围内的访问记录 |
| `find-mem-pattern` | 在已访问内存中找字节模式 |
| `mem-writes-in-range` | 范围内的写入记录 |
| `byte-writer-map` | 缓冲区逐字节最新写入者 |
| `mem-byte-history` | 给定范围内每个字节的读写历史 |
| `mem-write-bursts` | 时间窗内地址连续的写入区间，不推断算法 |

## 数据依赖

| 命令 | 用途 |
|---|---|
| `taint-fwd` | 正向逐指令传播，包含 parent/深度 |
| `taint-bwd` | 反向逐指令来源，可穿过内存/函数边界 |
| `reg-chase` | 沿寄存器数据流追踪，可排除 sp/fp/lr |
| `dep-graph` | 限深依赖图 |
| `bfs-slice` | 后向依赖行集合，多种子并/交 |
| `forward-dep-graph` | def→use DAG，查询下游消费 |
| `byte-lineage` | 单字节沿内存写与源寄存器回追 |

## 字符串与 JNI

| 命令 | 用途 |
|---|---|
| `strings` | trace 中观测到的字符串 |
| `jni-strings` | 三类 JNI UTF-8 缓冲区的已观测字节预览 |
| `jni-calls` | JNI 调用列表 |
| `jni-events` | JNI 参数/返回值事件 |
| `jni-object-history` | 指定 jobject 历史 |

`jni-strings` 仅预览 NewStringUTF 输入、GetStringUTFChars 已观测返回和
ReleaseStringUTFChars 输入；`bytes_hex` 保存原始 modified UTF-8，`string` 是 UTF-8
有损显示，`read_stop` 区分 NUL、证据缺失与读取上限，不保证完整字符串。
JNI 调用识别依赖观测到的调用表访问；`jni-events` 另需采集对应 hook sidecar。

## 输出与密码特征

| 命令 | 用途 |
|---|---|
| `output-backtrace` | 已知输出字符串/字节的来源报告 |
| `base64-map` | 用户提供的 Base64 文本、解码字节与内存写入者之间的映射 |
| `crypto` | 常量指纹与 ARM CE 指令组合分析 |
| `hash-input-search` | 按指定算法组合反查目标摘要输入 |

## VM

| 命令 | 用途 |
|---|---|
| `vm-slice` | VM 记录切片 |
| `vm-ops` | 按显式 VM 角色将动态记录聚合为候选虚拟指令 |
| `vm-backstep` | VM store/load 链单步回溯 |
| `vm-backchain` | 迭代回链 |
| `vm-backtree` | 分支回溯树 |

`vm-*` 命令须指定 `--vm-ip-reg`、`--vm-state-reg`、`--vm-dispatch-reg` 与
`--vm-slot-bytes`；适用于使用这些寄存器角色和等宽状态槽的解释器。未知或不对齐的槽位
保留为未知，不自动识别私有字节码。`byte-writer-map`、`base64-map`、`output-backtrace`
仅开启 VM 链分析时需要这些参数。

## 验证与观察

| 命令 | 用途 |
|---|---|
| `trace-replay` | 逐条锚定捕获前态，检查 ARM64 寄存器/PC 转移 |
| `watch` | `reg-change`、`reg-equals` 或 `mem-touch` 扫描 |
| `fn-summary` | 函数命中频次与热门块 |
| `fork-events` | 需采集时启用的 fork 事件 |

`trace-replay` 的窗口和内存回看均最多 10000 条。`matched/diverged/stopped` 分别表示
窗口匹配、寄存器/PC 发散、证据不足/语义不支持/达到上限；`checked` 只计匹配转移，
`stop.next_capture` 给出补采建议。内存只使用连续、受支持边界内此前的 store/外部写
及有效初始快照；未知边界之前的来源失效。尚不接入 SIMD sidecar 或验证设备实际写入。
`metadata_present=false` 只做结构连续性检查；未定位的 dropped 使转移保守不确定。

## 采集与恢复

| 命令 | 用途 |
|---|---|
| `trace` | Frida 指令采集 |
| `probe` | Interceptor 函数计数，不产生 trace |
| `doctor` | adb/root/Frida 进程/配置检查，不执行注入 |
| `finalize` | 按 `trace.bin` 修复 pending/call 元数据 |

默认 attach；`--spawn` 在挂起进程中 attach/init 后 resume，`--launch` 则先启动再 attach。
入口由 `--so` 与 `--fn-offset/--export/--method` 三选一指定；`--cmd` 过滤须同时给
`--cmd-arg`。反检测插件默认关闭，patch 需目标 spec。

```bash
./tracemiku trace --pkg com.example.app --so libfoo.so --export sign --out traces/run1
./tracemiku trace --target-profile examples/custom_target/target.json --out traces/demo
./tracemiku finalize traces/run1
```

Frida 回传默认窗口 1、块上限 256KiB、文件上限 8GiB；单文件限时 180 秒，会话排空
限时 900 秒。未封口文件拒绝回传，完成后 `.part` 原子提交；失败保留 pending 和设备
spool、退出 2，不自动退回 adb。设备 `files/.miku/` 中的 spool 成功后也保留。
Frida 模式不支持 child race-attach。中断后可按 pending meta 的 `devicePath` 取回文件再 finalize。

### 目标配置与插件

[target.json](../examples/custom_target/target.json) 使用 schema 1：`target` 指定目标，
`capture` 提供默认参数，显式 CLI 参数覆盖 profile；脚本与 JNI spec 路径相对 JSON 解析。
未知字段、错误类型、缺失文件和重复插件 ID 报错。

| 插件 | 接口 |
|---|---|
| `agent_plugins` | 最多 8 个 `{id,path,config}`；普通 JS `module.exports` 声明 `apiVersion: 1`，同步 `install/onModule/beforeTrace/dispose`，可选 `invoke` |
| `host_plugin` | 一个 `{path,config}`；Python `API_VERSION = 1`，`prepare/on_ready/finish`；返回值写 run meta |

agent 上下文含 `config/emit`；`onModule` 含 `module`，`beforeTrace` 含 `args/tid/address`。
host 可调用 `script.exports_sync.plugin_call(id,payload)`；Java bridge 不自动注入。
host 的 `prepare` 在 attach 前，`on_ready` 在 init/resume 后，`finish` 仅在 Frida 回传后、
unload 前；上下文含 `args/config`，后两者还有 `script/session/pid`，`on_ready` 另含 `device`。

插件执行任意可信代码，无沙箱。单文件限 1MiB，config/host 返回值限 64KiB；agent
事件限 200 条、`detail` JSON 文本限 16384 个 UTF-16 码元。Python 生命周期等待 30 秒后失败，不能强杀线程；JS 卡死无法抢占。

## 分析示例

```bash
./tracemiku resolve <call_dir> --so libfoo.so --off 0x1234
./tracemiku records <call_dir> --start 0 --count 50 --regs x0,x1,sp
./tracemiku reg-at <call_dir> --reg x0 --so libfoo.so --off 0x1234
./tracemiku mem-export <call_dir> --so libfoo.so --off 0x2000 --len 0x100 --out /tmp/dec.bin
./tracemiku bfs-slice <call_dir> --idx 1000
./tracemiku output-backtrace <call_dir> --bytes-hex aabbccdd
./tracemiku vm-ops <call_dir> --start 0 --vm-ip-reg x9 --vm-state-reg x10 --vm-dispatch-reg x11 --vm-slot-bytes 8
./tracemiku trace-replay <call_dir> --start 100 --count 200
```

目标脚本在 `tools/hooks/` 和 `examples/<target>/`；
[llm_cookbook.py](../examples/llm_cookbook.py) 演示 CLI 编排，
[vm_replay_plan_eval.py](../tools/vm_replay_plan_eval.py) 消费 `vm-ops --replay-plan`。
