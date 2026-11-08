# traceMiku 缺失能力清单

## 1. NEON / SIMD（`V`/`Q`/`D`/`S`/`H`/`B`）访存字节载荷（Payload）提取与重建缺失

- **`Record` 仅保存通用标量寄存器（`rust/crates/tracemiku-core/src/trace/record.rs`）**
  - `trace.bin` 的单条 `Record` 固定为 272 字节（`pc: u64`、`regs: [u64; 31]` 即 `x0..x28, fp, lr`、`sp: u64`、`nzcv: u32`、`inst: u32`），不内嵌 `Q0..Q31` / `V0..V31` 向量/浮点寄存器状态。
  - `Record::reg_by_name` 仅解析 `x0..x30`、`w0..w30`、`fp`、`lr`、`sp`、`pc`、`nzcv`、`xzr`/`wzr`，对 `q*`/`v*`/`d*`/`s*`/`h*`/`b*` 均返回 `None`。
- **`MemShadow` 无法从 SIMD/FP 访存指令重建字节值（`rust/crates/tracemiku-core/src/memshadow.rs`）**
  - `value_of_write` 与 `value_of_read` 通过 `Record::reg_by_name` 读取源/目的寄存器值；当指令为 SIMD/FP 读写（如 `ldr/str qN`、`stp/ldp qN, qM`、`ld1/st1` 等）时，`reg_by_name` 返回 `None`，不生成 `MemShadow` 的 `writes`/`reads`（`MemRec { idx, addr, size, value: u64 }` 仅支持 64 位标量值）及 `bytes`（`ByteEvent`）记录。
  - 虽然 Agent 可选采集 `simd_trace.bin`（`520B`/条：`idx: u64` + `v[32]: 512B`），但 `tracemiku-core` 未接入或解析 `simd_trace.bin`，`MemShadow`（`TMMSV6`）也不会消费该 sidecar。
  - 在 `disasm::mem_op::extract`（`rust/crates/tracemiku-core/src/disasm/mem_op.rs`）中，`STORE_BASES` 仅包含标量/通用存储助记符（未包含 `st1`、`st2`、`st3`、`st4`），且向量结构访存指令的宽度与多寄存器展开尚未建模。
- **下游分析命令表现为未知字节**
  - `Index`（`rust/crates/tracemiku-core/src/index.rs`）虽可根据基址寄存器记录 `ldr/str/stp/ldp qN` 的访存地址与大小，但因 `MemShadow::bytes` 无对应事件：
    - `mem-accesses`（`rust/crates/tracemiku-core/src/analysis/mem_accesses.rs`）返回的事件中 `bytes` 全为 `null`（即 `Vec<Option<u8>>` 皆为 `None`）；
    - `mem-dump`、`find-mem-pattern`、`byte-lineage` 在对应地址上只能读到未知状态（`??` / `unknown`）或回退到调用前的旧值/初始快照。

## 2. 目标入口（`--fn-offset`）调用前（模块加载期 `.init_array` / `JNI_OnLoad`）与后台线程的采集空白

- **单次调用窗口外的初始化执行未纳入 Trace（`tracer/src/agent.ts`）**
  - `--fn-offset` / `--export` / `--method` 采用函数调用作用域采集：仅在目标入口 `onEnter` 至 `onLeave` 期间对进入该入口的 `primaryTid` 启用 `Stalker.follow`。
  - 模块加载阶段（`dlopen`、`.init_array` 构造函数、`JNI_OnLoad`）以及目标入口被调用前已完成的内存写入不在指令采集窗口内，无法关联到产生这些字节的具体指令。
- **跨线程 / 后台 Worker 线程覆盖受限（`tracer/src/hooks/pthread_follow.ts`）**
  - 默认仅跟踪进入目标函数的单一线程（`primaryTid`）。
  - 可选的 `followWorkers` 仅在 `STATE.fnEntered` 期间通过 `pthread_create` 的 `onLeave` 钩子以 `setTimeout(..., 1)` 异步枚举并跟踪新创建的线程（且写入独立的 `worker_trace_call<N>_tid<TID>.bin`，不被 `tracemiku-core` 的 `MemShadow` 合并）；在目标函数进入前已驻留的后台线程池/工作线程、或在调用窗口外异步修改内存的线程，其指令流与内存写入均无法被捕获。
