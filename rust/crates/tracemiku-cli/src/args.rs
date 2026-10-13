use super::*;

#[derive(Parser, Debug)]
#[command(
    name = "tracemiku",
    about = "Android ARM64 trace 离线分析与 JSON 证据查询",
    version
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
pub(super) enum Cmd {
    /// Describe every CLI command and argument as machine-readable JSON.
    Capabilities,
    /// Verify supported ARM64 instructions against captured pre/post states and report the first evidence frontier.
    TraceReplay {
        #[command(flatten)]
        args: super::replay_command::ReplayArgs,
    },
    /// Generate shell completion scripts for bash, zsh, fish, or powershell.
    Completions {
        /// Shell type: bash, zsh, fish, powershell.
        shell: clap_complete::Shell,
    },
    /// Print trace metadata as JSON.
    Stats {
        /// Per-call trace directory.
        trace_dir: PathBuf,
        /// Show ALL modules (overrides --top-modules).
        #[arg(long)]
        all_modules: bool,
        /// Limit modules list to top-N by size. Default 10.
        #[arg(long, default_value_t = 10)]
        top_modules: usize,
    },
    /// 单次 trace 的采集元数据与格式信息。
    Meta { trace_dir: PathBuf },
    /// List runs under a trace root or calls under one run.
    List {
        /// Trace root or run dir. Defaults to ./traces.
        path: Option<PathBuf>,
        /// Base trace dir when path is omitted.
        #[arg(long, default_value = "traces")]
        dir: PathBuf,
        /// Emit one JSON array instead of one JSON row per line.
        #[arg(long)]
        json: bool,
    },
    /// Inspect one run or per-call trace directory.
    Info {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Resolve an address against a saved /proc/<pid>/maps file.
    ResolveMapAddr { maps_file: PathBuf, addr: String },
    /// Resolve an address against trace meta module ranges.
    ResolveTraceAddr { trace_dir: PathBuf, addr: String },
    /// Resolve an ELF/shared-library virtual offset to the nearest symbol.
    ResolveElfSymbol { elf_file: PathBuf, offset: String },
    /// 按区间导出指令记录，可选寄存器列。
    Records {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 0)]
        start: usize,
        #[arg(long, default_value_t = 100)]
        count: usize,
        #[arg(long)]
        regs: Option<String>,
        #[arg(long)]
        indices: Option<String>,
    },
    /// 单条记录与寄存器注释详情。
    Record { trace_dir: PathBuf, idx: usize },
    /// 某 PC 被执行的 trace 下标集合。
    IdxsForPc {
        trace_dir: PathBuf,
        pc: String,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// 反汇编/操作数正则搜索。
    Search {
        trace_dir: PathBuf,
        pattern: String,
        #[arg(long, default_value_t = 2000)]
        max_results: usize,
        #[arg(long)]
        cursor: Option<usize>,
    },
    /// 各 SO 的 trace 统计。
    SoStats {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 50)]
        top: usize,
        #[arg(long)]
        all: bool,
    },
    /// (SO,offset) ↔ 绝对 PC 双向解析，并返回执行事实。
    ///
    /// Forward:  --addr 0x... (absolute PC) -> module, offset, exec facts.
    /// Reverse:  --so libfoo --off 0x...    (module+offset) -> absolute PC.
    /// `--so` matches full path / basename / basename-prefix / substring, so
    /// the stable name you read in IDA/BN/Ghidra resolves to the loaded .so.
    /// Addresses/offsets are HEX by default (disassembler convention): `10`
    /// means 0x10; prefix with `d` to force decimal (`d16` = 16).
    Resolve {
        trace_dir: PathBuf,
        /// Absolute PC, hex by default (`d`-prefix for decimal). PC -> (SO, offset).
        #[arg(long)]
        addr: Option<String>,
        /// Module name / basename / prefix / substring. Use with --off.
        #[arg(long)]
        so: Option<String>,
        /// Module-relative static offset, hex by default. Use with --so.
        #[arg(long)]
        off: Option<String>,
    },
    /// `br/blr` 的运行时真实跳转目标分布。
    ///
    /// Resolves the real target distribution + hit counts for an indirect
    /// branch/call, keyed on (SO, offset) or absolute PC. With no source given,
    /// lists every indirect-branch source in the trace, busiest first. The wall
    /// static disassemblers (IDA/BN/Ghidra) hit on `br x8` — answered from the
    /// trace. Addresses/offsets are HEX by default; `d`-prefix forces decimal.
    IndirectTargets {
        trace_dir: PathBuf,
        /// Absolute PC of the br/blr source. PC form.
        #[arg(long)]
        addr: Option<String>,
        /// Module name / basename / prefix / substring. Use with --off.
        #[arg(long)]
        so: Option<String>,
        /// Module-relative offset of the br/blr source. Use with --so.
        #[arg(long)]
        off: Option<String>,
        /// Drop targets observed fewer than this many times (default 1).
        #[arg(long)]
        min_count: Option<u64>,
    },
    /// (SO,offset)/PC 处的寄存器值 + 跨执行去重分布。
    ///
    /// "At libfoo+0x1234, what was x0?" Reads the register at EVERY execution
    /// of that PC and returns both the per-hit values and a distinct-value
    /// distribution with counts — one static offset usually holds many values
    /// across the run (loops/repeated calls), which static tools can't show.
    /// Offsets/addr are HEX by default; `d`-prefix forces decimal.
    RegAt {
        trace_dir: PathBuf,
        /// Register name (x0-x30, sp, fp, lr, pc, nzcv, w0-w30).
        #[arg(long)]
        reg: String,
        /// Absolute PC. Or use --so + --off.
        #[arg(long)]
        addr: Option<String>,
        /// Module name / basename / prefix / substring. Use with --off.
        #[arg(long)]
        so: Option<String>,
        /// Module-relative offset. Use with --so.
        #[arg(long)]
        off: Option<String>,
        /// Max per-hit rows returned (distribution covers all hits regardless).
        #[arg(long)]
        max: Option<usize>,
    },
    /// 单次执行的寄存器值。
    RegValueAt {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long)]
        reg: String,
    },
    /// 寄存器最近一次被写的位置。
    LastWriteOfReg {
        trace_dir: PathBuf,
        #[arg(long)]
        reg: String,
        #[arg(long)]
        before: Option<usize>,
        #[arg(long)]
        cursor: Option<usize>,
    },
    /// 寄存器下一次被读的位置。
    NextUseOfReg {
        trace_dir: PathBuf,
        #[arg(long)]
        reg: String,
        #[arg(long)]
        after: Option<usize>,
    },
    /// 观察点扫描：`reg-change`/`reg-equals`/`mem-touch`。
    Watch {
        trace_dir: PathBuf,
        #[arg(long, default_value = "reg-change")]
        kind: String,
        #[arg(long)]
        reg: Option<String>,
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        value: Option<String>,
        #[arg(long, default_value_t = 1)]
        size: u64,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// 列出函数（symbol 与 trace 来源）。
    Functions { trace_dir: PathBuf },
    /// fork 事件（反调试常用）。
    ForkEvents {
        trace_dir: PathBuf,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        is_fork_like: Option<bool>,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// 函数控制流图数据。
    Cfg {
        trace_dir: PathBuf,
        #[arg(long = "fn")]
        fn_name: Option<String>,
    },
    /// 块命中次数与所属记录。
    IdxsForBlock {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
        #[arg(long, default_value_t = 200)]
        max_count: usize,
        #[arg(long, default_value_t = -1)]
        near: isize,
    },
    /// PC → 基本块。
    BlockForPc {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
    },
    /// 基本块详情。
    Block {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
    },
    /// 循环检测结果。
    Loops { trace_dir: PathBuf },
    /// 函数执行路径与观测分支分布。
    /// for the function at a (SO,offset)/PC, or by --fn name. For each branch:
    /// which way it actually went and how often (static "both possible" ->
    /// the real path). one_sided branches = static ambiguity collapsed.
    Coverage {
        trace_dir: PathBuf,
        /// Absolute PC inside the function. Or --so+--off, or --fn.
        #[arg(long)]
        addr: Option<String>,
        /// Module name/basename/prefix/substring (with --off).
        #[arg(long)]
        so: Option<String>,
        /// Module-relative offset inside the function (with --so). HEX default.
        #[arg(long)]
        off: Option<String>,
        /// Scope directly by function name (e.g. sub_7f10).
        #[arg(long = "fn")]
        fn_name: Option<String>,
    },
    /// 指定位置的调用回溯。
    Backtrace {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long, default_value_t = 256)]
        limit: usize,
    },
    /// 调用树。
    CallTree {
        trace_dir: PathBuf,
        #[arg(long)]
        max_depth: Option<usize>,
    },
    /// 命中函数之间的调用链。
    CallChain {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long, default_value_t = 5)]
        depth: usize,
    },
    /// 从 trace 观察到的字符串。
    Strings {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 4)]
        min_len: usize,
        #[arg(long, default_value = "")]
        q: String,
        #[arg(long, default_value_t = -1)]
        cursor: i64,
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
    /// 某字符串每个字节的来源。
    StringProvenance {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 32)]
        length: usize,
    },
    /// 内存范围 hex dump。
    MemDump {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 256)]
        count: usize,
        #[arg(long)]
        cursor: Option<u64>,
        /// Emit compact hex/ascii fields instead of only per-byte entries.
        #[arg(long)]
        summary: bool,
        /// Interpret the range as a NUL-terminated C string.
        #[arg(long)]
        cstr: bool,
    },
    /// Tenet-style export: per-byte provenance (writer idx / initial /
    /// unknown) for a memory range, without fabricating missing memory.
    MemTenet {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 64)]
        length: usize,
    },
    /// 按 (SO,offset,len) 导出运行时解密字节。
    ///
    /// Reconstructs the real bytes the program saw (MemShadow w/x/i layers) for
    /// a packed/VMP'd/self-decrypting region a static disassembler can't read.
    /// Keyed on (SO,offset) or absolute PC. With --out, writes the raw decrypted
    /// bytes to a file for IDA loadfile / BN / Ghidra import at the same offset;
    /// otherwise prints the JSON (hex blob + provenance runs + completeness).
    /// Offsets/len are HEX by default; `d`-prefix forces decimal.
    MemExport {
        trace_dir: PathBuf,
        /// Absolute PC of the range start. Or use --so + --off.
        #[arg(long)]
        addr: Option<String>,
        /// Module name / basename / prefix / substring. Use with --off.
        #[arg(long)]
        so: Option<String>,
        /// Module-relative offset of the range start. Use with --so.
        #[arg(long)]
        off: Option<String>,
        /// Number of bytes to export (hex by default).
        #[arg(long)]
        len: String,
        /// Time point (record idx); default = end of trace.
        #[arg(long)]
        cursor: Option<u64>,
        /// Write raw decrypted bytes to this file (for disassembler loadfile).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// 某地址最后一次写入者。
    LastWriteOfAddr {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = -1)]
        before_idx: isize,
        /// Include boundary-diff external writes from MemShadow.
        #[arg(long)]
        with_external: bool,
    },
    /// 触碰某地址的全部记录。
    IdxsTouchingAddr {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        #[arg(long, default_value_t = 30)]
        limit: usize,
        /// Include byte values from MemShadow, blocking to load/build it if needed.
        #[arg(long)]
        with_bytes: bool,
    },
    /// 触碰某范围的全部记录。
    IdxsTouchingRange {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 1)]
        size: u64,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// 在 trace 访问过的内存中找字节模式。
    FindMemPattern {
        trace_dir: PathBuf,
        #[arg(long = "bytes-hex")]
        bytes_hex: String,
        #[arg(long, default_value_t = -1)]
        since: isize,
        #[arg(long, default_value_t = 100)]
        max: usize,
        #[arg(long)]
        idx_lo: Option<usize>,
        #[arg(long)]
        idx_hi: Option<usize>,
    },
    /// 从 (start,reg) 正向逐指令传播。
    /// (start, reg) following def/use through registers and (optionally)
    /// memory. Use when you need per-instruction propagation steps with
    /// parent_idxs / taint_depth; for "all rows that depend on this" use
    /// `bfs-slice` (backward) or `forward-dep-tree` (downstream) instead.
    TaintFwd {
        trace_dir: PathBuf,
        /// Trace index where propagation starts.
        #[arg(long)]
        start: usize,
        /// Seed register name (e.g. x9, w9, sp).
        #[arg(long)]
        reg: String,
        /// 结果条数上限，受 core 硬上限约束。
        #[arg(long)]
        max_count: Option<usize>,
        /// Follow stores/loads through MemShadow (memory taint propagation).
        #[arg(long)]
        through_mem: bool,
        /// Drop control-flow / addressing-reg edges; only follow value flow.
        #[arg(long)]
        data_only: bool,
        /// Allow taint to cross function-call boundaries.
        #[arg(long)]
        cross_fn_call: bool,
        /// 连续 N 次无新增命中后停止；0 关闭，省略使用 core 默认值。
        /// 返回 stop_reason 和 scan_limit_used。
        #[arg(long)]
        scan_limit: Option<usize>,
    },
    /// 从 (start,reg) 反向追来源。
    /// through register defs and (optionally) memory writes. Returns each
    /// upstream row with parent_idxs, taint_depth, and edge_kind. For "what
    /// rows did this seed depend on" without per-instruction modeling, use
    /// `bfs-slice` instead (much faster).
    TaintBwd {
        trace_dir: PathBuf,
        /// Trace index where the lineage chase starts (the sink). Optional if
        /// you instead give --so/--off (a tool-neutral (SO,offset) coordinate).
        #[arg(long)]
        start: Option<usize>,
        /// Module name/basename/prefix/substring for the seed (with --off).
        /// Resolves (SO,offset) -> PC -> the chosen execution's trace index.
        #[arg(long)]
        so: Option<String>,
        /// Module-relative offset of the seed (with --so). HEX by default.
        #[arg(long)]
        off: Option<String>,
        /// Which execution of that PC to seed from (0 = first). Default 0.
        #[arg(long, default_value_t = 0)]
        occurrence: usize,
        /// Seed register name (e.g. x9, w9, sp).
        #[arg(long)]
        reg: String,
        /// 结果条数上限，受 core 硬上限约束。
        #[arg(long)]
        max_count: Option<usize>,
        /// Follow stores/loads through MemShadow (memory taint propagation).
        #[arg(long)]
        through_mem: bool,
        /// Drop control-flow / addressing-reg edges; only follow value flow.
        #[arg(long)]
        data_only: bool,
        /// Allow taint to cross function-call boundaries.
        #[arg(long)]
        cross_fn_call: bool,
        /// 连续 N 次无新增命中后停止；0 关闭，省略使用 core 默认值。
        /// 返回 stop_reason 和 scan_limit_used。
        #[arg(long)]
        scan_limit: Option<usize>,
    },
    /// 沿寄存器数据流追踪，跳过 sp/fp/lr 噪声。
    DataChase {
        trace_dir: PathBuf,
        #[arg(long)]
        start: usize,
        #[arg(long)]
        reg: String,
        #[arg(long, default_value_t = 50)]
        max_steps: usize,
        #[arg(long, default_value = "sp,fp,lr")]
        exclude_regs: String,
    },
    /// 依赖图。
    DepGraph {
        trace_dir: PathBuf,
        /// Concrete trace record index to use as seed.
        #[arg(long)]
        idx: Option<usize>,
        /// Resolve seed to the last definition of this register before --before.
        #[arg(long)]
        reg: Option<String>,
        /// Resolve seed to the last write touching this address before --before.
        #[arg(long)]
        addr: Option<String>,
        #[arg(long)]
        before: Option<usize>,
        #[arg(long, default_value_t = 8)]
        depth: usize,
        #[arg(long, default_value_t = 160)]
        limit: usize,
    },
    /// 后向 BFS 依赖切片，多种子并/交。
    /// CSR, with multi-seed union/intersection. Use this when you want every
    /// trace row a value transitively depends on, faster than taint and
    /// without having to model propagation. Multi-seed `intersection` finds
    /// the common ancestors of two operations.
    BfsSlice {
        trace_dir: PathBuf,
        /// Single seed by trace index.
        #[arg(long)]
        idx: Option<usize>,
        /// Multi-seed by indices, comma-separated, e.g. "1234,5678". Up to
        /// 16 seeds per query.
        #[arg(long)]
        idxs: Option<String>,
        /// Single seed by register (last def before --before).
        #[arg(long)]
        reg: Option<String>,
        /// Multi-seed by registers, comma-separated, e.g. "x9,x10".
        #[arg(long)]
        regs: Option<String>,
        /// Single seed by memory address (last write before --before).
        #[arg(long)]
        addr: Option<String>,
        /// Multi-seed by addresses, comma-separated.
        #[arg(long)]
        addrs: Option<String>,
        /// Lookup cutoff for `--reg` / `--regs` / `--addr` / `--addrs`.
        /// Default = trace.len().
        #[arg(long)]
        before: Option<usize>,
        /// Drop control-flow edges. Default: include them.
        #[arg(long)]
        data_only: bool,
        /// 切片行数上限，受 core 硬上限约束。
        #[arg(long, default_value_t = 5_000)]
        limit: usize,
        /// `union` (default) or `intersection`. Multi-seed only —
        /// intersection across one seed equals the seed's slice.
        #[arg(long, default_value = "union")]
        mode: String,
        /// Module name/basename/prefix/substring for the seed (with --off).
        /// Resolves (SO,offset) -> PC -> chosen execution's idx as the seed.
        #[arg(long)]
        so: Option<String>,
        /// Module-relative offset of the seed (with --so). HEX by default.
        #[arg(long)]
        off: Option<String>,
        /// Which execution of that PC to seed from (0 = first). Default 0.
        #[arg(long, default_value_t = 0)]
        occurrence: usize,
    },
    /// def→use DAG，某值被谁消费。
    /// transitively consumed the seed's value. Inverse direction of
    /// `dep-graph` / `bfs-slice`.
    ForwardDepTree {
        trace_dir: PathBuf,
        /// Single seed by trace index.
        #[arg(long)]
        idx: Option<usize>,
        /// Seed by register (last def before --before).
        #[arg(long)]
        reg: Option<String>,
        /// Seed by memory address (last write before --before).
        #[arg(long)]
        addr: Option<String>,
        /// Lookup cutoff for `--reg` / `--addr` resolution. Default = trace.len().
        #[arg(long)]
        before: Option<usize>,
        /// Maximum BFS depth. depth=0 means seed only.
        #[arg(long, default_value_t = 8)]
        depth: usize,
        /// 返回节点数上限，受 core 硬上限约束。
        #[arg(long, default_value_t = 160)]
        limit: usize,
        /// Drop control-flow edges. Default: include them.
        #[arg(long)]
        data_only: bool,
        /// Module name/basename/prefix/substring for the seed (with --off).
        /// Resolves (SO,offset) -> PC -> chosen execution's idx as the seed.
        #[arg(long)]
        so: Option<String>,
        /// Module-relative offset of the seed (with --so). HEX by default.
        #[arg(long)]
        off: Option<String>,
        /// Which execution of that PC to seed from (0 = first). Default 0.
        #[arg(long, default_value_t = 0)]
        occurrence: usize,
    },
    /// 寄存器随 trace 区间变化的时间线。
    RegTimeline {
        trace_dir: PathBuf,
        #[arg(long)]
        reg: String,
        #[arg(long, default_value_t = 0)]
        start: usize,
        #[arg(long, default_value_t = -1)]
        end: isize,
        #[arg(long, default_value_t = 1000)]
        max_points: usize,
    },
    /// 两段内存差异。
    MemDiff {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 16)]
        size: usize,
    },
    /// 内存写入流。
    MemFlow {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 8)]
        count: usize,
        #[arg(long)]
        idx_lo: Option<usize>,
        #[arg(long)]
        idx_hi: Option<usize>,
        #[arg(long, default_value_t = 10)]
        events_per_byte: usize,
        #[arg(long)]
        writers_only: bool,
        #[arg(long)]
        readers_only: bool,
    },
    /// 范围内的全部内存写。
    MemWritesInRange {
        trace_dir: PathBuf,
        #[arg(long)]
        idx_lo: usize,
        #[arg(long, default_value_t = -1)]
        idx_hi: isize,
        #[arg(long)]
        addr_lo: Option<String>,
        #[arg(long)]
        addr_hi: Option<String>,
        #[arg(long)]
        src_byte: Option<String>,
        #[arg(long)]
        with_external: bool,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// Expand memory writes into the latest writer for each byte in a buffer.
    ByteWriterMap {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long)]
        size: u64,
        #[arg(long, default_value_t = 0)]
        idx_lo: usize,
        #[arg(long, default_value_t = -1)]
        idx_hi: isize,
        #[arg(long, default_value_t = 5000)]
        max: usize,
        /// Attach VM backchains for this many steps per selected writer run. 0 disables.
        #[arg(long, default_value_t = 0)]
        vm_chain_steps: usize,
        /// Max writer runs to expand with VM backchains.
        #[arg(long, default_value_t = 6)]
        vm_chain_runs: usize,
        /// Lookback window for each VM backchain step.
        #[arg(long, default_value_t = 1800000)]
        vm_chain_lookback: usize,
        /// Let attached VM chains continue through frontier source regs.
        #[arg(long)]
        vm_chain_follow_frontier: bool,
        /// Emit a compact AI-readable summary instead of all byte and chain details.
        #[arg(long)]
        summary: bool,
        /// Register holding the VM instruction pointer in this trace/profile.
        /// Required — traceMiku no longer assumes a target-specific default.
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// Register holding the VM state/virtual-register base. Required.
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// Register holding the dispatch table base or dispatch lookup base. Required.
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        /// Optional; sp/fp/lr and the three core VM regs are always included.
        #[arg(long)]
        vm_infra_regs: Option<String>,
    },
    /// 检测 OLLVM 风格 VM。
    OllvmDetectVm {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 10)]
        min_entries: usize,
        #[arg(long, default_value_t = 0.5)]
        threshold: f64,
    },
    /// 函数命中频次与热门块。
    FnSummary {
        trace_dir: PathBuf,
        #[arg(long = "fn")]
        fn_name: String,
        #[arg(long, default_value_t = 5)]
        top_blocks: usize,
    },
    /// 密码学常量指纹扫描。
    CryptoScan { trace_dir: PathBuf },
    /// Run combined crypto analysis (const scan + crypto instr detection).
    Crypto {
        /// Per-call trace directory.
        trace_dir: PathBuf,
    },
    /// 检测 hash finalize 模式。
    HashFinalizeDetect {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 500)]
        window: usize,
        #[arg(long, default_value_t = 16)]
        min_size: u64,
        #[arg(long, default_value_t = 500)]
        limit: usize,
        /// Expand candidate output buffers with byte-writer-map evidence.
        #[arg(long)]
        map_bytes: bool,
        /// Max candidates to expand when --map-bytes is enabled.
        #[arg(long, default_value_t = 50)]
        map_candidates: usize,
        /// Keep only mapped candidates whose bytes are not all zero.
        #[arg(long)]
        nonzero_only: bool,
        /// Optional target bytes as hex; mapped candidates report byte-offset hits.
        #[arg(long = "target-bytes")]
        target_bytes: Option<String>,
    },
    /// 已知目标摘要反查输入（指定算法组合）。
    HashInputSearch {
        trace_dir: PathBuf,
        #[arg(long = "target-bytes")]
        target_bytes: String,
        #[arg(long)]
        inputs: String,
        #[arg(long, default_value = "")]
        keys: String,
        #[arg(long, default_value = "sha1,md5,sha256,hmac-sha1,hmac-md5,hmac-sha256")]
        algos: String,
        #[arg(long, default_value = "plain,prefix_key,suffix_key,key_prefix_input")]
        combos: String,
        #[arg(long, default_value_t = 8)]
        prefix_bytes: usize,
        #[arg(long, default_value_t = false)]
        search_in_mem: bool,
    },
    /// 多条 trace 的稳定/变化字节对比。
    DiffTraces {
        traces: Vec<PathBuf>,
        /// Output key to diff. Repeat to compare multiple keys. Defaults to all observed keys.
        #[arg(long = "key")]
        keys: Vec<String>,
        #[arg(long, default_value_t = false)]
        show_offsets: bool,
        #[arg(long, default_value_t = false)]
        show_per_byte: bool,
    },
    /// 自动检测执行阶段。
    AutoPhaseDetect {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = true)]
        detect_byte_streams: bool,
        #[arg(long, default_value_t = 2000)]
        max_phases: usize,
    },
    /// JNI 调用列表。
    JniCalls {
        trace_dir: PathBuf,
        #[arg(long)]
        in_fn: Option<String>,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// JNI 事件（含参数/返回值）。
    JniEvents {
        trace_dir: PathBuf,
        #[arg(long, alias = "kind")]
        id: Option<String>,
        #[arg(long)]
        idx_lo: Option<usize>,
        #[arg(long)]
        idx_hi: Option<usize>,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// List NewStringUTF output key/value pairs.
    JniOutputStrings {
        trace_dir: PathBuf,
        /// Keep only pairs with this output key, for example a header name.
        #[arg(long)]
        key: Option<String>,
        /// Keep pairs whose key or value contains this text.
        #[arg(long)]
        contains: Option<String>,
        #[arg(long, default_value_t = 2000)]
        limit: usize,
    },
    /// Recursively scan jni_hooks.jsonl files for NewStringUTF key/value pairs.
    ScanJniOutputStrings {
        /// Trace root, run dir, or call dir. Defaults to ./traces.
        #[arg(default_value = "traces")]
        path: PathBuf,
        /// Keep only pairs with this output key, for example a header name.
        #[arg(long)]
        key: Option<String>,
        /// Keep pairs whose key or value contains this text.
        #[arg(long)]
        contains: Option<String>,
        /// Stop after this many returned pairs. 0 means no cap.
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Include percent-decoded value fields when the value is URL-encoded.
        #[arg(long)]
        decode_url: bool,
        /// Include best-effort base64 decoded length and prefix/suffix hex.
        #[arg(long)]
        decode_base64: bool,
        /// Include full base64 decoded hex. Useful for small signature payload diffing.
        #[arg(long)]
        decode_base64_full: bool,
        /// Include byte-level diff across decoded Base64 outputs.
        #[arg(long)]
        diff_base64: bool,
        /// Analyze a Base64 tail beginning at this output character offset.
        #[arg(long)]
        base64_tail_start: Option<usize>,
        /// Base64 characters to prepend before decoding the tail, for alignment.
        #[arg(long, default_value = "")]
        base64_tail_align_prefix: String,
        /// Drop this many decoded bytes from the aligned tail before diffing.
        #[arg(long, default_value_t = 0)]
        base64_tail_drop: usize,
        /// Include this many recent GetStringUTFChars strings before each output.
        #[arg(long, default_value_t = 0)]
        prior_inputs: usize,
    },
    /// Build an output-to-input backward trace report for a known output.
    OutputBacktrace {
        trace_dir: PathBuf,
        /// Start from a JNI NewStringUTF key/value pair, for example a header name.
        #[arg(long)]
        key: Option<String>,
        /// Start from an observed UTF-8 output string directly.
        #[arg(long)]
        value: Option<String>,
        /// Start from raw bytes as hex instead of a UTF-8 string.
        #[arg(long = "bytes-hex")]
        bytes_hex: Option<String>,
        /// Max NewStringUTF events to scan when --key is used.
        #[arg(long, default_value_t = 2000)]
        jni_limit: usize,
        /// Max memory locations to report for each byte pattern.
        #[arg(long, default_value_t = 20)]
        max_mem_hits: usize,
        /// Max memory writes to report for each memory hit.
        #[arg(long, default_value_t = 20)]
        writes_per_hit: usize,
        /// Max backward-taint seeds to run from discovered writers.
        #[arg(long, default_value_t = 8)]
        taint_seeds: usize,
        /// Max rows per backward-taint seed.
        #[arg(long, default_value_t = 1000)]
        taint_max_count: usize,
        /// Attach VM backchains for this many steps per selected writer run. 0 disables.
        #[arg(long, default_value_t = 0)]
        vm_chain_steps: usize,
        /// Max writer runs per memory hit to expand with VM backchains.
        #[arg(long, default_value_t = 6)]
        vm_chain_runs: usize,
        /// Lookback window for each VM backchain step.
        #[arg(long, default_value_t = 200000)]
        vm_chain_lookback: usize,
        /// Let attached VM chains continue through frontier source regs when a table/ALU step has no upstream writer.
        #[arg(long)]
        vm_chain_follow_frontier: bool,
        /// Register holding the VM instruction pointer in this trace/profile.
        /// Required — traceMiku no longer assumes a target-specific default.
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// Register holding the VM state/virtual-register base. Required.
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// Register holding the dispatch table base or dispatch lookup base. Required.
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        /// Optional; sp/fp/lr and the three core VM regs are always included.
        #[arg(long)]
        vm_infra_regs: Option<String>,
        /// Skip backward-taint expansion and only report output/memory writers.
        #[arg(long)]
        skip_taint: bool,
        /// Do not add a percent-decoded pattern for URL-encoded strings.
        #[arg(long = "no-url-decode")]
        no_url_decode: bool,
        /// Do not add a best-effort Base64-decoded byte pattern for textual outputs.
        #[arg(long = "no-base64-decode")]
        no_base64_decode: bool,
    },
    /// Compact map from textual output/Base64 groups to writer runs.
    OutputMap {
        trace_dir: PathBuf,
        /// Start from a JNI NewStringUTF key/value pair, for example a header name.
        #[arg(long)]
        key: Option<String>,
        /// Start from an observed UTF-8 output string directly.
        #[arg(long)]
        value: Option<String>,
        /// Max NewStringUTF events to scan when --key is used.
        #[arg(long, default_value_t = 2000)]
        jni_limit: usize,
        /// Max memory locations to consider for the observed output bytes.
        #[arg(long, default_value_t = 8)]
        max_mem_hits: usize,
        /// Ranked memory hit to use after --hit-order sorting.
        #[arg(long, default_value_t = 0)]
        hit_rank: usize,
        /// Memory-hit ordering before applying --hit-rank.
        ///
        /// earliest is best for reversing generation; nearest follows the final JNI handoff.
        #[arg(long, value_enum, default_value_t = HitOrder::Earliest)]
        hit_order: HitOrder,
        /// First Base64 group offset to return.
        #[arg(long, default_value_t = 0)]
        group_start: usize,
        /// Number of Base64 groups to return. 0 means all groups.
        #[arg(long, default_value_t = 0)]
        groups: usize,
        /// Select groups covering this decoded semantic byte offset.
        #[arg(long)]
        semantic_offset: Option<usize>,
        /// Number of decoded semantic bytes to cover when --semantic-offset is set.
        #[arg(long, default_value_t = 1)]
        semantic_count: usize,
        /// Attach VM backtrees for this depth per group. 0 disables.
        #[arg(long, default_value_t = 0)]
        tree_depth: usize,
        /// Max nodes per attached VM backtree.
        #[arg(long, default_value_t = 120)]
        tree_max_nodes: usize,
        /// Attach VM backtrees to matched Base64 alphabet index registers. If --tree-depth is 0,
        /// output-map builds hidden lookup trees to find alphabet table lookups first.
        #[arg(long, default_value_t = 0)]
        index_tree_depth: usize,
        /// Max nodes per attached Base64 index VM backtree.
        #[arg(long, default_value_t = 80)]
        index_tree_max_nodes: usize,
        /// Include frontier source-reg branches even when a tree node has an upstream memory edge.
        #[arg(long = "tree-frontier-with-next")]
        tree_frontier_with_next: bool,
        /// Lookback window for each VM backtree step.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Do not percent-decode the textual output before Base64 grouping.
        #[arg(long = "no-url-decode")]
        no_url_decode: bool,
        /// Analyze a Base64 tail beginning at this output character offset.
        #[arg(long)]
        base64_tail_start: Option<usize>,
        /// Base64 characters to prepend before grouping the tail, for alignment.
        #[arg(long, default_value = "")]
        base64_tail_align_prefix: String,
        /// Drop this many decoded bytes from the aligned tail before assigning semantic offsets.
        #[arg(long, default_value_t = 0)]
        base64_tail_drop: usize,
        /// Attach byte-writer-map evidence for decoded semantic bytes in the pre-encoding scratch buffer.
        #[arg(long)]
        semantic_writer_map: bool,
        /// Override the exclusive idx_hi used for --semantic-writer-map. Defaults to the first final-output writer.
        #[arg(long)]
        semantic_writer_map_idx_hi: Option<usize>,
        /// Max writes to read while building --semantic-writer-map.
        #[arg(long, default_value_t = 5000)]
        semantic_writer_map_max: usize,
        /// Attach VM backchains for this many steps per semantic writer run. 0 disables.
        #[arg(long, default_value_t = 0)]
        semantic_writer_map_vm_chain_steps: usize,
        /// Max semantic writer runs to expand with VM backchains.
        #[arg(long, default_value_t = 8)]
        semantic_writer_map_vm_chain_runs: usize,
        /// Expand semantic writer VM chains per byte lane instead of per coalesced writer run.
        #[arg(long)]
        semantic_writer_map_vm_chain_bytes: bool,
        /// Lookback window for each semantic writer VM backchain step.
        #[arg(long, default_value_t = 1800000)]
        semantic_writer_map_vm_chain_lookback: usize,
        /// Let semantic writer VM chains continue through frontier source regs.
        #[arg(long)]
        semantic_writer_map_vm_chain_follow_frontier: bool,
        /// Register holding the VM instruction pointer in this trace/profile.
        /// Required — traceMiku no longer assumes a target-specific default.
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// Register holding the VM state/virtual-register base. Required.
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// Register holding the dispatch table base or dispatch lookup base. Required.
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        /// Optional; sp/fp/lr and the three core VM regs are always included.
        #[arg(long)]
        vm_infra_regs: Option<String>,
        /// Emit a compact AI-readable summary.
        #[arg(long)]
        summary: bool,
    },
    /// Compact dynamic VM-oriented record slice.
    VmSlice {
        trace_dir: PathBuf,
        /// First trace index to include.
        #[arg(long)]
        start: usize,
        /// End trace index, exclusive. Overrides --count.
        #[arg(long)]
        end: Option<usize>,
        /// Number of records when --end is not set.
        #[arg(long, default_value_t = 300)]
        count: usize,
        /// Comma-separated registers to include in the analysis.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        /// Drop records that do not look VM-related.
        #[arg(long)]
        only_vm: bool,
        /// Register holding the VM instruction pointer in this trace/profile.
        /// Required — traceMiku no longer assumes a target-specific default.
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// Register holding the VM state/virtual-register base. Required.
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// Register holding the dispatch table base or dispatch lookup base. Required.
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        /// Optional; sp/fp/lr and the three core VM regs are always included.
        #[arg(long)]
        vm_infra_regs: Option<String>,
        /// Base VM IP for vm_off. Defaults to the first row's --vm-ip-reg.
        #[arg(long)]
        base_ip: Option<String>,
    },
    /// Group dynamic VM-oriented records into compact virtual instruction slices.
    VmOps {
        trace_dir: PathBuf,
        /// First trace index to include.
        #[arg(long)]
        start: usize,
        /// End trace index, exclusive. Overrides --count.
        #[arg(long)]
        end: Option<usize>,
        /// Number of records when --end is not set.
        #[arg(long, default_value_t = 300)]
        count: usize,
        /// Comma-separated registers to include in the analysis.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        /// Register holding the VM instruction pointer in this trace/profile.
        /// Required — traceMiku no longer assumes a target-specific default.
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// Register holding the VM state/virtual-register base. Required.
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// Register holding the dispatch table base or dispatch lookup base. Required.
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        /// Optional; sp/fp/lr and the three core VM regs are always included.
        #[arg(long)]
        vm_infra_regs: Option<String>,
        /// Base VM IP for vm_off. Defaults to the first row's --vm-ip-reg.
        #[arg(long)]
        base_ip: Option<String>,
        /// Max VM op groups to return.
        #[arg(long, default_value_t = 80)]
        max_ops: usize,
        /// Max records per analysis chunk; 0 requests the whole selected window.
        #[arg(long, default_value_t = 900)]
        chunk_size: usize,
        /// Emit a compact AI-readable summary.
        #[arg(long)]
        summary: bool,
        /// With --summary, emit only top-level effects and state updates.
        #[arg(long)]
        effects_only: bool,
        /// Emit a minimal replay-oriented template summary for AI agents.
        #[arg(long)]
        compact: bool,
        /// Emit ordered compact replay steps plus template skeletons.
        #[arg(long)]
        replay_plan: bool,
    },
    /// Follow a single byte backward through memory writes and VM source registers.
    ByteLineage {
        trace_dir: PathBuf,
        /// Memory byte address to start from.
        #[arg(long)]
        addr: String,
        /// Find the last write strictly before this trace index.
        #[arg(long)]
        before_idx: usize,
        /// Number of consecutive bytes to trace starting at --addr.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Max lineage steps.
        #[arg(long, default_value_t = 12)]
        depth: usize,
        /// Local records to inspect before each writer idx.
        #[arg(long, default_value_t = 120)]
        context: usize,
        /// How far back to scan memory writers for each discovered source.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Max memory writes to collect while looking for the last one.
        #[arg(long, default_value_t = 5000)]
        max_writes: usize,
        /// Comma-separated registers to include in the analysis.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        /// Emit a compact AI-readable summary instead of the full step payload.
        #[arg(long)]
        summary: bool,
        /// Emit a minimal path/frontier digest for AI agents.
        #[arg(long)]
        compact: bool,
    },
    /// One backward step through a dynamic VM store/load chain.
    VmBackstep {
        trace_dir: PathBuf,
        /// Writer/load trace index to explain.
        #[arg(long)]
        idx: usize,
        /// Source register to chase. Defaults to the first store source reg.
        #[arg(long)]
        reg: Option<String>,
        /// Local records to inspect before idx.
        #[arg(long, default_value_t = 120)]
        context: usize,
        /// How far back to scan memory writers for the discovered source.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Max memory writes to collect while looking for the last one.
        #[arg(long, default_value_t = 5000)]
        max_writes: usize,
        /// Comma-separated registers to include in the analysis.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        /// Register holding the VM instruction pointer in this trace/profile.
        /// Required — traceMiku no longer assumes a target-specific default.
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// Register holding the VM state/virtual-register base. Required.
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// Register holding the dispatch table base or dispatch lookup base. Required.
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        /// Optional; sp/fp/lr and the three core VM regs are always included.
        #[arg(long)]
        vm_infra_regs: Option<String>,
    },
    /// Iterate vm-backstep and emit a compact backward chain.
    VmBackchain {
        trace_dir: PathBuf,
        /// Initial writer/load trace index.
        #[arg(long)]
        idx: usize,
        /// Initial source register. Defaults to the first store source reg.
        #[arg(long)]
        reg: Option<String>,
        /// Max backward steps.
        #[arg(long, default_value_t = 8)]
        steps: usize,
        /// Local records to inspect before each idx.
        #[arg(long, default_value_t = 120)]
        context: usize,
        /// How far back to scan memory writers for each discovered source.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Max memory writes to collect while looking for the last one.
        #[arg(long, default_value_t = 5000)]
        max_writes: usize,
        /// Continue through a chosen frontier source reg when upstream.next is unavailable.
        #[arg(long)]
        follow_frontier: bool,
        /// Prefer upstream memory byte writers matching this little-endian source byte lane.
        #[arg(long)]
        byte_lane: Option<usize>,
        /// Emit a compact AI-readable summary instead of the full step payload.
        #[arg(long)]
        summary: bool,
        /// Comma-separated registers to include in the analysis.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        /// Register holding the VM instruction pointer in this trace/profile.
        /// Required — traceMiku no longer assumes a target-specific default.
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// Register holding the VM state/virtual-register base. Required.
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// Register holding the dispatch table base or dispatch lookup base. Required.
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        /// Optional; sp/fp/lr and the three core VM regs are always included.
        #[arg(long)]
        vm_infra_regs: Option<String>,
    },
    /// Branching backward tree through dynamic VM upstream/frontier links.
    VmBacktree {
        trace_dir: PathBuf,
        /// Initial writer/load trace index.
        #[arg(long)]
        idx: usize,
        /// Initial source register. Defaults to the first store source reg.
        #[arg(long)]
        reg: Option<String>,
        /// Max tree depth.
        #[arg(long, default_value_t = 6)]
        depth: usize,
        /// Max returned tree nodes.
        #[arg(long, default_value_t = 64)]
        max_nodes: usize,
        /// Local records to inspect before each idx.
        #[arg(long, default_value_t = 120)]
        context: usize,
        /// How far back to scan memory writers for each discovered source.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Max memory writes to collect while looking for the last one.
        #[arg(long, default_value_t = 5000)]
        max_writes: usize,
        /// Also enqueue frontier branches when upstream.next exists.
        #[arg(long)]
        frontier_with_next: bool,
        /// Emit a compact AI-readable summary instead of the full node tree.
        #[arg(long)]
        summary: bool,
        /// Comma-separated registers to include in the analysis.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        /// Register holding the VM instruction pointer in this trace/profile.
        /// Required — traceMiku no longer assumes a target-specific default.
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// Register holding the VM state/virtual-register base. Required.
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// Register holding the dispatch table base or dispatch lookup base. Required.
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        /// Optional; sp/fp/lr and the three core VM regs are always included.
        #[arg(long)]
        vm_infra_regs: Option<String>,
    },
    /// 指定 JNI jobject 的历史。
    JobjHistory {
        trace_dir: PathBuf,
        #[arg(long)]
        jobject: String,
        #[arg(long, default_value_t = 0)]
        start: usize,
        #[arg(long, default_value_t = -1)]
        end: isize,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// JNI NewStringUTF 输出串。
    JniStrings {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 200)]
        max: usize,
        #[arg(long, default_value_t = 128)]
        max_len: usize,
    },
    /// Repair per-call meta.json from trace.bin and normalize call directory names.
    Finalize {
        /// Run directory (contains calls/).
        path: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum HitOrder {
    Earliest,
    Nearest,
    Latest,
}
impl From<HitOrder> for core_reports::HitOrder {
    fn from(value: HitOrder) -> Self {
        match value {
            HitOrder::Earliest => Self::Earliest,
            HitOrder::Nearest => Self::Nearest,
            HitOrder::Latest => Self::Latest,
        }
    }
}
