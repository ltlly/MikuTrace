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
    /// 列出分析命令及参数的 JSON 清单；统一入口还包含采集命令。
    Capabilities,
    /// 逐条检查 ARM64 状态转移；在首个发散、证据缺口或不支持指令处停止。
    TraceReplay {
        #[command(flatten)]
        args: super::replay_command::ReplayArgs,
    },
    /// 输出指定 shell 的补全脚本。
    Completions {
        /// shell 类型：bash、zsh、fish、powershell、elvish。
        shell: clap_complete::Shell,
    },
    /// 读取单次采集元数据、格式版本及模块映射。
    Meta {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
    },
    /// 枚举 trace 根目录中的 run，或 run 下的 calls。
    List {
        /// trace 根目录或 run 目录；省略使用 --dir。
        path: Option<PathBuf>,
        /// 省略 path 时使用的 trace 根目录。
        #[arg(long, default_value = "traces")]
        dir: PathBuf,
        /// 输出一个 JSON 数组；省略时每行一个 JSON 对象。
        #[arg(long)]
        json: bool,
    },
    /// 查看 run/call 的记录数、结束状态及采集摘要。
    Info {
        /// run 或单次 call 目录。
        path: PathBuf,
    },
    /// 按保存的 /proc/<pid>/maps 解析运行时地址及文件偏移。
    ResolveMapAddr {
        /// 保存的 /proc/<pid>/maps 文本文件。
        maps_file: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        addr: String,
    },
    /// 查询本地 ELF 偏移之前最近的符号；需要 llvm-nm 或 nm。
    ResolveElfSymbol {
        /// 本地 ELF/SO 文件。
        elf_file: PathBuf,
        /// ELF 虚拟偏移，默认十六进制；d16 表示十进制 16。
        offset: String,
    },
    /// 批量读取执行记录及可选的指令前寄存器值。
    Records {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 起始记录下标，从 0 开始（包含）。
        #[arg(long, default_value_t = 0)]
        start: usize,
        /// 请求记录数。
        #[arg(long, default_value_t = 100)]
        count: usize,
        /// 逗号分隔的寄存器名。
        #[arg(long)]
        regs: Option<String>,
        /// 逗号分隔的记录下标；逐条返回完整详情，覆盖 --start/--count/--regs。
        #[arg(long)]
        indices: Option<String>,
    },
    /// 读取单条指令、执行前寄存器及地址注释。
    Record {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        idx: usize,
    },
    /// 查询同一 PC 的所有执行位置，按游标前后分页。
    #[command(name = "pc-hits")]
    IdxsForPc {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时指令地址，默认十六进制；d16 表示十进制 16。
        pc: String,
        /// 记录下标游标，区分游标前后的结果。
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// 用正则表达式搜索反汇编指令和操作数。
    Search {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 匹配指令与操作数字符串的正则表达式。
        pattern: String,
        /// 最多返回的匹配记录数，范围 1–5000。
        #[arg(long, default_value_t = 2000)]
        max_results: usize,
        /// 从此记录起继续搜索；结果提供下一游标。
        #[arg(long)]
        cursor: Option<usize>,
    },
    /// 按 SO 统计观测到的指令执行次数。
    SoStats {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 按执行次数返回前 N 个 SO。
        #[arg(long, default_value_t = 50)]
        top: usize,
        /// 返回所有 SO，覆盖 --top。
        #[arg(long)]
        all: bool,
    },
    /// 在运行时地址与 (SO, 偏移) 之间转换，并返回执行次数与位置。
    Resolve {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: Option<String>,
        /// 模块全名、basename、前缀或子串；与 --off 配合，歧义会返回候选。
        #[arg(long)]
        so: Option<String>,
        /// 模块内偏移，默认十六进制；与 --so 配合。
        #[arg(long)]
        off: Option<String>,
    },
    /// 统计 br/blr 的实际目标；不指定源地址时列出所有间接跳转点。
    IndirectTargets {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: Option<String>,
        /// 模块全名、basename、前缀或子串；与 --off 配合，歧义会返回候选。
        #[arg(long)]
        so: Option<String>,
        /// 模块内偏移，默认十六进制；与 --so 配合。
        #[arg(long)]
        off: Option<String>,
        /// 仅保留至少命中 N 次的跳转目标。
        #[arg(long)]
        min_count: Option<u64>,
    },
    /// 查询指定 PC 每次执行前的寄存器值及去重分布。
    RegAt {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: String,
        /// 查询该 PC 的执行；也可用 --so 与 --off。
        #[arg(long)]
        addr: Option<String>,
        /// 模块全名、basename、前缀或子串；与 --off 配合，歧义会返回候选。
        #[arg(long)]
        so: Option<String>,
        /// 模块内偏移，默认十六进制；与 --so 配合。
        #[arg(long)]
        off: Option<String>,
        /// 最多返回的逐次执行值；去重分布仍统计全部命中。
        #[arg(long)]
        max: Option<usize>,
    },
    /// 查询单条记录执行前的一个寄存器值。
    RegValueAt {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: usize,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: String,
    },
    /// 查找给定记录之前最后一次定义该寄存器的指令。
    LastWriteOfReg {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: String,
        /// 只查询此记录之前（不含）的定义；省略表示 trace 末尾。
        #[arg(long)]
        before: Option<usize>,
    },
    /// 查找给定记录之后下一次读取该寄存器的指令。
    NextUseOfReg {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: String,
        /// 只查询此记录之后（不含）的使用；省略为 0。
        #[arg(long)]
        after: Option<usize>,
    },
    /// 按寄存器变化、值相等或内存访问条件扫描记录。
    Watch {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 条件类型：reg-change、reg-equals、mem-touch。
        #[arg(long, default_value = "reg-change", value_parser = ["reg-change", "reg-equals", "mem-touch"])]
        kind: String,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: Option<String>,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: Option<String>,
        /// 比较值，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        value: Option<String>,
        /// 内存范围长度（字节，十进制）。
        #[arg(long, default_value_t = 1)]
        size: u64,
        /// 从此记录起扫描。
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// 列出来自符号及实际调用的函数；--fn 筛选使用返回项的 name。
    Functions {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
    },
    /// 查询采集时记录的 fork/clone 事件；需启用 fork hook。
    ForkEvents {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 按 attach_status 原值筛选，如 attached、failed。
        #[arg(long)]
        status: Option<String>,
        /// 按事件 is_fork_like 布尔值筛选（true/false）。
        #[arg(long)]
        is_fork_like: Option<bool>,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// 返回观测到的函数基本块和控制流边。
    Cfg {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// functions 返回项的 name（符号名称）；省略表示全局 CFG。
        #[arg(long = "fn")]
        fn_name: Option<String>,
    },
    /// 查询包含给定 PC 的基本块所覆盖的记录下标。
    #[command(name = "block-hits")]
    IdxsForBlock {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时指令地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        pc: String,
        /// 请求返回记录数上限；受 core 硬上限约束。
        #[arg(long, default_value_t = 200)]
        max_count: usize,
        /// 优先返回最靠近此记录的命中；-1 按记录顺序返回。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        near: isize,
    },
    /// 返回包含给定 PC 的基本块、指令和出口。
    Block {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时指令地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        pc: String,
    },
    /// 查询观测 CFG 中的循环强连通分量。
    Loops {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
    },
    /// 统计函数内观测分支的方向和次数；不代表静态代码全覆盖率。
    #[command(name = "branch-coverage")]
    Coverage {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: Option<String>,
        /// 模块全名、basename、前缀或子串；与 --off 配合，歧义会返回候选。
        #[arg(long)]
        so: Option<String>,
        /// 模块内偏移，默认十六进制；与 --so 配合。
        #[arg(long)]
        off: Option<String>,
        /// functions 返回项的 name（符号名称）。
        #[arg(long = "fn")]
        fn_name: Option<String>,
    },
    /// 重放调用边界，返回指定记录处的动态调用栈。
    Backtrace {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: usize,
        /// 最多返回的栈帧数。
        #[arg(long, default_value_t = 256)]
        limit: usize,
    },
    /// 汇总观测到的调用树及各节点执行次数。
    CallTree {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 调用树深度上限；省略使用 core 默认值。
        #[arg(long)]
        max_depth: Option<usize>,
    },
    /// 从指定记录的 LR 反查调用点链，作为调用栈的另一种证据。
    CallChain {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: usize,
        /// 沿 LR 最多回查的调用点数（硬上限 256）。
        #[arg(long, default_value_t = 5)]
        depth: usize,
    },
    /// 提取已观测内存中的可打印字符串。
    Strings {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 最短字符串长度（字节）。
        #[arg(long, default_value_t = 4)]
        min_len: usize,
        /// 字符串包含的文本；空值不筛选。
        #[arg(long, default_value = "")]
        q: String,
        /// 仅显示每个字节都已在此记录前观测到的串；-1 不限制。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        cursor: i64,
        /// 字符串数量上限；0 使用硬上限 5000。
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
    /// 查询内存范围逐字节当前值及读写历史；每字节最多返回各 20 条记录。
    #[command(name = "mem-byte-history")]
    StringProvenance {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 查询字节数，范围 1–4096。
        #[arg(long, default_value_t = 32)]
        length: usize,
    },
    /// 查询指定时刻的内存字节；未观测字节保留未知。
    MemDump {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 读取字节数，范围 1–4096。
        #[arg(long, default_value_t = 256)]
        count: usize,
        /// 内存观测时刻的记录下标（包含）；省略表示 trace 末尾。
        #[arg(long)]
        cursor: Option<u64>,
        /// 仅输出摘要，省略完整明细。
        #[arg(long)]
        summary: bool,
        /// 按 NUL 终止的 C 字符串生成摘要。
        #[arg(long)]
        cstr: bool,
    },
    /// 导出 trace 结束时逐字节值、来源类别和最近写入者。
    #[command(name = "mem-provenance")]
    MemTenet {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 内存范围长度（字节，十进制）。
        #[arg(long, default_value_t = 64)]
        length: usize,
    },
    /// 按地址或 (SO, 偏移) 导出运行时字节及完整度，不执行解密算法。
    MemExport {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: Option<String>,
        /// 模块全名、basename、前缀或子串；与 --off 配合，歧义会返回候选。
        #[arg(long)]
        so: Option<String>,
        /// 模块内偏移，默认十六进制；与 --so 配合。
        #[arg(long)]
        off: Option<String>,
        /// 导出字节数，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        len: String,
        /// 内存观测时刻的记录下标（包含）；省略表示 trace 末尾。
        #[arg(long)]
        cursor: Option<u64>,
        /// 同时写出原始字节文件；JSON 保留来源与完整度，未知字节不会成为已知证据。
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// 查找指定时刻之前覆盖该内存地址的最后一次写入。
    LastWriteOfAddr {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 仅查询此前的写入；-1 表示 trace 末尾。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        before_idx: isize,
        /// 包含边界差分记录的外部写入。
        #[arg(long)]
        with_external: bool,
    },
    /// 查询一个内存字节的读写记录，可附观测值。
    #[command(name = "mem-accesses")]
    IdxsTouchingAddr {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 记录下标游标，区分游标前后的结果。
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 30)]
        limit: usize,
        /// 附每次访问的字节观测值及来源。
        #[arg(long)]
        with_bytes: bool,
    },
    /// 查询与内存范围相交的读写记录，按游标前后分页。
    #[command(name = "mem-range-accesses")]
    IdxsTouchingRange {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 内存范围长度（字节，十进制）。
        #[arg(long, default_value_t = 1)]
        size: u64,
        /// 记录下标游标，区分游标前后的结果。
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// 在已观测内存中查找指定字节序列及首次观测位置。
    FindMemPattern {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 字节序列的十六进制文本，如 41424300。
        #[arg(long = "bytes-hex")]
        bytes_hex: String,
        /// 首次观测下标下限；-1 不限制。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        since: isize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 100)]
        max: usize,
        /// 记录范围起点（包含）；省略从 trace 开始。
        #[arg(long)]
        idx_lo: Option<usize>,
        /// 记录范围终点（不包含）；省略或 -1 表示 trace 末尾。
        #[arg(long)]
        idx_hi: Option<usize>,
    },
    /// 从寄存器种子逐指令向后传播影响，返回父节点与传播深度。
    TaintFwd {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 起始记录下标，从 0 开始（包含）。
        #[arg(long)]
        start: usize,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: String,
        /// 请求返回记录数上限；受 core 硬上限约束。
        #[arg(long)]
        max_count: Option<usize>,
        /// 通过内存 load/store 传播数据依赖。
        #[arg(long)]
        through_mem: bool,
        /// 排除控制流和地址寄存器依赖，仅追踪值来源。
        #[arg(long)]
        data_only: bool,
        /// 允许跨越函数调用边界。
        #[arg(long)]
        cross_fn_call: bool,
        /// 连续 N 条无新增命中后停止；0 关闭该早停，省略使用 core 默认值。
        #[arg(long)]
        scan_limit: Option<usize>,
    },
    /// 从寄存器种子逐指令反向追踪来源，可跨内存和调用边界。
    TaintBwd {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 来源回溯的种子记录下标；或使用 --so/--off/--occurrence。
        #[arg(long)]
        start: Option<usize>,
        /// 模块全名、basename、前缀或子串；与 --off 配合，歧义会返回候选。
        #[arg(long)]
        so: Option<String>,
        /// 模块内偏移，默认十六进制；与 --so 配合。
        #[arg(long)]
        off: Option<String>,
        /// 选择该 PC 的第几次执行，从 0 开始。
        #[arg(long, default_value_t = 0)]
        occurrence: usize,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: String,
        /// 请求返回记录数上限；受 core 硬上限约束。
        #[arg(long)]
        max_count: Option<usize>,
        /// 通过内存 load/store 传播数据依赖。
        #[arg(long)]
        through_mem: bool,
        /// 排除控制流和地址寄存器依赖，仅追踪值来源。
        #[arg(long)]
        data_only: bool,
        /// 允许跨越函数调用边界。
        #[arg(long)]
        cross_fn_call: bool,
        /// 连续 N 条无新增命中后停止；0 关闭该早停，省略使用 core 默认值。
        #[arg(long)]
        scan_limit: Option<usize>,
    },
    /// 沿单个寄存器的定义与使用链追踪，并排除指定寄存器。
    #[command(name = "reg-chase")]
    DataChase {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 起始记录下标，从 0 开始（包含）。
        #[arg(long)]
        start: usize,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: String,
        /// 最多追踪的步骤数。
        #[arg(long, default_value_t = 50)]
        max_steps: usize,
        /// 排除的寄存器，逗号分隔。
        #[arg(long, default_value = "sp,fp,lr")]
        exclude_regs: String,
    },
    /// 返回种子记录、寄存器或内存值的有界后向依赖图。
    DepGraph {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: Option<usize>,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: Option<String>,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: Option<String>,
        /// 只查询此记录之前（不含）的定义；省略表示 trace 末尾。
        #[arg(long)]
        before: Option<usize>,
        /// 最多展开的依赖层数。
        #[arg(long, default_value_t = 8)]
        depth: usize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 160)]
        limit: usize,
    },
    /// 查询后向依赖记录集合；多种子可求并集或共同来源。
    BfsSlice {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: Option<usize>,
        /// 多个种子记录下标，逗号分隔；最多 16 个种子。
        #[arg(long)]
        idxs: Option<String>,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: Option<String>,
        /// 逗号分隔的寄存器名。
        #[arg(long)]
        regs: Option<String>,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: Option<String>,
        /// 多个种子内存地址，逗号分隔；默认十六进制。
        #[arg(long)]
        addrs: Option<String>,
        /// 只查询此记录之前（不含）的定义；省略表示 trace 末尾。
        #[arg(long)]
        before: Option<usize>,
        /// 排除控制流和地址寄存器依赖，仅追踪值来源。
        #[arg(long)]
        data_only: bool,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 5_000)]
        limit: usize,
        /// 多种子组合：union 求并集，intersection 求共同依赖。
        #[arg(long, default_value = "union", value_parser = ["union", "intersection"])]
        mode: String,
        /// 模块全名、basename、前缀或子串；与 --off 配合，歧义会返回候选。
        #[arg(long)]
        so: Option<String>,
        /// 模块内偏移，默认十六进制；与 --so 配合。
        #[arg(long)]
        off: Option<String>,
        /// 选择该 PC 的第几次执行，从 0 开始。
        #[arg(long, default_value_t = 0)]
        occurrence: usize,
    },
    /// 返回种子值的有界前向 def→use 依赖图。
    #[command(name = "forward-dep-graph")]
    ForwardDepTree {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: Option<usize>,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: Option<String>,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: Option<String>,
        /// 只查询此记录之前（不含）的定义；省略表示 trace 末尾。
        #[arg(long)]
        before: Option<usize>,
        /// 最多展开的依赖层数。
        #[arg(long, default_value_t = 8)]
        depth: usize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 160)]
        limit: usize,
        /// 排除控制流和地址寄存器依赖，仅追踪值来源。
        #[arg(long)]
        data_only: bool,
        /// 模块全名、basename、前缀或子串；与 --off 配合，歧义会返回候选。
        #[arg(long)]
        so: Option<String>,
        /// 模块内偏移，默认十六进制；与 --so 配合。
        #[arg(long)]
        off: Option<String>,
        /// 选择该 PC 的第几次执行，从 0 开始。
        #[arg(long, default_value_t = 0)]
        occurrence: usize,
    },
    /// 查询区间内寄存器的变化时间线。
    RegTimeline {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: String,
        /// 起始记录下标，从 0 开始（包含）。
        #[arg(long, default_value_t = 0)]
        start: usize,
        /// 结束记录下标（不包含）；-1 表示 trace 末尾。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        end: isize,
        /// 最多返回的时间线点数。
        #[arg(long, default_value_t = 1000)]
        max_points: usize,
    },
    /// 比较同一内存范围在 idx-1 与 idx 时刻的字节。
    MemDiff {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: usize,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 内存范围长度（字节，十进制）。
        #[arg(long, default_value_t = 16)]
        size: usize,
    },
    /// 查询内存范围逐字节的读写事件序列。
    MemFlow {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 查询字节数（十进制）。
        #[arg(long, default_value_t = 8)]
        count: usize,
        /// 记录范围起点（包含）；省略从 trace 开始。
        #[arg(long)]
        idx_lo: Option<usize>,
        /// 记录范围终点（不包含）；省略表示 trace 末尾。
        #[arg(long)]
        idx_hi: Option<usize>,
        /// 每个字节最多返回的事件数。
        #[arg(long, default_value_t = 10)]
        events_per_byte: usize,
        /// 仅返回写入事件。
        #[arg(long)]
        writers_only: bool,
        /// 仅返回读取事件。
        #[arg(long)]
        readers_only: bool,
    },
    /// 查询记录区间及可选地址范围内的内存写入。
    MemWritesInRange {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录范围起点（包含），必须提供。
        #[arg(long)]
        idx_lo: usize,
        /// 记录范围终点（不包含）；省略或 -1 表示 trace 末尾。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        idx_hi: isize,
        /// 地址范围起点（包含），默认十六进制。
        #[arg(long)]
        addr_lo: Option<String>,
        /// 地址范围终点（不包含），默认十六进制。
        #[arg(long)]
        addr_hi: Option<String>,
        /// 筛选写入中的目标字节值，默认十六进制，取最低 8 位。
        #[arg(long)]
        src_byte: Option<String>,
        /// 包含边界差分记录的外部写入。
        #[arg(long)]
        with_external: bool,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// 按给定时间范围，为缓冲区每个字节定位最新写入者。
    ByteWriterMap {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 内存范围长度（字节，十进制）。
        #[arg(long)]
        size: u64,
        /// 记录范围起点（包含）；省略从 trace 开始。
        #[arg(long, default_value_t = 0)]
        idx_lo: usize,
        /// 记录范围终点（不包含）；省略或 -1 表示 trace 末尾。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        idx_hi: isize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
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
        /// 仅输出摘要，省略完整明细。
        #[arg(long)]
        summary: bool,
        #[command(flatten)]
        vm: super::vm_args::VmArgs,
    },
    /// 统计函数执行频次和最常命中的基本块。
    FnSummary {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// functions 返回项的 name（符号名称）。
        #[arg(long = "fn")]
        fn_name: String,
        /// 返回最常命中的前 N 个基本块。
        #[arg(long, default_value_t = 5)]
        top_blocks: usize,
    },
    /// 搜索密码常量和 ARM Crypto Extension 指令，输出候选证据。
    Crypto {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
    },
    /// 检索时间窗内地址连续的写入区间；不推断哈希算法或函数阶段。
    #[command(name = "mem-write-bursts")]
    MemWriteBursts {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 连续写入区间首末记录允许相差的最大条数。
        #[arg(long, default_value_t = 500)]
        window: usize,
        /// 连续写入区间的最小字节数。
        #[arg(long, default_value_t = 16)]
        min_size: u64,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 500)]
        limit: usize,
        /// 附候选区间的逐字节写入者映射。
        #[arg(long)]
        map_bytes: bool,
        /// 最多展开的候选区间数。
        #[arg(long, default_value_t = 50)]
        map_candidates: usize,
        /// 展开候选映射并仅保留非全零区间。
        #[arg(long)]
        nonzero_only: bool,
        /// 目标字节的十六进制文本。
        #[arg(long = "target-bytes")]
        target_bytes: Option<String>,
    },
    /// 验证用户给定的摘要输入和密钥组合，可关联运行时内存证据。
    HashInputSearch {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 目标字节的十六进制文本。
        #[arg(long = "target-bytes")]
        target_bytes: String,
        /// 候选输入文本，逗号分隔；按 UTF-8 字节计算。
        #[arg(long)]
        inputs: String,
        /// 候选密钥文本，逗号分隔；空字符串也是候选。
        #[arg(long, default_value = "")]
        keys: String,
        /// 候选算法，逗号分隔：sha1、md5、sha256、sha384、sha512、crc32、hmac-sha1、hmac-md5、hmac-sha256。
        #[arg(long, default_value = "sha1,md5,sha256,hmac-sha1,hmac-md5,hmac-sha256")]
        algos: String,
        /// 输入组合，逗号分隔：plain=input；prefix_key=key||input；suffix_key=input||key；key_prefix_input=key||00||input；input_pipe_key=input|key；key_dot_input=key.input。
        #[arg(long, default_value = "plain,prefix_key,suffix_key,key_prefix_input")]
        combos: String,
        /// 比较摘要前 N 字节；最少 4 字节，且不超过目标摘要长度。
        #[arg(long, default_value_t = 8)]
        prefix_bytes: usize,
        /// 同时在观测内存中查找候选摘要前缀。
        #[arg(long, default_value_t = false)]
        search_in_mem: bool,
    },
    /// 从调用指令及 JNI 表访问识别 JNI 调用；结果是观测候选。
    JniCalls {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 仅保留该函数内的 JNI 调用；使用 functions 返回项的 name。
        #[arg(long)]
        in_fn: Option<String>,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// 读取 jni_hooks.jsonl 的参数和返回值；需采集时启用对应 JNI hook。
    JniEvents {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// JNI 事件 ID 精确匹配，如 NewStringUTF；省略返回所有事件。
        #[arg(long)]
        id: Option<String>,
        /// 记录范围起点（包含）；省略从 trace 开始。
        #[arg(long)]
        idx_lo: Option<usize>,
        /// 记录范围终点（不包含）；省略不限制。
        #[arg(long)]
        idx_hi: Option<usize>,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// 从明确提供的字符串或字节回溯内存写入者和寄存器来源。
    OutputBacktrace {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 明确观测到的 UTF-8 输出字符串，与 --bytes-hex 二选一。
        #[arg(
            long,
            required_unless_present = "bytes_hex",
            conflicts_with = "bytes_hex"
        )]
        value: Option<String>,
        /// 明确观测到的输出字节（十六进制），与 --value 二选一。
        #[arg(long = "bytes-hex", required_unless_present = "value")]
        bytes_hex: Option<String>,
        /// 输出观测位置（记录下标），用于候选距离排序；省略不设时间锚点。
        #[arg(long)]
        at_idx: Option<usize>,
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
        #[command(flatten)]
        vm: super::vm_args::VmArgs,
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
    /// 将明确提供的 Base64 文本分组，关联编码前字节与运行时写入者。
    #[command(name = "base64-map")]
    OutputMap {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 明确观测到的 Base64 文本；部分尾串用 --base64-tail-start 配置。
        #[arg(long, required = true)]
        value: Option<String>,
        /// 输出观测位置（记录下标），用于候选距离排序；省略不设时间锚点。
        #[arg(long)]
        at_idx: Option<usize>,
        /// Max memory locations to consider for the observed output bytes.
        #[arg(long, default_value_t = 8)]
        max_mem_hits: usize,
        /// Ranked memory hit to use after --hit-order sorting.
        #[arg(long, default_value_t = 0)]
        hit_rank: usize,
        /// Memory-hit ordering before applying --hit-rank.
        ///
        /// earliest/latest 按缓冲区首次写入记录排序；nearest 按 --at-idx 的距离排序。
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
        /// base64-map builds hidden lookup trees to find alphabet table lookups first.
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
        #[command(flatten)]
        vm: super::vm_args::VmArgs,
        /// 仅输出摘要，省略完整明细。
        #[arg(long)]
        summary: bool,
    },
    /// 按显式 VM 寄存器角色标注记录；不解码目标的私有字节码。
    VmSlice {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 起始记录下标，从 0 开始（包含）。
        #[arg(long)]
        start: usize,
        /// 结束记录下标（不包含），覆盖 --count。
        #[arg(long)]
        end: Option<usize>,
        /// 请求记录数。
        #[arg(long, default_value_t = 300)]
        count: usize,
        /// 逗号分隔的寄存器名。
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        /// Drop records that do not look VM-related.
        #[arg(long)]
        only_vm: bool,
        #[command(flatten)]
        vm: super::vm_args::VmArgs,
        /// Base VM IP for vm_off. Defaults to the first row's --vm-ip-reg.
        #[arg(long)]
        base_ip: Option<String>,
    },
    /// 按显式 VM IP 的变化聚合执行片段及状态槽效果。
    VmOps {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 起始记录下标，从 0 开始（包含）。
        #[arg(long)]
        start: usize,
        /// 结束记录下标（不包含），覆盖 --count。
        #[arg(long)]
        end: Option<usize>,
        /// 请求记录数。
        #[arg(long, default_value_t = 300)]
        count: usize,
        /// 逗号分隔的寄存器名。
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        #[command(flatten)]
        vm: super::vm_args::VmArgs,
        /// Base VM IP for vm_off. Defaults to the first row's --vm-ip-reg.
        #[arg(long)]
        base_ip: Option<String>,
        /// Max VM op groups to return.
        #[arg(long, default_value_t = 80)]
        max_ops: usize,
        /// Max records per analysis chunk; 0 requests the whole selected window.
        #[arg(long, default_value_t = 900)]
        chunk_size: usize,
        /// 仅输出摘要，省略完整明细。
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
    /// 沿内存写入和源寄存器回溯一个或多个字节，不要求 VM 配置。
    ByteLineage {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 运行时内存地址，默认十六进制；d16 表示十进制 16。
        #[arg(long)]
        addr: String,
        /// 仅查找此记录之前（不含）的内存写入。
        #[arg(long)]
        before_idx: usize,
        /// 从 --addr 起连续回溯的字节数。
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// 每个字节最多回溯的步骤数。
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
        /// 逗号分隔的寄存器名。
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        /// 仅输出摘要，省略完整明细。
        #[arg(long)]
        summary: bool,
        /// Emit a minimal path/frontier digest for AI agents.
        #[arg(long)]
        compact: bool,
    },
    /// 按显式 VM 配置回溯一步写入、读取或源寄存器关系。
    VmBackstep {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: usize,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
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
        /// 逗号分隔的寄存器名。
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        #[command(flatten)]
        vm: super::vm_args::VmArgs,
    },
    /// 按显式 VM 配置迭代回溯单条来源链。
    VmBackchain {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: usize,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
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
        /// 仅输出摘要，省略完整明细。
        #[arg(long)]
        summary: bool,
        /// 逗号分隔的寄存器名。
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        #[command(flatten)]
        vm: super::vm_args::VmArgs,
    },
    /// 按显式 VM 配置展开多分支来源树及未知边界。
    VmBacktree {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 记录下标，从 0 开始。
        #[arg(long)]
        idx: usize,
        /// 寄存器名，如 x0、w0、sp、fp、lr。
        #[arg(long)]
        reg: Option<String>,
        /// 最多展开的依赖层数。
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
        /// 仅输出摘要，省略完整明细。
        #[arg(long)]
        summary: bool,
        /// 逗号分隔的寄存器名。
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp,fp,lr"
        )]
        regs: String,
        #[command(flatten)]
        vm: super::vm_args::VmArgs,
    },
    /// 查询 JNI jobject 在已识别调用参数中的出现记录。
    #[command(name = "jni-object-history")]
    JobjHistory {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// JNI 对象句柄，默认十六进制。
        #[arg(long)]
        jobject: String,
        /// 起始记录下标，从 0 开始（包含）。
        #[arg(long, default_value_t = 0)]
        start: usize,
        /// 结束记录下标（不包含）；-1 表示 trace 末尾。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        end: isize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// 预览 NewStringUTF、GetStringUTFChars、ReleaseStringUTFChars 的已观测字节缓冲区。
    JniStrings {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, default_value_t = 200)]
        max: usize,
        /// 每个 JNI 字符串最多读取的字节数（硬上限 4096）。
        #[arg(long, default_value_t = 128)]
        max_len: usize,
    },
    /// 依据本地 trace.bin 修复 pending/call 元数据并规范目录名。
    Finalize {
        /// 待修复的 run 目录，须包含 calls/。
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
