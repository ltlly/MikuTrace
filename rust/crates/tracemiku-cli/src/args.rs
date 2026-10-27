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
    /// 按区间或下标读取指令前状态；默认只读取所选记录。
    Records {
        /// 单次 call 目录。
        trace_dir: PathBuf,
        /// 起始记录（包含）。
        #[arg(long, default_value_t = 0, conflicts_with = "indices")]
        start: usize,
        /// 请求条数；最多 1000 条。
        #[arg(long, default_value_t = 100, conflicts_with = "indices")]
        count: usize,
        /// 结束记录（不包含）；若指定则覆盖 --count。
        #[arg(long, conflicts_with = "indices")]
        end: Option<usize>,
        /// 逗号分隔的寄存器名；按输入顺序返回所选记录。
        #[arg(long, default_value = "")]
        regs: String,
        /// 逗号分隔的记录下标；与区间查询使用同一输出结构。
        #[arg(long, value_delimiter = ',')]
        indices: Option<Vec<usize>>,
        /// 加载完整寄存器和符号；CFG、指针及内存历史需分别显式开启。
        #[arg(long)]
        detail: bool,
        /// 为 --detail 启用内存解引用和字符串指针注释；构建 MemShadow。
        #[arg(long, requires = "detail")]
        detail_pointers: bool,
        /// 为 --detail 启用所选内存操作数的逐字节历史；构建 MemShadow。
        #[arg(long, requires = "detail")]
        detail_memory: bool,
        /// 为 --detail 启用基本块和执行次数；构建 CFG。
        #[arg(long, requires = "detail")]
        detail_cfg: bool,
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
    /// 解析运行时地址或 (SO, 偏移)；也可直接查询保存的 maps。
    Resolve {
        /// 单次 call 目录；--maps 模式可省略。
        #[arg(required_unless_present = "maps", conflicts_with = "maps")]
        trace_dir: Option<PathBuf>,
        /// /proc/<pid>/maps 文件；无需 trace，只接受 --addr。
        #[arg(long, requires = "addr", conflicts_with_all = ["so", "off"])]
        maps: Option<PathBuf>,
        /// 运行时地址，默认十六进制，d16 表示十进制 16。
        #[arg(long, conflicts_with_all = ["so", "off"])]
        addr: Option<String>,
        /// 模块名称；与 --off 配合。
        #[arg(long, requires = "off")]
        so: Option<String>,
        /// 模块内偏移，默认十六进制。
        #[arg(long, requires = "so")]
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
    /// 汇总函数；指定函数时同时返回执行频次与热点块摘要。
    Functions {
        /// 单次 call 目录。
        trace_dir: PathBuf,
        /// 函数名，如 f_root；省略时只列出函数。
        #[arg(long = "fn")]
        fn_id: Option<String>,
    },
    /// 查询运行时 CFG；可定位块、执行位置和已观测分支覆盖。
    Cfg {
        /// 单次 call 目录。
        trace_dir: PathBuf,
        /// 按函数名筛选，如 f_root。
        #[arg(long = "fn")]
        fn_name: Option<String>,
        /// 定位包含该运行时 PC 的块，默认十六进制。
        #[arg(long)]
        pc: Option<String>,
        /// 返回所选块的执行记录下标；需要 --pc。
        #[arg(long, requires = "pc")]
        hits: bool,
        /// 返回所选 PC 或函数的已观测分支统计。
        #[arg(long)]
        coverage: bool,
        /// 块执行位置分页游标，记录下标（包含）。
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        /// 块执行位置返回上限，最多 1000。
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// 查询观测 CFG 中的循环强连通分量。
    Loops {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
    },
    /// 根据实际 call/ret 重建调用栈；可附加独立的 LR 线索。
    Backtrace {
        /// 单次 call 目录。
        trace_dir: PathBuf,
        /// 查询记录下标。
        #[arg(long)]
        idx: usize,
        /// 最多返回的栈帧和 LR 线索深度，最多 256。
        #[arg(long, default_value_t = 256)]
        limit: usize,
        /// 附加 LR 推测链；不混入实际调用栈。
        #[arg(long)]
        lr_clues: bool,
    },
    /// 汇总观测到的调用树及各节点执行次数。
    CallTree {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 调用树深度上限；省略使用 core 默认值。
        #[arg(long)]
        max_depth: Option<usize>,
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
    /// 读取某时刻的内存；可比较另一时刻或导出已知字节。
    MemDump {
        /// 单次 call 目录。
        trace_dir: PathBuf,
        /// 运行时起始地址，默认十六进制。
        #[arg(long, required_unless_present = "so", conflicts_with_all = ["so", "off"])]
        addr: Option<String>,
        /// 按模块名和偏移定位内存。
        #[arg(long, requires = "off")]
        so: Option<String>,
        /// 模块内偏移，默认十六进制。
        #[arg(long, requires = "so")]
        off: Option<String>,
        /// 字节数（十进制）；最多 4096。
        #[arg(long, default_value_t = 128)]
        count: usize,
        /// 记录时刻（包含该记录写入）；省略使用 trace 末尾。
        #[arg(long)]
        at: Option<u64>,
        /// 另一个记录时刻；未知字节的变化明确标为 unknown。
        #[arg(long)]
        compare_at: Option<u64>,
        /// 导出到文件；存在未知字节或截断时拒绝导出。
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// 查询指定时刻的逐字节来源和最后已观测写入者，保留未知证据。
    #[command(name = "mem-provenance")]
    MemTenet {
        /// 单次 call 目录。
        trace_dir: PathBuf,
        /// 运行时起始地址，默认十六进制。
        #[arg(long)]
        addr: String,
        /// 字节数（十进制）；最多 4096。
        #[arg(long, default_value_t = 32)]
        count: usize,
        /// 记录时刻（包含）；省略使用 trace 末尾。
        #[arg(long)]
        at: Option<usize>,
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
        /// 连续字节范围宽度（十进制）；大于 1 时附加逐字节历史。
        #[arg(long, default_value_t = 1)]
        size: u32,
    },
    /// 查询地址范围的读写事件、字节值及来源；按时间分页。
    #[command(name = "mem-accesses")]
    IdxsTouchingAddr {
        /// 单次 call 目录。
        trace_dir: PathBuf,
        /// 运行时起始地址，默认十六进制。
        #[arg(long)]
        addr: String,
        /// 范围字节数（十进制）；最多 4096。
        #[arg(long, default_value_t = 1)]
        size: usize,
        /// 起始记录（包含）。
        #[arg(long, default_value_t = 0)]
        start: usize,
        /// 结束记录（不包含）；省略到 trace 末尾。
        #[arg(long)]
        end: Option<usize>,
        /// 读写筛选；write 包含外部写入。
        #[arg(long, default_value = "all", value_parser = ["all", "read", "write"])]
        kind: String,
        /// 返回上限，最多 5000 条。
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// 匹配事件序号游标；使用结果的 next_cursor。
        #[arg(long, default_value_t = 0)]
        cursor: usize,
    },
    /// 在已观测内存中查找指定字节序列及首次观测位置。
    FindMemPattern {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
        /// 字节序列的十六进制文本，如 41424300；与 --ascii 二选一。
        #[arg(
            long = "bytes-hex",
            required_unless_present = "ascii",
            conflicts_with = "ascii"
        )]
        bytes_hex: Option<String>,
        /// UTF-8 字符串模式；与 --bytes-hex 二选一。
        #[arg(
            long,
            required_unless_present = "bytes_hex",
            conflicts_with = "bytes_hex"
        )]
        ascii: Option<String>,
        /// 首次观测下标下限；-1 不限制（搜索全时段及瞬态窗口）。
        #[arg(long, default_value_t = -1, allow_negative_numbers = true)]
        since: isize,
        /// 请求返回条数上限；实际数量及截断信息见结果。
        #[arg(long, visible_alias = "limit", default_value_t = 100)]
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
        /// 排除控制依赖，保留寄存器、地址和内存依赖。
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
        /// 排除控制依赖，保留寄存器、地址和内存依赖。
        #[arg(long)]
        data_only: bool,
        /// 允许跨越函数调用边界。
        #[arg(long)]
        cross_fn_call: bool,
        /// 连续 N 条无新增命中后停止；0 关闭该早停，省略使用 core 默认值。
        #[arg(long)]
        scan_limit: Option<usize>,
    },
    /// 查询前向或后向依赖集合；可附带有界依赖图。
    BfsSlice {
        /// 遍历方向：backward 查询来源，forward 查询使用者。
        #[arg(long, default_value = "backward", value_parser = ["backward", "forward"])]
        direction: String,
        /// 输出视图；graph 在集合结果上附加节点与边。
        #[arg(long, default_value = "slice", value_parser = ["slice", "graph"])]
        view: String,
        /// 最大依赖深度；省略时不限制深度。
        #[arg(long)]
        depth: Option<usize>,
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
        /// 排除控制依赖，保留寄存器、地址和内存依赖。
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
    /// 查询区间内寄存器的变化时间线。
    RegTimeline {
        /// 只保留等于该值的记录（十六进制）；省略时返回变化点。
        #[arg(long)]
        equals: Option<String>,
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
    /// 搜索密码常量和 ARM Crypto Extension 指令，输出候选证据。
    Crypto {
        /// 单次 call 目录，须包含 trace.bin。
        trace_dir: PathBuf,
    },
    /// 查询已识别 JNI 调用；可筛选对象参数并预览 MUTF-8 字符串。
    JniCalls {
        /// 单次 call 目录。
        trace_dir: PathBuf,
        /// 所属函数名。
        #[arg(long)]
        in_fn: Option<String>,
        /// JNI 函数名称，如 NewStringUTF。
        #[arg(long)]
        name: Option<String>,
        /// 筛选 x1..x4 中出现的对象值（十六进制）；仅表示数值匹配。
        #[arg(long)]
        jobject: Option<String>,
        /// 起始记录（包含）。
        #[arg(long, default_value_t = 0)]
        start: usize,
        /// 结束记录（不包含）。
        #[arg(long)]
        end: Option<usize>,
        /// 匹配调用序号游标。
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        /// 返回上限，最多 5000。
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// 只返回三种 UTF 字符串调用，并附加字节与停止原因。
        #[arg(long)]
        strings: bool,
        /// 每次字符串预览最多读取的字节数，最多 4096。
        #[arg(long, default_value_t = 256)]
        max_len: usize,
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
        /// 可选 VM 指令指针寄存器（如 x21）。
        #[arg(long)]
        vm_ip_reg: Option<String>,
        /// 可选 VM 状态区基址寄存器（如 x25），用于零深度开销折叠虚拟寄存器槽。
        #[arg(long)]
        vm_state_reg: Option<String>,
        /// 可选 VM 派发表基址寄存器（如 x23）。
        #[arg(long)]
        vm_dispatch_reg: Option<String>,
        /// 可选 VM 寄存器槽地址范围，格式 <BASE_HEX:SIZE_HEX>。
        #[arg(long)]
        vm_regfile: Option<String>,
    },
    /// 依据本地 trace.bin 修复 pending/call 元数据并规范目录名。
    Finalize {
        /// 待修复的 run 目录，须包含 calls/。
        path: PathBuf,
    },
    /// 有界读取 JNI 或进程分叉采集事件；无需加载 trace 和索引。
    Events {
        /// 包含 meta.json 或 jni_hooks.jsonl 的 call 目录。
        trace_dir: PathBuf,
        /// 事件来源。
        #[arg(long, value_parser = ["jni", "fork"])]
        source: String,
        /// JNI 事件名称，如 NewStringUTF。
        #[arg(long)]
        id: Option<String>,
        /// fork 事件的 attach_status。
        #[arg(long)]
        status: Option<String>,
        /// 按是否属于进程分叉筛选 fork 事件。
        #[arg(long)]
        is_fork_like: Option<bool>,
        /// 起始 trace 记录（包含）；没有 trace_idx 的事件不匹配。
        #[arg(long)]
        start: Option<usize>,
        /// 结束 trace 记录（不包含）。
        #[arg(long)]
        end: Option<usize>,
        /// 不透明来源游标；原样传入返回的 next_cursor。
        #[arg(long)]
        cursor: Option<String>,
        /// 返回上限，最多 5000；另有 8 MiB 扫描与响应预算。
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// 尚待不同解释器验证的 VM 分析；接口可能变化。
    Experimental {
        #[command(subcommand)]
        command: super::experimental::ExperimentalCmd,
    },
}
