//! VM 入口集中于显式试验分组，不参与稳定命令选择。
use super::*;
#[derive(Subcommand, Debug)]
pub(super) enum ExperimentalCmd {
    /// 按显式 VM 寄存器角色标注记录；不解码目标的私有字节码。
    #[command(name = "vm-slice")]
    Slice {
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
    #[command(name = "vm-ops")]
    Ops {
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
    /// 按显式 VM 配置回溯一步写入、读取或源寄存器关系。
    #[command(name = "vm-backstep")]
    Backstep {
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
    #[command(name = "vm-backchain")]
    Backchain {
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
    #[command(name = "vm-backtree")]
    Backtree {
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
}
pub(super) fn run(command: ExperimentalCmd) -> anyhow::Result<()> {
    match command {
        ExperimentalCmd::Slice {
            trace_dir,
            start,
            end,
            count,
            regs,
            only_vm,
            vm,
            base_ip,
        } => {
            let profile = vm.into_profile()?;
            cmd_vm_slice(
                trace_dir, start, end, count, regs, only_vm, base_ip, profile,
            )
        }
        ExperimentalCmd::Ops {
            trace_dir,
            start,
            end,
            count,
            regs,
            vm,
            base_ip,
            max_ops,
            chunk_size,
            summary,
            effects_only,
            compact,
            replay_plan,
        } => {
            let profile = vm.into_profile()?;
            cmd_vm_ops(
                trace_dir,
                start,
                end,
                count,
                regs,
                base_ip,
                max_ops,
                chunk_size,
                summary,
                effects_only,
                compact,
                replay_plan,
                profile,
            )
        }
        ExperimentalCmd::Backstep {
            trace_dir,
            idx,
            reg,
            context,
            lookback,
            max_writes,
            regs,
            vm,
        } => {
            let profile = vm.into_profile()?;
            cmd_vm_backstep(
                trace_dir, idx, reg, context, lookback, max_writes, regs, profile,
            )
        }
        ExperimentalCmd::Backchain {
            trace_dir,
            idx,
            reg,
            steps,
            context,
            lookback,
            max_writes,
            follow_frontier,
            byte_lane,
            summary,
            regs,
            vm,
        } => {
            let profile = vm.into_profile()?;
            cmd_vm_backchain(
                trace_dir,
                idx,
                reg,
                steps,
                context,
                lookback,
                max_writes,
                follow_frontier,
                byte_lane,
                regs,
                summary,
                profile,
            )
        }
        ExperimentalCmd::Backtree {
            trace_dir,
            idx,
            reg,
            depth,
            max_nodes,
            context,
            lookback,
            max_writes,
            frontier_with_next,
            summary,
            regs,
            vm,
        } => {
            let profile = vm.into_profile()?;
            cmd_vm_backtree(
                trace_dir,
                idx,
                reg,
                depth,
                max_nodes,
                context,
                lookback,
                max_writes,
                frontier_with_next,
                summary,
                regs,
                profile,
            )
        }
    }
}
