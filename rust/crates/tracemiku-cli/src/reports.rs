use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_output_backtrace(
    trace_dir: PathBuf,
    opts: OutputBacktraceOpts,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::output_backtrace(trace_dir, opts)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_vm_backtree(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    depth: usize,
    max_nodes: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    frontier_with_next: bool,
    summary: bool,
    regs: String,
    profile: VmProfile,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::vm_backtree(
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
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_vm_backchain(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    steps: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    follow_frontier: bool,
    byte_lane: Option<usize>,
    regs: String,
    summary: bool,
    profile: VmProfile,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::vm_backchain(
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
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_byte_lineage(
    trace_dir: PathBuf,
    addr: String,
    before_idx: usize,
    count: usize,
    depth: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    summary: bool,
    compact: bool,
    profile: VmProfile,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::byte_lineage(
        trace_dir, addr, before_idx, count, depth, context, lookback, max_writes, regs, summary,
        compact, profile,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_vm_backstep(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    profile: VmProfile,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::vm_backstep(
        trace_dir, idx, reg, context, lookback, max_writes, regs, profile,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_vm_ops(
    trace_dir: PathBuf,
    start: usize,
    end: Option<usize>,
    count: usize,
    regs: String,
    base_ip: Option<String>,
    max_ops: usize,
    chunk_size: usize,
    summary: bool,
    effects_only: bool,
    compact: bool,
    replay_plan: bool,
    profile: VmProfile,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::vm_ops(
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
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_vm_slice(
    trace_dir: PathBuf,
    start: usize,
    end: Option<usize>,
    count: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: VmProfile,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::vm_slice(
        trace_dir, start, end, count, regs, only_vm, base_ip, profile,
    )?)
}
