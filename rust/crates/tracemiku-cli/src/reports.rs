use super::*;

pub(super) fn parse_vm_profile(
    ip_reg: Option<String>,
    state_reg: Option<String>,
    dispatch_reg: Option<String>,
    infra_regs: Option<String>,
) -> anyhow::Result<VmProfile> {
    let ip_reg = ip_reg.context(
        "--vm-ip-reg is required (no target-specific default; pass the register \
             holding the VM instruction pointer)",
    )?;
    let state_reg = state_reg.context(
        "--vm-state-reg is required (no target-specific default; pass the register \
             holding the VM state/virtual-register base)",
    )?;
    let dispatch_reg = dispatch_reg.context(
        "--vm-dispatch-reg is required (no target-specific default; pass the register \
             holding the dispatch table or lookup base)",
    )?;
    Ok(VmProfile::new(
        ip_reg,
        state_reg,
        dispatch_reg,
        infra_regs.unwrap_or_default(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_output_map(trace_dir: PathBuf, opts: OutputMapOpts) -> anyhow::Result<()> {
    print_pretty(&core_reports::output_map(trace_dir, opts)?)
}

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
) -> anyhow::Result<()> {
    print_pretty(&core_reports::byte_lineage(
        trace_dir, addr, before_idx, count, depth, context, lookback, max_writes, regs, summary,
        compact,
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

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_scan_jni_output_strings(
    path: PathBuf,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
    decode_url: bool,
    decode_base64: bool,
    decode_base64_full: bool,
    diff_base64: bool,
    base64_tail_start: Option<usize>,
    base64_tail_align_prefix: String,
    base64_tail_drop: usize,
    prior_inputs: usize,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::scan_jni_output_strings(
        path,
        key,
        contains,
        limit,
        decode_url,
        decode_base64,
        decode_base64_full,
        diff_base64,
        base64_tail_start,
        base64_tail_align_prefix,
        base64_tail_drop,
        prior_inputs,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_jni_output_strings(
    trace_dir: PathBuf,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::jni_output_strings(
        trace_dir, key, contains, limit,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_hash_finalize_detect(
    trace_dir: PathBuf,
    window: usize,
    min_size: u64,
    limit: usize,
    map_bytes: bool,
    map_candidates: usize,
    nonzero_only: bool,
    target_bytes: Option<String>,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::hash_finalize_detect(
        trace_dir,
        window,
        min_size,
        limit,
        map_bytes,
        map_candidates,
        nonzero_only,
        target_bytes,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_byte_writer_map(
    trace_dir: PathBuf,
    addr: String,
    size: u64,
    idx_lo: usize,
    idx_hi: isize,
    max: usize,
    vm_chain_steps: usize,
    vm_chain_runs: usize,
    vm_chain_lookback: usize,
    vm_chain_follow_frontier: bool,
    summary: bool,
    vm_profile: VmProfile,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::byte_writer_map(
        trace_dir,
        addr,
        size,
        idx_lo,
        idx_hi,
        max,
        vm_chain_steps,
        vm_chain_runs,
        vm_chain_lookback,
        vm_chain_follow_frontier,
        summary,
        vm_profile,
    )?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_mem_tenet(trace_dir: PathBuf, addr: String, length: usize) -> anyhow::Result<()> {
    print_pretty(&core_reports::mem_tenet(trace_dir, addr, length)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_stats(
    trace_dir: PathBuf,
    all_modules: bool,
    top_modules: usize,
) -> anyhow::Result<()> {
    print_pretty(&core_reports::stats(trace_dir, all_modules, top_modules)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_resolve_elf_symbol(elf_file: PathBuf, offset: String) -> anyhow::Result<()> {
    print_pretty(&core_reports::resolve_elf_symbol(elf_file, offset)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_resolve_trace_addr(trace_dir: PathBuf, addr: String) -> anyhow::Result<()> {
    print_pretty(&core_reports::resolve_trace_addr(trace_dir, addr)?)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_resolve_map_addr(maps_file: PathBuf, addr: String) -> anyhow::Result<()> {
    print_pretty(&core_reports::resolve_map_addr(maps_file, addr)?)
}
