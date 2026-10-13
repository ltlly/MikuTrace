//! CLI arguments and transport only; replay semantics live in core.
use std::path::PathBuf;
#[derive(Debug, clap::Args)]
pub(super) struct ReplayArgs {
    /// 单次 call 目录，须包含 trace.bin。
    pub trace_dir: PathBuf,
    /// 起始记录下标，从 0 开始。
    #[arg(long, default_value_t = 0)]
    pub start: usize,
    /// 请求验证的状态转移数，硬上限 10000；结果解释首次停止原因。
    #[arg(long, default_value_t = 100)]
    pub count: usize,
}
pub(super) fn run(args: ReplayArgs) -> anyhow::Result<()> {
    super::query_json(
        args.trace_dir,
        super::Query::TraceReplay(tracemiku_core::analysis::trace_replay::ReplayQuery {
            start: args.start,
            count: args.count,
        }),
    )
}
