//! CLI arguments and transport only; replay semantics live in core.
use std::path::PathBuf;
#[derive(Debug, clap::Args)]
pub(super) struct ReplayArgs {
    pub trace_dir: PathBuf,
    #[arg(long, default_value_t = 0)]
    pub start: usize,
    /// Requested transitions (hard cap 10000); output explains the first stop.
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
