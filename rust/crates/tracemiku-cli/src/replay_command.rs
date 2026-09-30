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
pub(super) async fn run(args: ReplayArgs) -> anyhow::Result<()> {
    super::route_get_json(
        args.trace_dir,
        format!(
            "/api/trace-replay?start={}&count={}",
            args.start, args.count
        ),
    )
    .await
}
