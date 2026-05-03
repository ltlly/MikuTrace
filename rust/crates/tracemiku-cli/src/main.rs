use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "tracemiku-cli",
    about = "traceMiku v2 CLI (subcommands populated in M3)",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print the path to the trace dir + record count (placeholder).
    Stats {
        /// Per-call trace directory.
        trace_dir: std::path::PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Stats { trace_dir }) => {
            let meta = tracemiku_core::prelude::TraceMeta::load(&trace_dir)?;
            println!("{}", serde_json::to_string_pretty(&meta)?);
            Ok(())
        }
        None => {
            eprintln!("(M1: only `stats` subcommand available; M3 fills the rest)");
            Ok(())
        }
    }
}
