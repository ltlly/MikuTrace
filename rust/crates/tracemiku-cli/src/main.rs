use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "tracemiku-cli",
    about = "traceMiku v2 CLI (subcommands populated incrementally per milestone)",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Print trace metadata as JSON. Mirrors `python -m viewer stats`.
    Stats {
        /// Per-call trace directory.
        trace_dir: std::path::PathBuf,
        /// Show ALL modules (overrides --top-modules).
        #[arg(long)]
        all_modules: bool,
        /// Limit modules list to top-N by size. Default 10.
        #[arg(long, default_value_t = 10)]
        top_modules: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Stats {
            trace_dir,
            all_modules,
            top_modules,
        }) => {
            let meta = tracemiku_core::prelude::TraceMeta::load(&trace_dir)?;
            let trace = tracemiku_core::prelude::Trace::load(&trace_dir)?;

            let modules_sorted: Vec<&tracemiku_core::prelude::ModuleInfo> = {
                let mut m: Vec<_> = meta.modules.iter().collect();
                m.sort_by_key(|x| std::cmp::Reverse(x.size));
                m
            };

            let target_name = meta.module.as_ref().map(|m| m.name.as_str());
            let modules_total = modules_sorted.len();

            let modules_out: Vec<&tracemiku_core::prelude::ModuleInfo> = if all_modules {
                modules_sorted.clone()
            } else {
                let n = top_modules.max(1);
                let mut kept: Vec<_> = if let Some(tn) = target_name {
                    modules_sorted
                        .iter()
                        .copied()
                        .filter(|m| m.name == tn)
                        .take(1)
                        .collect()
                } else {
                    Vec::new()
                };
                let already = kept
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<std::collections::HashSet<_>>();
                let need = n.saturating_sub(kept.len());
                kept.extend(
                    modules_sorted
                        .iter()
                        .copied()
                        .filter(|m| !already.contains(m.name.as_str()))
                        .take(need),
                );
                kept
            };

            let modules_truncated = modules_out.len() < modules_total;

            let out = serde_json::json!({
                "path": trace_dir.display().to_string(),
                "records": trace.len(),
                "method": meta.method,
                "cmd": meta.cmd,
                "fn_addr": meta.fn_addr,
                "module": meta.module,
                "modules": modules_out,
                "modules_total": modules_total,
                "modules_truncated": modules_truncated,
            });
            println!("{}", serde_json::to_string_pretty(&out)?);
            Ok(())
        }
        None => {
            eprintln!("(M2-α: only `stats` subcommand available; M3 fills the rest)");
            Ok(())
        }
    }
}
