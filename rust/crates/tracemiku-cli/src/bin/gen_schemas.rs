//! Generate JSON Schema documents for the typed CLI output models.
//!
//! Writes one `.schema.json` per model into `docs/schema/` (repo root). The
//! schemas are a committed AI-facing contract: consumers can validate CLI
//! stdout against them. Run via `cargo run -p tracemiku-cli --bin gen-schemas`.

use std::fs;
use std::path::PathBuf;

use schemars::schema_for;

use tracemiku_cli::output_lineage::{LineageBatchReport, LineageRow};
use tracemiku_cli::output_types::{BacktraceReport, OutputMapReport, StatsReport};
use tracemiku_cli::output_vm::{VmOpsReport, VmSliceReport};

fn emit(dir: &PathBuf, name: &str, schema: &serde_json::Value) -> std::io::Result<()> {
    let path = dir.join(format!("{name}.schema.json"));
    let pretty = serde_json::to_string_pretty(schema).expect("schema serializes");
    fs::write(path, pretty + "\n")
}

fn main() -> std::io::Result<()> {
    // Repo root is three levels above the crate dir (rust/crates/<crate>).
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("crate is three levels under repo root");
    let dir = repo_root.join("docs").join("schema");
    fs::create_dir_all(&dir)?;

    let models: Vec<(&str, serde_json::Value)> = vec![
        (
            "backtrace-report",
            serde_json::to_value(schema_for!(BacktraceReport)).unwrap(),
        ),
        (
            "output-map-report",
            serde_json::to_value(schema_for!(OutputMapReport)).unwrap(),
        ),
        (
            "stats-report",
            serde_json::to_value(schema_for!(StatsReport)).unwrap(),
        ),
        (
            "vm-slice-report",
            serde_json::to_value(schema_for!(VmSliceReport)).unwrap(),
        ),
        (
            "vm-ops-report",
            serde_json::to_value(schema_for!(VmOpsReport)).unwrap(),
        ),
        (
            "lineage-row",
            serde_json::to_value(schema_for!(LineageRow)).unwrap(),
        ),
        (
            "lineage-batch-report",
            serde_json::to_value(schema_for!(LineageBatchReport)).unwrap(),
        ),
    ];

    for (name, schema) in models {
        emit(&dir, name, &schema)?;
        println!("wrote {}/{}", dir.display(), name);
    }
    Ok(())
}
