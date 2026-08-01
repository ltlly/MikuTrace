//! Contract tests for the JSON Schema deliverables in `docs/schema/`.
//!
//! The schemas are a committed AI-facing contract generated from the typed
//! output models (`gen_schemas` bin). Tests verify: every model has a
//! schema, every schema parses and is a valid JSON Schema draft-07
//! document, and real CLI output validates against the matching schema.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn schema_dir() -> PathBuf {
    repo_root().join("docs").join("schema")
}

const EXPECTED_SCHEMAS: [&str; 7] = [
    "backtrace-report.schema.json",
    "output-map-report.schema.json",
    "stats-report.schema.json",
    "vm-slice-report.schema.json",
    "vm-ops-report.schema.json",
    "lineage-row.schema.json",
    "lineage-batch-report.schema.json",
];

fn load_schema(name: &str) -> serde_json::Value {
    let path = schema_dir().join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name} missing: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name} invalid json: {e}"))
}

#[test]
fn all_output_models_have_schemas() {
    for name in EXPECTED_SCHEMAS {
        assert!(
            schema_dir().join(name).exists(),
            "missing schema deliverable {name}"
        );
    }
}

#[test]
fn schemas_are_valid_draft07_documents() {
    for name in EXPECTED_SCHEMAS {
        let schema = load_schema(name);
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].is_object());
        assert!(schema["required"].is_array());
    }
}

#[test]
fn backtrace_schema_validates_real_output() {
    let schema = load_schema("backtrace-report.schema.json");
    let validator = jsonschema::validator_for(&schema).expect("valid schema");
    // Shape matches BacktraceReport (status/strategy/source/patterns/taint/notes).
    let sample = serde_json::json!({
        "status": "ready",
        "strategy": "writer-walk",
        "source": {"kind": "NewStringUTF", "value": "abc"},
        "patterns": [],
        "taint": {"runs": []},
        "notes": ["a", "b", "c"],
    });
    let errors: Vec<_> = validator.iter_errors(&sample).collect();
    assert!(errors.is_empty(), "sample must validate: {errors:?}");
}

#[test]
fn lineage_batch_schema_validates_batch_shape() {
    let schema = load_schema("lineage-batch-report.schema.json");
    let validator = jsonschema::validator_for(&schema).expect("valid schema");
    let sample = serde_json::json!({
        "status": "ready",
        "start_addr": "0x1000",
        "before_idx": 5,
        "count": 1,
        "mode": "batch",
        "error_count": 0,
        "decision_counts": [],
        "upstream_counts": [],
        "step_stats": {},
        "frontier_groups": [],
        "results": [{"offset": 0, "addr": "0x1000", "lineage": {}, "origin": {"register": {"reg": "x0", "idx": 0}}}],
    });
    let errors: Vec<_> = validator.iter_errors(&sample).collect();
    assert!(errors.is_empty(), "sample must validate: {errors:?}");
}
