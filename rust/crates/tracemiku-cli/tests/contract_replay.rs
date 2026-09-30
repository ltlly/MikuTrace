mod common;
use common::{assert_valid, run_json, synth_call_dir};
#[test]
fn trace_replay_matches_typed_schema_and_checks_only_contiguous_transitions() {
    let (_tmp, cd) = synth_call_dir();
    let out = run_json(&["trace-replay", cd.to_str().unwrap(), "--count", "9"]);
    assert_valid(
        serde_json::to_value(schemars::schema_for!(
            tracemiku_cli::output_types::ReplayReport
        ))
        .unwrap(),
        &out,
    );
    assert_eq!(out["mode"], "per_instruction_anchored_arm64");
    assert_eq!(out["status"], "stopped");
    assert_eq!(out["checked"], 1);
    assert_eq!(out["stop"]["idx"], 1);
    assert_eq!(out["stop"]["reason"], "trace_gap");
    assert_eq!(out["stop"]["next_capture"]["action"], "expand_trace_scope");
}
#[test]
fn trace_replay_bad_range_fails_instead_of_returning_success() {
    let (_tmp, cd) = synth_call_dir();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
        .args(["trace-replay", cd.to_str().unwrap(), "--count", "0"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
