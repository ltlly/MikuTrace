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

#[test]
fn replay_after_syscall_does_not_certify_stale_memory() {
    let (_tmp, cd) = synth_call_dir();
    let mut records = Vec::new();
    for (idx, inst) in [0xf9000020, 0xd4000001, 0xf9400020, 0xd503201f]
        .into_iter()
        .enumerate()
    {
        let mut rec = tracemiku_core::trace::Record::zero(0x100000 + idx as u64 * 4);
        rec.inst = inst;
        rec.regs[0] = 65;
        rec.regs[1] = 0x7000;
        records.push(rec);
    }
    let mut raw = Vec::new();
    for rec in records {
        raw.extend(rec.pc.to_le_bytes());
        for value in rec.regs {
            raw.extend(value.to_le_bytes());
        }
        raw.extend(rec.sp.to_le_bytes());
        raw.extend(rec.nzcv.to_le_bytes());
        raw.extend(rec.inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), raw).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
    let out = run_json(&[
        "trace-replay",
        cd.to_str().unwrap(),
        "--start",
        "2",
        "--count",
        "1",
    ]);
    assert_valid(
        serde_json::to_value(schemars::schema_for!(
            tracemiku_cli::output_types::ReplayReport
        ))
        .unwrap(),
        &out,
    );
    assert_eq!(out["status"], "stopped");
    assert_eq!(out["checked"], 0);
    assert_eq!(out["independent_memory_bytes"], 0);
    assert_eq!(out["stop"]["reason"], "unknown_memory");
    assert_eq!(out["stop"]["next_capture"]["addr"], 0x7000);
    assert_eq!(out["stop"]["next_capture"]["size"], 8);
    assert_eq!(
        out["stop"]["next_capture"]["action"],
        "capture_memory_before_instruction"
    );
}
