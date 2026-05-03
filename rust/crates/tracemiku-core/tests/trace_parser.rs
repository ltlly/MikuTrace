mod common;

use tracemiku_core::prelude::*;

#[test]
fn loads_synth_trace_with_9_records() {
    let fix = common::synth_trace_dir(9);
    let trace = Trace::load(&fix.call_dir).expect("load synth trace");
    assert_eq!(trace.len(), 9);
}

#[test]
fn loads_empty_trace_zero_records() {
    let fix = common::synth_trace_dir(0);
    let trace = Trace::load(&fix.call_dir).expect("load empty trace");
    assert_eq!(trace.len(), 0);
}

#[test]
fn rejects_truncated_trace_bin() {
    use std::fs::OpenOptions;
    use std::io::Write;
    let fix = common::synth_trace_dir(3);
    // Append 5 stray bytes — total file size is no longer a multiple of 272.
    let mut f = OpenOptions::new()
        .append(true)
        .open(fix.call_dir.join("trace.bin"))
        .unwrap();
    f.write_all(b"\x00\x01\x02\x03\x04").unwrap();
    drop(f);

    let err = Trace::load(&fix.call_dir).expect_err("truncated trace must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("not a multiple of 272") || msg.contains("REC_SIZE"),
        "error should explain layout violation, got: {msg}"
    );
}

#[test]
fn missing_trace_bin_yields_error() {
    let fix = common::synth_trace_dir(3);
    std::fs::remove_file(fix.call_dir.join("trace.bin")).unwrap();
    let err = Trace::load(&fix.call_dir).expect_err("missing trace.bin must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("trace.bin"),
        "error should mention trace.bin, got: {msg}"
    );
}
