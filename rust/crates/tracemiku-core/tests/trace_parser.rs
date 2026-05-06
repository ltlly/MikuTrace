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
fn ignores_partial_trailing_record() {
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

    let trace = Trace::load(&fix.call_dir).expect("partial trailing record is ignored");
    assert_eq!(trace.len(), 3);
    assert_eq!(trace.raw().len(), 3 * REC_SIZE);
    assert_eq!(trace.record(2).pc, 0x100008);
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

#[test]
fn record_idx_returns_correct_pc() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();

    // Synth fixture writes pc = 0x100000 + 4*i.
    assert_eq!(t.record(0).pc, 0x100000);
    assert_eq!(t.record(1).pc, 0x100004);
    assert_eq!(t.record(4).pc, 0x100010);
    assert_eq!(t.record(0).inst, 0xd503201f); // NOP
    assert_eq!(t.record(0).sp, 0x7000);
    assert_eq!(t.record(0).regs[0], 0); // synth fixture writes zeros
}

#[test]
fn record_idx_out_of_range_panics() {
    let fix = common::synth_trace_dir(3);
    let t = Trace::load(&fix.call_dir).unwrap();

    let r = std::panic::catch_unwind(|| t.record(3));
    assert!(
        r.is_err(),
        "record(len()) must panic with index out of bounds"
    );
}

#[test]
fn pc_fast_path_matches_record_pc() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    for i in 0..t.len() {
        assert_eq!(
            t.pc(i),
            t.record(i).pc,
            "pc fast path must agree at idx {i}"
        );
    }
}

#[test]
fn inst_fast_path_matches_record_inst() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    for i in 0..t.len() {
        assert_eq!(t.inst(i), t.record(i).inst);
    }
}

#[test]
fn iter_visits_every_record_in_order() {
    let fix = common::synth_trace_dir(7);
    let t = Trace::load(&fix.call_dir).unwrap();

    let pcs: Vec<u64> = t.iter().map(|r| r.pc).collect();
    let expected: Vec<u64> = (0..7).map(|i| 0x100000 + 4 * i as u64).collect();
    assert_eq!(pcs, expected);
}

#[test]
fn iter_count_matches_len() {
    let fix = common::synth_trace_dir(13);
    let t = Trace::load(&fix.call_dir).unwrap();
    assert_eq!(t.iter().count(), t.len());
}

#[test]
fn iter_on_empty_trace_yields_nothing() {
    let fix = common::synth_trace_dir(0);
    let t = Trace::load(&fix.call_dir).unwrap();
    assert_eq!(t.iter().count(), 0);
}
