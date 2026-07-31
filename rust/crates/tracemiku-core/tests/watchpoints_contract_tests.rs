//! Boundary contract tests for tracemiku-core::watchpoints.
//!
//! Public API: watchpoint_scan with RegChange / RegEquals / MemTouch specs.
//! Covers edge cases: limit clamping, cursor filtering, unknown registers,
//! empty traces, dedup of overlapping mem touches.

use tracemiku_core::index::Index;
use tracemiku_core::prelude::Trace;
use tracemiku_core::watchpoints::{watchpoint_scan, WatchpointSpec};

fn synth_trace() -> Trace {
    let mut buf = vec![0u8; 272 * 4];
    // x0 changes 1->2->3->3; x1 constant 7.
    for i in 0..4 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&(1u64 + i as u64).min(3).to_le_bytes()); // x0
        buf[off + 16..off + 24].copy_from_slice(&7u64.to_le_bytes()); // x1
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("calls").join("call_001_tid1_4r_1ms");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("trace.bin"), &buf).unwrap();
    std::fs::write(dir.join("meta.json"), r#"{"records":4}"#).unwrap();
    std::fs::write(
        tmp.path().join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    Trace::load(&dir).expect("load trace")
}

#[test]
fn reg_change_reports_each_transition() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::RegChange { reg: "x0".into() },
        0,
        100,
    );
    assert_eq!(scan.status, "ready");
    // x0: 1,2,3,3 -> transitions at idx 1 and idx 2.
    let idxs: Vec<usize> = scan.hits.iter().map(|h| h.idx).collect();
    assert_eq!(idxs, vec![1, 2]);
    assert_eq!(scan.total_matches, 2);
    assert_eq!(scan.returned, 2);
    assert!(!scan.truncated);
}

#[test]
fn reg_change_respects_cursor() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    // cursor=2 skips the idx1 transition; only idx2 remains.
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::RegChange { reg: "x0".into() },
        2,
        100,
    );
    let idxs: Vec<usize> = scan.hits.iter().map(|h| h.idx).collect();
    assert_eq!(idxs, vec![2]);
    assert_eq!(scan.total_matches, 1);
}

#[test]
fn reg_change_limit_truncates() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::RegChange { reg: "x0".into() },
        0,
        1,
    );
    assert_eq!(scan.returned, 1);
    assert_eq!(scan.total_matches, 2);
    assert!(scan.truncated);
}

#[test]
fn reg_change_unknown_reg_has_no_hits() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::RegChange { reg: "zz".into() },
        0,
        100,
    );
    assert_eq!(scan.total_matches, 0);
    assert!(scan.hits.is_empty());
    assert!(!scan.truncated);
}

#[test]
fn reg_equals_finds_matching_idxs() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    // x0 == 3 at idx 2 and idx 3.
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::RegEquals {
            reg: "x0".into(),
            value: 3,
        },
        0,
        100,
    );
    let idxs: Vec<usize> = scan.hits.iter().map(|h| h.idx).collect();
    assert_eq!(idxs, vec![2, 3]);
    assert_eq!(scan.total_matches, 2);
}

#[test]
fn reg_equals_cursor_filters_before_idx() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::RegEquals {
            reg: "x0".into(),
            value: 3,
        },
        3,
        100,
    );
    let idxs: Vec<usize> = scan.hits.iter().map(|h| h.idx).collect();
    assert_eq!(idxs, vec![3]);
}

#[test]
fn mem_touch_uses_cursor_and_dedups() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    // No stores/loads in this trace, so mem_touch finds nothing.
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::MemTouch {
            addr: 0x2000,
            size: 4,
        },
        0,
        100,
    );
    assert_eq!(scan.total_matches, 0);
    assert!(scan.hits.is_empty());
}

#[test]
fn mem_touch_size_zero_clamps_to_one() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    // size=0 must not panic; clamps to 1 byte.
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::MemTouch {
            addr: 0x2000,
            size: 0,
        },
        0,
        100,
    );
    assert_eq!(scan.status, "ready");
    assert_eq!(scan.total_matches, 0);
}

#[test]
fn limit_zero_clamps_to_one() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::RegEquals {
            reg: "x0".into(),
            value: 3,
        },
        0,
        0,
    );
    assert_eq!(scan.returned, 1, "limit 0 clamps to 1");
    assert_eq!(scan.total_matches, 2);
    assert!(scan.truncated);
}

#[test]
fn cursor_past_end_returns_empty() {
    let trace = synth_trace();
    let index = Index::build(&trace);
    let scan = watchpoint_scan(
        &trace,
        &index,
        &WatchpointSpec::RegChange { reg: "x0".into() },
        99,
        100,
    );
    assert_eq!(scan.total_matches, 0);
    assert!(scan.hits.is_empty());
}
