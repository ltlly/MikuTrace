//! Real-trace integration: load the 4.2GB debug_minimal trace and assert
//! basic invariants. #[ignore] by default — opt in with `cargo test --ignored`.
//!
//! Path is resolved relative to the workspace root (assumed to be 3 levels
//! up from CARGO_MANIFEST_DIR). Skips with a print if the fixture is absent.

use std::path::PathBuf;
use std::time::Instant;

use tracemiku_core::prelude::*;

const REAL_TRACE_REL: &str =
    "../../../traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms";
const EXPECTED_RECORDS: usize = 15_426_904;

fn real_trace_path() -> Option<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let p = PathBuf::from(manifest).join(REAL_TRACE_REL);
    let p = p.canonicalize().ok()?;
    if !p.join("trace.bin").exists() {
        return None;
    }
    Some(p)
}

#[test]
#[ignore]
fn loads_real_4_2gb_trace_and_counts_records() {
    let Some(p) = real_trace_path() else {
        eprintln!("skip: real trace fixture not found at {REAL_TRACE_REL} — run `git lfs pull` or generate it");
        return;
    };

    let t0 = Instant::now();
    let t = Trace::load(&p).expect("load 4.2GB trace");
    let load_ms = t0.elapsed().as_millis();
    eprintln!("Trace::load took {load_ms}ms (mmap is constant-time; should be <50ms)");

    assert_eq!(
        t.len(),
        EXPECTED_RECORDS,
        "record count must match the dir name (15426904r)"
    );

    // Spot-check first + last + middle PC values: just non-zero / sensible.
    let first = t.record(0);
    let last = t.record(t.len() - 1);
    let mid = t.record(t.len() / 2);
    assert!(first.pc != 0, "first PC must be non-zero");
    assert!(last.pc != 0, "last PC must be non-zero");
    assert!(mid.pc != 0, "middle PC must be non-zero");

    // Walk the iterator, count again — verifies size_hint + iteration.
    let walk_t = Instant::now();
    let counted = t.iter().count();
    let walk_ms = walk_t.elapsed().as_millis();
    eprintln!("Trace::iter().count() took {walk_ms}ms (expected: <500ms for 15.4M records)");
    assert_eq!(counted, EXPECTED_RECORDS);

    // Time pc-only scan — should be much faster than full record scan.
    let pc_t = Instant::now();
    let pc_sum: u64 = (0..t.len())
        .map(|i| t.pc(i))
        .fold(0u64, |a, b| a.wrapping_add(b));
    let pc_ms = pc_t.elapsed().as_millis();
    eprintln!("pc-only scan: {pc_ms}ms (sum={pc_sum:#x})");
    assert!(
        pc_ms < walk_ms + 500,
        "pc fast path should be at least competitive with full iter"
    );
}
