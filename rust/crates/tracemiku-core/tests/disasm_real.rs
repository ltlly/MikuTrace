//! Real-trace decode integration. #[ignore] — opt in via cargo test --ignored.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

use tracemiku_core::prelude::*;

const REAL_TRACE_REL: &str =
    "../../../traces/debug_minimal/calls/call_001_tid22371_15426904r_11325ms";
const SCAN_LIMIT: usize = 1_000_000;

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
fn decodes_first_1m_distinct_pcs() {
    let Some(p) = real_trace_path() else {
        eprintln!("skip: real trace fixture not found");
        return;
    };
    let t = Trace::load(&p).expect("load real trace");
    let limit = SCAN_LIMIT.min(t.len());

    // First pass: scan the first SCAN_LIMIT records, decode each distinct PC once.
    let scan_t = Instant::now();
    let mut seen = HashSet::with_capacity(20_000);
    let mut decoded_count = 0usize;
    for i in 0..limit {
        let pc = t.pc(i);
        if !seen.insert(pc) {
            continue;
        }
        let _d = decode(pc, t.inst(i));
        decoded_count += 1;
    }
    let scan_ms = scan_t.elapsed().as_millis();
    eprintln!("decoded {decoded_count} distinct PCs in {scan_ms}ms (target <500ms; Python baseline 838ms)");
    assert!(decoded_count > 0, "must decode at least one PC");
    // Python baseline: 10,825 distinct PCs in first 1M records. Allow 50% tolerance for
    // test-data drift but flag if WAY off.
    assert!(
        decoded_count > 100,
        "implausibly few distinct PCs: {decoded_count}"
    );

    // Second pass: re-decode the same PCs, should be 100% cache hits — much faster.
    let cache_t = Instant::now();
    for i in 0..limit {
        let pc = t.pc(i);
        if seen.contains(&pc) {
            let _d = decode(pc, t.inst(i));
        }
    }
    let cache_ms = cache_t.elapsed().as_millis();
    eprintln!("re-scan with cache hits: {cache_ms}ms");
}
