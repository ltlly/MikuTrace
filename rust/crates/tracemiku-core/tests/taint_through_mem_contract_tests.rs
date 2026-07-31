//! Contract tests for taint `through_mem` two-mode semantics.
//!
//! Two writes to the same address: both modes chase the *latest* writer
//! before the query index — they differ only in granularity.
//! - `through_mem=false` (exact-addr): one candidate per address.
//! - `through_mem=true` (byte-overlap): one candidate per byte, deduped.
//!
//! Neither mode returns historical writers shadowed by a later write;
//! `backward_taint` provenance answers "which writes define the current
//! bytes", not "every write that ever touched this address".
//!
//! These tests lock that contract so a refactor cannot silently collapse
//! the modes.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use tracemiku_core::index::Index;
use tracemiku_core::memshadow::MemShadow;
use tracemiku_core::taint::{backward_taint, forward_taint};
use tracemiku_core::trace::record::REC_SIZE;
use tracemiku_core::trace::trace::Trace;

/// 5-record trace: `str x0,[x8]` at idx 0 writes mem[0x2000]=x0; `str x1,[x8]`
/// at idx 2 overwrites the same address; `ldr x0,[x8]` at idx 4 reads it.
fn synth_two_writes() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_5r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let insts: [u32; 5] = [
        0xf9000100, // str x0, [x8]
        0xd503201f, // nop
        0xf9000101, // str x1, [x8]
        0xd503201f, // nop
        0xf9400100, // ldr x0, [x8]
    ];
    let mut buf = vec![0u8; REC_SIZE * 5];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * REC_SIZE;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + i as u64 * 4).to_le_bytes());
        // x8 = 0x2000 (base addr).
        buf[off + 8 * 8..off + 8 * 9].copy_from_slice(&0x2000u64.to_le_bytes());
        buf[off..off + 8].copy_from_slice(&0x1111u64.to_le_bytes());
        buf[off + 8..off + 8 * 2].copy_from_slice(&0x2222u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":0x10000}}"#,
    )
    .unwrap();
    (dir, cd)
}

fn load() -> (Trace, Index, MemShadow, tempfile::TempDir) {
    let (dir, cd) = synth_two_writes();
    let t = Trace::load(&cd).unwrap();
    let idx = Index::build(&t);
    let mem = MemShadow::build_from_trace(&t);
    (t, idx, mem, dir)
}

#[test]
fn exact_mode_reports_only_latest_writer() {
    let (t, idx, _mem, _dir) = load();
    let exclude = HashSet::new();
    // Query at idx 4 (ldr) — exact mode, no mem shadow: only latest writer idx 2.
    let (hits, _stopped) = backward_taint(&t, &idx, 4, "x0", 100, &exclude, false, None, false);
    let writer_idxs: Vec<usize> = hits
        .iter()
        .filter(|h| h.why == "mem")
        .map(|h| h.idx)
        .collect();
    eprintln!(
        "DEBUG bwd exact hits: {:?}",
        hits.iter().map(|h| (h.idx, &h.why)).collect::<Vec<_>>()
    );
    assert_eq!(
        writer_idxs,
        vec![2],
        "exact mode must report only the latest writer: {writer_idxs:?}"
    );
}

#[test]
fn byte_overlap_mode_reports_all_writers() {
    let (t, idx, mem, _dir) = load();
    let exclude = HashSet::new();
    let (hits, _stopped) =
        backward_taint(&t, &idx, 4, "x0", 100, &exclude, true, Some(&mem), false);
    let writer_idxs: Vec<usize> = hits
        .iter()
        .filter(|h| h.why == "mem")
        .map(|h| h.idx)
        .collect();
    assert_eq!(
        writer_idxs,
        vec![2],
        "byte-overlap mode reports latest writer per byte, deduped: {writer_idxs:?}"
    );
}

#[test]
fn forward_exact_mode_kills_mem_on_overwrite() {
    let (t, idx, _mem, _dir) = load();
    let exclude = HashSet::new();
    // Forward from idx 0 (str x0): exact mode — idx 2 overwrite kills mem taint,
    // so idx 4 ldr is NOT tainted through memory.
    let (hits, _stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
    let mem_hits: Vec<usize> = hits
        .iter()
        .filter(|h| h.why == "mem")
        .map(|h| h.idx)
        .collect();
    assert!(
        !mem_hits.contains(&4),
        "exact mode: overwrite at idx 2 must kill mem taint; got {mem_hits:?}"
    );
}

#[test]
fn forward_byte_overlap_also_kills_mem_on_clean_overwrite() {
    // Even with byte-overlap granularity, a clean store (idx 2, x1) that
    // overwrites a tainted address clears the taint — same kill semantics
    // as exact mode, per-byte.
    let (t, idx, mem, _dir) = load();
    let exclude = HashSet::new();
    let (hits, _stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, true, Some(&mem), false);
    let mem_hits: Vec<usize> = hits
        .iter()
        .filter(|h| h.why == "mem")
        .map(|h| h.idx)
        .collect();
    assert!(
        !mem_hits.contains(&4),
        "byte-overlap: clean overwrite at idx 2 kills mem taint; got {mem_hits:?}"
    );
}
