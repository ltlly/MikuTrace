//! Contract tests for Tenet-style memory export.
//!
//! Tenet export answers "where did each byte come from" without fabricating
//! missing memory: every byte of the requested range is either tied to a
//! concrete writer (store/external), marked as initial-snapshot value, or
//! explicitly `unknown`. The shape is a committed AI-facing contract.

use std::fs;
use std::path::PathBuf;

use tracemiku_core::memshadow::MemShadow;
use tracemiku_core::trace::record::REC_SIZE;
use tracemiku_core::trace::trace::Trace;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_2r_1ms");
    fs::create_dir_all(&cd).unwrap();
    // idx 0: str x0, [sp] (write 8 bytes at sp=0x7000); idx 1: nop.
    let insts: [u32; 2] = [0xf90003e0, 0xd503201f];
    let mut buf = vec![0u8; REC_SIZE * 2];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * REC_SIZE;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + i as u64 * 4).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&0x4142434445464748u64.to_le_bytes()); // x0
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes()); // sp
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":2}"#).unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":0x10000}}"#,
    )
    .unwrap();
    (dir, cd)
}

#[test]
fn tenet_export_marks_written_bytes_and_unknown_gaps() {
    let (_dir, cd) = synth_call_dir();
    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::build_from_trace(&trace);
    // Dump 16 bytes at 0x7000: first 8 written by store, next 8 unknown.
    let dump = mem.tenet_export(0x7000, 16).unwrap();
    assert_eq!(dump.addr, 0x7000);
    assert_eq!(dump.bytes.len(), 16, "one entry per byte, no gaps");
    for b in &dump.bytes[0..8] {
        assert_ne!(
            b.source.kind, "unknown",
            "byte at +{:x} must have a writer: {b:?}",
            b.offset
        );
    }
    for b in &dump.bytes[8..16] {
        assert_eq!(b.source.kind, "unknown");
    }
}

#[test]
fn tenet_export_writer_kind_is_store() {
    let (_dir, cd) = synth_call_dir();
    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::build_from_trace(&trace);
    let dump = mem.tenet_export(0x7000, 8).unwrap();
    let first = &dump.bytes[0];
    let src = &first.source;
    assert_eq!(src.kind, "store");
    assert_eq!(src.idx, Some(0), "writer is the store at record 0");
    assert_eq!(
        first.value, 0x48,
        "little-endian: x0=0x4142434445464748 writes 0x48 first"
    );
}

#[test]
fn tenet_export_out_of_range_is_err() {
    let (_dir, cd) = synth_call_dir();
    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::build_from_trace(&trace);
    // 1MiB+1 dump must be rejected by the size cap.
    assert!(mem.tenet_export(0x7000, (1 << 20) + 1).is_err());
}
