//! 内存比较的时间边界、无效参数和未知证据契约。

use super::analysis_support;
use std::fs;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_2r_1ms");
    fs::create_dir_all(&cd).unwrap();
    // idx 0: str x0, [sp] writes 8 bytes at sp=0x7000; idx 1: nop.
    let insts: [u32; 2] = [0xf90003e0, 0xd503201f];
    let mut buf = vec![0u8; 272 * 2];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + i as u64 * 4).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&0x4142434445464748u64.to_le_bytes()); // x0
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes()); // sp
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":2}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn get_json(call_dir: PathBuf, uri: &str) -> (Option<&'static str>, serde_json::Value) {
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, uri, None);
    let status = resp.error_code();
    let body = resp.bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[test]
fn mem_diff_detects_byte_change_across_idx() {
    let (_tmp, cd) = synth_call_dir();
    // idx 1: the store at idx 0 wrote 0x4142..; before_t = idx-1 = 0 includes
    // the idx-0 store, after_t = 1 is after it — both see 0x48 (first byte
    // of x0 in little-endian), so this range is unchanged across idx 1.
    let (status, v) = get_json(cd, "mem-dump?at=1&compare_at=0&addr=0x7000&count=8");
    assert_eq!(status, None);
    assert_eq!(v["count"], 8);
    let bytes = v["bytes"].as_array().unwrap();
    assert_eq!(bytes.len(), 8);
    let first = &bytes[0];
    assert_eq!(
        first["comparison"]["byte"], 0x48,
        "idx-0 store visible before idx 1"
    );
    assert_eq!(first["byte"], 0x48, "x0=0x4142.. writes 0x48 first");
    assert!(bytes
        .iter()
        .all(|b| b["comparison"]["change"] == "unchanged"));
}

#[test]
fn memory_comparison_rejects_zero_count() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _) = get_json(cd, "mem-dump?at=1&compare_at=0&addr=0x7000&count=0");
    assert_eq!(status, Some("invalid_argument"));
}

#[test]
fn memory_comparison_rejects_invalid_address() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _) = get_json(cd, "mem-dump?at=1&compare_at=0&addr=zz&count=4");
    assert_eq!(status, Some("invalid_argument"));
}

#[test]
fn memory_comparison_marks_unobserved_range_unknown() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "mem-dump?at=1&compare_at=0&addr=0x9000&count=8");
    assert_eq!(status, None);
    assert!(v["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|b| b["byte"].is_null() && b["comparison"]["change"] == "unknown"));
}
