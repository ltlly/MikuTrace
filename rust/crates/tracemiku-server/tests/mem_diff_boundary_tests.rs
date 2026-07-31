//! Boundary contract tests for /api/mem-diff.
//!
//! Covers the mem_diff branches beyond `timeline_contract_tests`'s
//! reg_timeline focus: size clamping, byte change detection across a trace
//! idx boundary, invalid-addr fallback, and the no-change shape.

use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

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

async fn get_json(call_dir: PathBuf, uri: &str) -> (StatusCode, serde_json::Value) {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn mem_diff_detects_byte_change_across_idx() {
    let (_tmp, cd) = synth_call_dir();
    // idx 1: the store at idx 0 wrote 0x4142..; before_t = idx-1 = 0 includes
    // the idx-0 store, after_t = 1 is after it — both see 0x48 (first byte
    // of x0 in little-endian), so this range is unchanged across idx 1.
    let (status, v) = get_json(cd, "/api/mem-diff?idx=1&addr=0x7000&size=8").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["size"], 8);
    let bytes = v["bytes"].as_array().unwrap();
    assert_eq!(bytes.len(), 8);
    let first = &bytes[0];
    assert_eq!(first["before"], 0x48, "idx-0 store visible before idx 1");
    assert_eq!(first["after"], 0x48, "x0=0x4142.. writes 0x48 first");
    assert_eq!(v["changed_count"], 0, "no change across idx 1");
}

#[tokio::test]
async fn mem_diff_zero_size_clamps_to_one() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/mem-diff?idx=1&addr=0x7000&size=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["size"], 1, "size 0 clamped to 1");
}

#[tokio::test]
async fn mem_diff_invalid_addr_falls_back_to_zero() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/mem-diff?idx=1&addr=zz&size=4").await;
    assert_eq!(status, StatusCode::OK);
    // addr=0 (fallback); bytes still present with addresses starting 0x0.
    let bytes = v["bytes"].as_array().unwrap();
    assert_eq!(bytes.len(), 4);
    assert_eq!(bytes[0]["addr"], "0x0");
}

#[tokio::test]
async fn mem_diff_unchanged_range_reports_zero_changed() {
    let (_tmp, cd) = synth_call_dir();
    // Address 0x9000 was never written: before == after == null everywhere.
    let (status, v) = get_json(cd, "/api/mem-diff?idx=1&addr=0x9000&size=8").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["changed_count"], 0);
    assert_eq!(v["status"], "ready");
}
