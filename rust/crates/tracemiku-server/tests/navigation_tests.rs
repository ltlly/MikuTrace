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
        .join("call_001_tid100_5r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100100, 0x100104, 0x100008];
    let insts: [u32; 5] = [
        0xd503201f, // nop
        0x9400003f, // bl 0x100100
        0xd503201f, // nop
        0xd65f03c0, // ret
        0xd65f03c0, // ret
    ];
    let mut buf = vec![0u8; 272 * pcs.len()];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":5,"known_offsets":{"0x0":"root","0x100":"callee"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

async fn get(call_dir: PathBuf, uri: &str) -> (StatusCode, serde_json::Value) {
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
async fn block_for_pc_finds_containing_block() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/block-for-pc?pc=0x100100").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["pc"], "0x100100");
    assert_eq!(v["block"], "0x100100");
}

#[tokio::test]
async fn block_detail_returns_insns_and_exits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/block?pc=0x100000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["start"], "0x100000");
    assert_eq!(v["func"], "root");
    assert!(v["insns"].as_array().unwrap().len() >= 2);
    assert!(v["exits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["to"] == "0x100100"));
}

#[tokio::test]
async fn loops_endpoint_returns_ready_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/loops").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert!(v["loops"].is_array());
}

#[tokio::test]
async fn backtrace_replays_calls_before_idx() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/backtrace?idx=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["depth"], 1);
    assert_eq!(v["stack"][0]["call_site_idx"], 1);
    assert_eq!(v["stack"][0]["callee_pc"], "0x100100");
}
