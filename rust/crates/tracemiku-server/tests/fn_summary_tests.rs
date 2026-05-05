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
        .join("call_001_tid100_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100008];
    let insts = [0xd503201fu32, 0xd503201f, 0xd65f03c0]; // nop; nop; ret
    let mut buf = vec![0u8; 272 * pcs.len()];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":3,"known_offsets":{"0x0":"f_root"}}"#,
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
async fn fn_summary_reports_ready_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/fn-summary?fn=f_root&top_blocks=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["fn"], "f_root");
    assert_eq!(v["pc"], "0x100000");
    assert_eq!(v["rel"], "0x0");
    assert_eq!(v["block_count"], 1);
    assert_eq!(v["total_executions"], 1);
    assert_eq!(v["entry_idxs"], serde_json::json!([0]));
    assert_eq!(v["entry_idxs_total"], 1);
    assert_eq!(v["hot_blocks"][0]["pc"], "0x100000");
    assert_eq!(v["hot_blocks"][0]["insns"], 3);
}

#[tokio::test]
async fn fn_summary_reports_not_found() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/fn-summary?fn=nope").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "not-found");
    assert_eq!(v["fn"], "nope");
}
