//! Black-box tests for GET /api/search-pc.

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
        .join("call_001_tid100_4r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100000, 0x100000];
    let mut buf = vec![0u8; 272 * pcs.len()];
    for (i, pc) in pcs.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
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
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn search_pc_returns_legacy_all_hit_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/search-pc?pc=0x100000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["pc"], "0x100000");
    assert_eq!(v["count"], 3);
    assert_eq!(v["idxs"], serde_json::json!([0, 2, 3]));
    assert_eq!(v["truncated"], false);
}

#[tokio::test]
async fn search_pc_limit_truncates_returned_idxs() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/search-pc?pc=0x100000&limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 3);
    assert_eq!(v["idxs"], serde_json::json!([0, 2]));
    assert_eq!(v["truncated"], true);
}

#[tokio::test]
async fn search_pc_bad_pc_is_400() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _v) = get(cd, "/api/search-pc?pc=bogus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
