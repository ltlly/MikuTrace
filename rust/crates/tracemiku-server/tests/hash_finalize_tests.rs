use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir(spacing: u64) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 4];
    for i in 0..4 {
        let off = i * 272;
        let pc = 0x100000u64 + i as u64 * 4;
        let x1 = 0x7000u64 + i as u64 * spacing;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&(0x41424344u64 + i as u64).to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xf9000020u32.to_le_bytes());
        // str x0,[x1]
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
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn hash_finalize_detects_contiguous_digest_region() {
    let (_tmp, cd) = synth_call_dir(8);
    let (status, v) = get(cd, "/api/hash-finalize-detect?window=10&min_size=16").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["window"], 10);
    assert_eq!(v["min_size"], 16);
    assert_eq!(v["count"], 1);
    assert_eq!(v["candidates"][0]["addr"], "0x7000");
    assert_eq!(v["candidates"][0]["size"], 32);
    assert_eq!(v["candidates"][0]["enter_idx"], 0);
    assert_eq!(v["candidates"][0]["exit_idx"], 3);
    assert_eq!(v["candidates"][0]["kind"], "mixed");
    assert_eq!(v["candidates"][0]["guess"], "sha256");
}

#[tokio::test]
async fn hash_finalize_ignores_non_contiguous_writes() {
    let (_tmp, cd) = synth_call_dir(16);
    let (status, v) = get(cd, "/api/hash-finalize-detect?window=10&min_size=16").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 0);
}
