use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir(x0: u64) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[8..16].copy_from_slice(&x0.to_le_bytes());
    buf[16..24].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[256..264].copy_from_slice(&0x8000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xf9000020u32.to_le_bytes()); // str x0,[x1]
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
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
async fn crypto_scan_finds_sha1_md5_iv_bytes() {
    let (_tmp, cd) = synth_call_dir(0x67452301);
    let (status, v) = get(cd, "/api/crypto-scan").await;
    assert_eq!(status, StatusCode::OK);
    assert!(v["scanned"].as_u64().unwrap() > 0);
    assert_eq!(v["any_hit"], true);
    let primitives = v["primitives"].as_array().unwrap();
    let sha1 = primitives
        .iter()
        .find(|p| p["name"] == "SHA1_H[0]/MD5_A")
        .unwrap();
    assert_eq!(sha1["pattern"], "01234567");
    assert_eq!(sha1["hit_count"], 1);
    assert_eq!(sha1["hits"][0]["addr"], "0x7000");
    assert_eq!(sha1["hits"][0]["first_idx"], 0);
}

#[tokio::test]
async fn crypto_scan_reports_zero_hits_for_non_crypto_bytes() {
    let (_tmp, cd) = synth_call_dir(0x11111111);
    let (status, v) = get(cd, "/api/crypto-scan").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["any_hit"], false);
}
