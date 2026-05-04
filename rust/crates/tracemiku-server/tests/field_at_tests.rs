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
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xd503201fu32.to_le_bytes());
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
async fn field_at_returns_bn_not_ready_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/field-at?pc=0x100000&reg=x8&offset=0x80").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["pc"], "0x100000");
    assert_eq!(v["reg"], "x8");
    assert_eq!(v["offset"], 128);
    assert_eq!(v["hit"], false);
    assert_eq!(v["struct"], serde_json::Value::Null);
    assert_eq!(v["field"], serde_json::Value::Null);
}

#[tokio::test]
async fn field_at_bad_offset_falls_back_to_zero() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/field-at?pc=not-a-number&reg=x0&offset=bad").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["hit"], false);
    assert_eq!(v["offset"], 0);
}
