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
        cd.join("jni_hooks.jsonl"),
        [
            r#"{"trace_idx":1,"id":"GetStringUTFChars","ret":"hello"}"#,
            r#"{"trace_idx":5,"id":"NewStringUTF","args":{"bytes":"x-sign"}}"#,
            "not json",
        ]
        .join("\n"),
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
async fn jni_events_filters_by_id_and_idx_range() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/jni-events?id=NewStringUTF&idx_lo=2&idx_hi=8").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 1);
    assert_eq!(v["events"][0]["id"], "NewStringUTF");
    assert_eq!(v["events"][0]["trace_idx"], 5);
}

#[tokio::test]
async fn jni_events_missing_file_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_0r_0ms");
    fs::create_dir_all(&cd).unwrap();
    fs::write(cd.join("trace.bin"), []).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":0}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    let (status, v) = get(cd, "/api/jni-events").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 0);
    assert!(v["events"].as_array().unwrap().is_empty());
}
