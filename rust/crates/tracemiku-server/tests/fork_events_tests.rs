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
    fs::write(
        cd.join("meta.json"),
        r#"{
          "records":1,
          "fork_events":[
            {"child_pid":123,"attach_status":"success","is_fork_like":true},
            {"child_pid":456,"attach_status":"failed_ptrace_conflict","is_fork_like":false}
          ]
        }"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
    )
    .unwrap();
    (tmp, cd)
}

async fn get_json(call_dir: PathBuf, uri: &str) -> serde_json::Value {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn fork_events_returns_all_events() {
    let (_tmp, call_dir) = synth_call_dir();
    let v = get_json(call_dir, "/api/fork-events").await;
    assert_eq!(v["count"], 2);
    assert_eq!(v["events"][0]["child_pid"], 123);
    assert_eq!(v["events"][1]["attach_status"], "failed_ptrace_conflict");
}

#[tokio::test]
async fn fork_events_filters_by_attach_status() {
    let (_tmp, call_dir) = synth_call_dir();
    let v = get_json(call_dir, "/api/fork-events?status=failed_ptrace_conflict").await;
    assert_eq!(v["count"], 1);
    assert_eq!(v["events"][0]["child_pid"], 456);
}
