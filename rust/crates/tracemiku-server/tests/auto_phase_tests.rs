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
    buf[8..16].copy_from_slice(&0x67452301u64.to_le_bytes());
    buf[16..24].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[256..264].copy_from_slice(&0x8000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xf9000020u32.to_le_bytes()); // str x0,[x1]
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
    fs::write(
        cd.join("jni_hooks.jsonl"),
        r#"{"trace_idx":0,"id":"NewStringUTF","args":{"bytes":"x-sign"}}"#,
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
async fn auto_phase_reports_jni_and_crypto_phases() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/auto-phase-detect").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["trace_records"], 1);
    let phases = v["phases"].as_array().unwrap();
    assert!(phases
        .iter()
        .any(|p| p["phase"] == "jni_output" && p["info"] == "NewStringUTF 'x-sign'"));
    assert!(phases
        .iter()
        .any(|p| p["phase"] == "sha1_init" && p["info"] == "IV pattern at 0x7000"));
}

#[tokio::test]
async fn auto_phase_caps_returned_phases() {
    let (_tmp, cd) = synth_call_dir();
    let mut lines = String::new();
    for n in 0..6 {
        let idx = n * 100;
        lines.push_str(&format!(
            r#"{{"trace_idx":{idx},"id":"NewStringUTF","args":{{"bytes":"s{n}"}}}}"#
        ));
        lines.push('\n');
    }
    fs::write(cd.join("jni_hooks.jsonl"), lines).unwrap();

    let (status, v) = get(
        cd,
        "/api/auto-phase-detect?detect_byte_streams=false&max_phases=3",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["returned"], 3);
    assert_eq!(v["truncated"], true);
    assert!(v["total"].as_u64().unwrap() >= 6);
    assert_eq!(v["phases"].as_array().unwrap().len(), 3);
}
