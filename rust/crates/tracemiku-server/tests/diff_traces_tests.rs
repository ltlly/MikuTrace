use std::fs;
use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;

fn make_trace_dir(root: &Path, name: &str, key: &str, output: &[u8]) -> PathBuf {
    let dir = root.join(name);
    fs::create_dir_all(&dir).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    fs::write(dir.join("trace.bin"), &buf).unwrap();
    fs::write(dir.join("meta.json"), r#"{"records":1}"#).unwrap();
    let encoded = STANDARD.encode(output);
    let events = [
        json!({"id":"NewStringUTF","trace_idx":1,"args":{"bytes":key}}),
        json!({"id":"NewStringUTF","trace_idx":2,"args":{"bytes":encoded}}),
    ];
    fs::write(
        dir.join("jni_hooks.jsonl"),
        events
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    dir
}

async fn post(app_dir: PathBuf, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let app = tracemiku_server::build_router(app_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/diff-traces")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, json)
}

#[tokio::test]
async fn diff_traces_reports_stable_and_variable_offsets() {
    let tmp = tempfile::tempdir().unwrap();
    let run1 = make_trace_dir(
        tmp.path(),
        "run1",
        "signature",
        &hex_bytes("6b360108aaaaaaaa11111111"),
    );
    let run2 = make_trace_dir(
        tmp.path(),
        "run2",
        "signature",
        &hex_bytes("6b360108bbbbbbbb11111111"),
    );
    let body = json!({
        "traces": [run1.display().to_string(), run2.display().to_string()],
        "show_offsets": true
    });
    let (status, v) = post(run1, body).await;
    assert_eq!(status, StatusCode::OK);
    let signature = &v["headers"]["signature"];
    assert_eq!(signature["len_compared"], 12);
    assert_eq!(signature["stable_count"], 8);
    assert_eq!(signature["variable_count"], 4);
    assert_eq!(
        signature["stable_offsets"],
        json!([0, 1, 2, 3, 8, 9, 10, 11])
    );
    assert_eq!(signature["variable_offsets"], json!([4, 5, 6, 7]));
}

#[tokio::test]
async fn diff_traces_requires_two_traces() {
    let tmp = tempfile::tempdir().unwrap();
    let run1 = make_trace_dir(tmp.path(), "run1", "signature", b"AAAAAAAA");
    let body = json!({"traces": [run1.display().to_string()]});
    let (status, _) = post(run1, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
