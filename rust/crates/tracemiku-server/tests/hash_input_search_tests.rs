use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::json;
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

async fn post(call_dir: PathBuf, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/hash-input-search")
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
async fn hash_input_search_finds_sha1_plain_match() {
    let (_tmp, cd) = synth_call_dir();
    let body = json!({
        "target_bytes": "aaf4c61ddcc5e8a2",
        "inputs": ["hello", "world"],
        "algos": ["sha1"],
        "combos": ["plain"],
        "prefix_bytes": 8
    });
    let (status, v) = post(cd, body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["target_prefix"], "aaf4c61ddcc5e8a2");
    assert_eq!(v["tried_combos"], 2);
    assert_eq!(v["found_count"], 1);
    assert_eq!(v["found"][0]["input"], "hello");
    assert_eq!(v["found"][0]["algo"], "sha1");
    assert_eq!(v["found"][0]["combo"], "plain");
    assert_eq!(v["found"][0]["full_match"], true);
}

#[tokio::test]
async fn hash_input_search_rejects_bad_target_hex() {
    let (_tmp, cd) = synth_call_dir();
    let body = json!({"target_bytes": "ZZZZ", "inputs": ["hello"]});
    let (status, _) = post(cd, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
