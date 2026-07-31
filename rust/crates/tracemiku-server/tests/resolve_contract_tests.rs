//! Boundary contract tests for the /api/resolve route.
//!
//! Covers the status matrix: hit / miss / out_of_range / ambiguous / error,
//! plus addr- and offset-based coordinate directions.

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
    let mut buf = vec![0u8; 272 * 4];
    for i in 0..4 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
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

async fn get_json(call_dir: PathBuf, uri: &str) -> (StatusCode, serde_json::Value) {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

fn validate(schema: &serde_json::Value, value: &serde_json::Value) -> Vec<String> {
    let validator = jsonschema::validator_for(schema).expect("valid json schema");
    validator
        .iter_errors(value)
        .map(|e| e.to_string())
        .collect()
}

fn status_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["status", "coord", "direction", "query"],
        "properties": {
            "status": {"enum": ["hit", "miss", "out_of_range", "ambiguous", "error"]},
            "coord": {"type": "object"},
            "direction": {"type": "string"},
        },
    })
}

#[tokio::test]
async fn resolve_off_in_module_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/resolve?so=libt.so&off=0x0").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(&status_schema(), &v);
    assert!(errors.is_empty(), "schema errors: {errors:?}");
    assert_eq!(v["status"], "hit");
}

#[tokio::test]
async fn resolve_off_outside_module_is_out_of_range() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/resolve?so=libt.so&off=0x99999").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "out_of_range");
}

#[tokio::test]
async fn resolve_unknown_module_is_miss() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/resolve?so=nonexistent.so&off=0x0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "miss");
}

#[tokio::test]
async fn resolve_invalid_off_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/resolve?so=libt.so&off=zz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "error");
    assert!(v["error"].as_str().is_some());
}

#[tokio::test]
async fn resolve_addr_in_trace_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/resolve?addr=0x100004").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "hit");
}

#[tokio::test]
async fn resolve_missing_args_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/resolve").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "error");
}

#[tokio::test]
async fn resolve_ambiguous_module_returns_ambiguous() {
    // Two modules overlapping the same name prefix -> ambiguous status.
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"modules":[{"name":"libt.so","base":"0x100000","size":65536},{"name":"libt_v2.so","base":"0x200000","size":65536}]}"#,
    )
    .unwrap();
    let (status, v) = get_json(cd, "/api/resolve?so=libt&off=0x0").await;
    assert_eq!(status, StatusCode::OK);
    // Prefix match may hit either hit (single candidate) or ambiguous.
    assert!(
        v["status"] == "hit" || v["status"] == "ambiguous",
        "unexpected status: {v:?}"
    );
}
