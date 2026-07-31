//! Boundary contract tests for reg-at / mem-export / analysis-index /
//! watchpoints routes — edge cases beyond the happy paths in
//! contract_routes_1.

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
        buf[off + 8..off + 16].copy_from_slice(&((i as u64 + 1) * 10).to_le_bytes());
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

#[tokio::test]
async fn reg_at_off_coordinate_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/reg-at?reg=x0&so=libt.so&off=0x0").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "reg", "source"],
            "properties": {"status": {"enum": ["hit", "no_execution"]}},
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
    assert_eq!(v["reg"], "x0");
}

#[tokio::test]
async fn reg_at_missing_args_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/reg-at?reg=x0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "error");
}

#[tokio::test]
async fn reg_at_invalid_addr_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/reg-at?reg=x0&addr=zz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "error");
}

#[tokio::test]
async fn mem_export_len_zero_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/mem-export?addr=0x100000&len=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "error", "len must be > 0");
}

#[tokio::test]
async fn mem_export_missing_len_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/mem-export?addr=0x100000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "error");
}

#[tokio::test]
async fn mem_export_huge_len_truncates() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/mem-export?addr=0x100000&len=999999999").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "len", "requested_len", "hex"],
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
    assert!(v["len"].as_u64().unwrap() <= 1_000_000, "capped export");
}

#[tokio::test]
async fn watchpoints_reg_change_route_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/watchpoints?reg=x0&cursor=0&limit=10").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "returned", "total_matches", "truncated", "hits"],
            "properties": {
                "hits": {"type": "array"},
                "truncated": {"type": "boolean"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn analysis_index_returns_summary_with_counts() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/analysis-index").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["checkpoint_count", "mem_last_def_count", "sidecar", "summary"],
            "properties": {
                "summary": {"type": "object"},
                "checkpoint_count": {"type": "integer"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
