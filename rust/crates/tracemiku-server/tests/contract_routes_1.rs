//! Black-box contract tests for server routes that previously had no
//! behavior tests: analysis_index / indirect_targets / mem_export / reg_at.
//!
//! Contract = JSON response validates against the schema defined here,
//! exercised through the real router (tower oneshot).

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
async fn analysis_index_returns_status_object() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/analysis-index").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["checkpoint_count", "mem_last_def_count", "sidecar", "summary"],
            "properties": {
                "summary": {"type": "object", "required": ["call_count"]},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn indirect_targets_unknown_addr_returns_error_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/indirect-targets?addr=0x999999").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status"],
            "properties": {"status": {"type": "string"}},
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn indirect_targets_valid_off_returns_hit_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/indirect-targets?so=libt.so&off=0x0").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": {"enum": ["hit", "miss", "no_dispatch"]},
                "targets": {"type": "array"},
                "distinct_targets": {"type": "integer"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn mem_export_without_len_returns_error_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/mem-export?addr=0x100000").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "error"],
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn mem_export_with_len_returns_hex_and_metadata() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/mem-export?addr=0x100000&len=4").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["hex", "len", "requested_len", "completeness", "observed_count", "histogram", "provenance_runs", "start", "note"],
            "properties": {
                "hex": {"type": "string"},
                "len": {"type": "integer"},
                "completeness": {"type": "number"},
                "histogram": {"type": "object"},
                "provenance_runs": {"type": "array"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn reg_at_unknown_pc_returns_error_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/reg-at?reg=x0&addr=0x999999").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "reg", "source"],
            "properties": {
                "status": {"enum": ["hit", "no_execution"]},
                "reg": {"type": "string"},
                "source": {"type": "object"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
    assert_eq!(v["status"], "no_execution");
}

#[tokio::test]
async fn reg_at_known_pc_returns_hits_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/reg-at?reg=x0&addr=0x100000").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "reg", "source"],
            "properties": {
                "status": {"enum": ["hit", "no_execution"]},
                "reg": {"type": "string"},
                "source": {"type": "object"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
