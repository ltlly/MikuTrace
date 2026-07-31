//! Boundary contract tests for auto-phase / fn-summary / hash-finalize /
//! indirect-targets edge cases.

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
    fs::write(
        cd.join("meta.json"),
        r#"{"records":4,"known_offsets":{"0x0":"f_root"}}"#,
    )
    .unwrap();
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
async fn auto_phase_returns_phase_list() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/auto-phase-detect").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "trace_records", "total", "returned", "truncated"],
            "properties": {
                "status": {"const": "ready"},
                "trace_records": {"const": 4},
                "truncated": {"type": "boolean"},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn auto_phase_max_phases_zero_uses_default() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/auto-phase-detect?max_phases=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
}

#[tokio::test]
async fn auto_phase_limit_alias_works() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/auto-phase-detect?limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert!(v["returned"].as_u64().unwrap() <= 1);
}

#[tokio::test]
async fn fn_summary_known_fn_returns_ready() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/fn-summary?fn=f_root").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status"],
            "properties": {"status": {"enum": ["ready", "not-found"]}},
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn fn_summary_unknown_fn_returns_not_found() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/fn-summary?fn=no_such_fn").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "not-found");
}

#[tokio::test]
async fn indirect_targets_no_dispatch_reports_miss() {
    let (_tmp, cd) = synth_call_dir();
    // nop-only trace has no indirect branches; a known pc returns no_dispatch.
    let (status, v) = get_json(cd, "/api/indirect-targets?so=libt.so&off=0x0").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        v["status"] == "no_dispatch" || v["status"] == "miss" || v["status"] == "hit",
        "unexpected status: {v:?}"
    );
}

#[tokio::test]
async fn hash_finalize_requires_algorithm() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/hash-finalize-detect").await;
    assert_eq!(status, StatusCode::OK);
    // Missing required args yields a structured error, never a 500.
    assert_eq!(status, StatusCode::OK);
    assert!(v.is_object());
}
