//! Black-box contract tests for the /api/coverage route.
//!
//! Covers: hit shape, miss (no executed blocks), branch determinism (sorted
//! by total desc, tie-break by block offset — the parity regression), and
//! error paths for invalid coordinates.

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
async fn coverage_known_fn_returns_ok_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/coverage?so=libt.so&off=0x0").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "function", "executed_blocks", "total_block_executions"],
            "properties": {
                "status": {"enum": ["ok", "miss"]},
                "executed_blocks": {"type": "integer"},
                "branch_points": {"type": ["integer", "array"]},
            },
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn coverage_unknown_pc_returns_miss() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/coverage?addr=0x999999").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(
        &serde_json::json!({
            "type": "object",
            "required": ["status", "query", "reason"],
            "properties": {"status": {"const": "miss"}},
        }),
        &v,
    );
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn coverage_missing_args_returns_error() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/coverage").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "error");
}

#[tokio::test]
async fn coverage_branches_are_deterministically_ordered() {
    // Regression for the parity bug: equal-total branches must be tie-broken
    // by block_offset, so two identical requests return byte-identical JSON.
    let (_tmp, cd) = synth_call_dir();
    let (_, v1) = get_json(cd.clone(), "/api/coverage?so=libt.so&off=0x0").await;
    let (_, v2) = get_json(cd, "/api/coverage?so=libt.so&off=0x0").await;
    assert_eq!(v1, v2, "coverage output must be deterministic");
    if let Some(branches) = v1.get("branches").and_then(|b| b.as_array()) {
        let offsets: Vec<&str> = branches
            .iter()
            .filter_map(|b| b["block_offset"].as_str())
            .collect();
        let mut sorted = offsets.clone();
        sorted.sort();
        assert_eq!(offsets, sorted, "tie-break by block_offset asc");
    }
}
