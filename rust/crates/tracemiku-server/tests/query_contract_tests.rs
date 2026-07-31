//! Boundary contract tests for the /api/query route.
//!
//! Covers: kind aliases, unknown-kind error shape, limit clamping, empty
//! search results, regex fallback on bad patterns.

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
    // mov x0,x1; mov x1,x2; nop; ret — real defs/uses for reg queries.
    let insts: [u32; 4] = [0xaa0103e0, 0xaa0203e1, 0xd503201f, 0xd65f03c0];
    let mut buf = vec![0u8; 272 * 4];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&((i as u64 + 1) * 10).to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
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

fn base_schema(status: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "required": ["status", "kind", "q", "count", "returned", "truncated", "max_used", "rows"],
        "properties": {
            "status": {"const": status},
            "rows": {"type": "array"},
            "count": {"type": "integer"},
            "truncated": {"type": "boolean"},
        },
    })
}

#[tokio::test]
async fn records_kind_returns_rows() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/query?kind=records&q=mov").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(&base_schema("ready"), &v);
    assert!(errors.is_empty(), "schema errors: {errors:?}");
    assert!(v["count"].as_u64().unwrap() >= 2, "two mov records");
    assert!(v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| { r.get("asm").and_then(|a| a.as_str()).is_some() }));
}

#[tokio::test]
async fn kind_alias_asm_is_accepted() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/query?kind=asm&q=ret").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert!(v["count"].as_u64().unwrap() >= 1, "ret exists");
}

#[tokio::test]
async fn unknown_kind_returns_error_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/query?kind=bogus&q=x").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "error");
    assert_eq!(v["kind"], "bogus");
    assert_eq!(v["count"], 0);
    assert!(v["rows"].as_array().unwrap().is_empty());
    assert_eq!(v["note"], "unknown query kind");
}

#[tokio::test]
async fn empty_search_returns_zero_count() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/query?kind=records&q=zzzznope").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["count"], 0);
    assert_eq!(v["returned"], 0);
    assert!(!v["truncated"].as_bool().unwrap());
}

#[tokio::test]
async fn bad_regex_falls_back_to_literal() {
    let (_tmp, cd) = synth_call_dir();
    // "(" is an invalid regex; must not panic, returns literal-ish result.
    let (status, v) = get_json(cd, "/api/query?kind=records&q=%28").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
}

#[tokio::test]
async fn regs_kind_returns_reg_values() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/query?kind=regs&q=x0&idx=0").await;
    assert_eq!(status, StatusCode::OK);
    let errors = validate(&base_schema("ready"), &v);
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

#[tokio::test]
async fn functions_kind_returns_function_rows() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/query?kind=functions").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
}

#[tokio::test]
async fn limit_zero_clamps_to_one() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/query?kind=records&q=mov&limit=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert!(v["returned"].as_u64().unwrap() <= 1, "limit clamped");
}

#[tokio::test]
async fn mem_kind_returns_memory_rows() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get_json(cd, "/api/query?kind=mem&addr=0x2000&idx=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    let errors = validate(&base_schema("ready"), &v);
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}
