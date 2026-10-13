use super::analysis_support;
use std::fs;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;

use serde_json::json;

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

fn synth_store_call_dir(x0: u64) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[8..16].copy_from_slice(&x0.to_le_bytes());
    buf[16..24].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xf9000020u32.to_le_bytes()); // str x0,[x1]
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn post(call_dir: PathBuf, body: serde_json::Value) -> (Option<&'static str>, serde_json::Value) {
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(
        &app,
        "hash-input-search",
        Some(serde_json::to_vec(&body).unwrap()),
    );
    let status = resp.error_code();
    let body = resp.bytes();
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, json)
}

#[test]
fn hash_input_search_finds_sha1_plain_match() {
    let (_tmp, cd) = synth_call_dir();
    let body = json!({
        "target_bytes": "aaf4c61ddcc5e8a2",
        "inputs": ["hello", "world"],
        "algos": ["sha1"],
        "combos": ["plain"],
        "prefix_bytes": 8
    });
    let (status, v) = post(cd, body);
    assert_eq!(status, None);
    assert_eq!(v["target_prefix"], "aaf4c61ddcc5e8a2");
    assert_eq!(v["tried_combos"], 2);
    assert_eq!(v["found_count"], 1);
    assert_eq!(v["found"][0]["input"], "hello");
    assert_eq!(v["found"][0]["algo"], "sha1");
    assert_eq!(v["found"][0]["combo"], "plain");
    assert_eq!(v["found"][0]["full_match"], true);
}

#[test]
fn hash_input_search_rejects_bad_target_hex() {
    let (_tmp, cd) = synth_call_dir();
    let body = json!({"target_bytes": "ZZZZ", "inputs": ["hello"]});
    let (status, _) = post(cd, body);
    assert_eq!(status, Some("invalid_argument"));
}

#[test]
fn hash_input_search_rejects_combo_over_limit() {
    // 100 inputs × 1 key × 4 默认 combos × 3000 algos = 1_200_000 > 200_000：
    // 必须在计算前拒绝。
    let (_tmp, cd) = synth_call_dir();
    let algos: Vec<String> = (0..3000).map(|i| format!("algo_{i}")).collect();
    let inputs: Vec<String> = (0..100).map(|i| format!("input_{i}")).collect();
    let body = json!({
        "target_bytes": "aaf4c61d",
        "inputs": inputs,
        "algos": algos,
    });
    let (status, v) = post(cd, body);
    assert_eq!(status, Some("limit_exceeded"));
    assert_eq!(v["status"], "error");
    assert_eq!(v["details"]["limit"], 200_000);
    assert_eq!(v["details"]["requested"], 1_200_000);
}

#[test]
fn hash_input_search_batches_memory_prefix_lookup() {
    // sha1("hello") starts with aa f4 c6 1d; store that prefix at 0x7000.
    let (_tmp, cd) = synth_store_call_dir(0x1dc6f4aa);
    let body = json!({
        "target_bytes": "00000000",
        "inputs": ["hello"],
        "algos": ["sha1"],
        "combos": ["plain"],
        "prefix_bytes": 4,
        "search_in_mem": true
    });
    let (status, v) = post(cd, body);
    assert_eq!(status, None);
    assert_eq!(v["found_count"], 1);
    assert_eq!(v["found"][0]["match_type"], "in_mem");
    assert_eq!(v["found"][0]["found_in_mem"][0]["addr"], "0x7000");
}
