//! Black-box contract tests for the query command family.
//!
//! Contract = output validates against JSON Schema. Schemas lock top-level
//! structure and key field types; volatile values stay loose.

mod common;

use common::{assert_valid, run_json, synth_call_dir};

#[test]
fn hash_search_long_prefix_skips_short_digests_without_panicking() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&[
        "hash-input-search",
        cd.to_str().unwrap(),
        "--target-bytes",
        &"ff".repeat(32),
        "--inputs",
        "abc",
        "--algos",
        "sha1,sha256",
        "--combos",
        "plain",
        "--prefix-bytes",
        "32",
        "--search-in-mem",
    ]);
    assert_eq!(value["status"], "ready");
    assert_eq!(value["tried_combos"], 2);
    assert_eq!(value["found_count"], 0);
    assert_eq!(value["found"], serde_json::json!([]));
}

#[test]
fn records_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["records", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["count", "returned", "start", "end", "records", "truncated"],
            "properties": {
                "count": {"const": 9},
                "records": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["idx", "pc", "off", "func", "module", "asm"],
                    },
                },
            },
        }),
        &value,
    );
}

#[test]
fn backward_taint_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&[
        "taint-bwd",
        cd.to_str().unwrap(),
        "--start",
        "4",
        "--reg",
        "x0",
        "--max-count",
        "10",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "from", "reg", "chain", "graph", "count"],
            "properties": {
                "from": {"type": "integer"},
                "chain": {"type": "array"},
                "graph": {
                    "type": "object",
                    "required": ["nodes", "edges", "node_count", "edge_count"],
                },
            },
        }),
        &value,
    );
}

#[test]
fn resolve_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&[
        "resolve",
        cd.to_str().unwrap(),
        "--so",
        "libt.so",
        "--off",
        "0x100",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "coord", "direction", "query"],
        }),
        &value,
    );
}

#[test]
fn search_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["search", cd.to_str().unwrap(), "nop"]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["count", "returned", "hits", "pattern", "total_matches", "truncated"],
            "properties": {
                "hits": {"type": "array"},
                "pattern": {"type": "string"},
                "truncated": {"type": "boolean"},
            },
        }),
        &value,
    );
}

#[test]
fn functions_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["functions", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["functions", "total_functions", "returned_functions", "truncated"],
            "properties": {"functions": {"type": "array"}, "truncated": {"type": "boolean"}},
        }),
        &value,
    );
    assert!(value["counts"].get("bn").is_none());
    for function in value["functions"].as_array().unwrap() {
        assert!(function.get("bn_start").is_none());
        assert!(function.get("can_bn_hlil").is_none());
        assert_eq!(function["source"], "symbol");
    }
}

#[test]
fn coverage_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["branch-coverage", cd.to_str().unwrap(), "--fn", "f"]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "function", "executed_blocks"],
            "properties": {"executed_blocks": {"type": "integer"}},
        }),
        &value,
    );
}

#[test]
fn call_tree_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["call-tree", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({"type": "object", "required": ["tree"]}),
        &value,
    );
}

#[test]
fn reg_at_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&[
        "reg-at",
        cd.to_str().unwrap(),
        "--addr",
        "0x100000",
        "--reg",
        "x0",
    ]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "source", "reg", "hits", "exec_count", "hits_capped"],
            "properties": {
                "status": {"const": "hit"},
                "reg": {"const": "x0"},
                "hits": {"type": "array", "minItems": 1},
                "exec_count": {"const": 1}
            },
        }),
        &value,
    );
    assert_eq!(value["hits"][0]["idx"], 0);
    assert_eq!(value["hits"][0]["value"], "0x0");
}

#[test]
fn cfg_matches_schema() {
    let (_tmp, cd) = synth_call_dir();
    let value = run_json(&["cfg", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["status", "blocks", "edges", "total_blocks", "total_edges", "truncated"],
            "properties": {"blocks": {"type": "array"}, "edges": {"type": "array"}},
        }),
        &value,
    );
}

#[test]
fn jni_strings_preserves_buffer_bytes_and_preview_boundary() {
    let (_tmp, cd) = synth_call_dir();
    let mut trace = vec![0u8; 272 * 4];
    for (idx, inst) in [0xf9000023u32, 0xf9429c09, 0xd63f0120, 0xd503201f]
        .into_iter()
        .enumerate()
    {
        let row = &mut trace[idx * 272..(idx + 1) * 272];
        row[..8].copy_from_slice(&(0x100000u64 + idx as u64 * 4).to_le_bytes());
        row[8..16].copy_from_slice(&0xdead_u64.to_le_bytes());
        row[16..24].copy_from_slice(&0x7000_u64.to_le_bytes());
        row[32..40].copy_from_slice(&u64::from_le_bytes(*b"hello\0\0\0").to_le_bytes());
        row[268..272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), trace).unwrap();
    let value = run_json(&["jni-strings", cd.to_str().unwrap()]);
    assert_valid(
        serde_json::json!({
            "type": "object",
            "required": ["count", "returned", "truncated", "encoding", "display_encoding", "hits"],
            "properties": {
                "encoding": {"const": "modified_utf8"},
                "display_encoding": {"const": "utf8_lossy"},
                "hits": {
                    "type": "array", "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["buffer_addr", "observed_bytes", "bytes_hex", "string", "read_stop"],
                        "properties": {
                            "bytes_hex": {"type": ["string", "null"]},
                            "string": {"type": ["string", "null"]},
                            "read_stop": {"enum": ["nul", "missing", "limit", "null_pointer", "return_unobserved", "address_overflow"]}
                        }
                    }
                }
            }
        }),
        &value,
    );
    assert_eq!(value["hits"][0]["jni_fn"], "NewStringUTF");
    assert_eq!(value["hits"][0]["buffer_addr"], "0x7000");
    assert_eq!(value["hits"][0]["bytes_hex"], "68656c6c6f");
    assert_eq!(value["hits"][0]["string"], "hello");
    assert_eq!(value["hits"][0]["read_stop"], "nul");
    let limited = run_json(&["jni-strings", cd.to_str().unwrap(), "--max-len", "3"]);
    assert_eq!(limited["hits"][0]["bytes_hex"], "68656c");
    assert_eq!(limited["hits"][0]["read_stop"], "limit");
}
