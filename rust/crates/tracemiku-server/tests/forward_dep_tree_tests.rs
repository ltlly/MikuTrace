//! Integration tests for `/api/forward-dep-tree`.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    // Same shape as dep_graph_tests.rs but with one more later use of x1 so
    // forward-dep-tree from idx=0 can show x0 fanning out to multiple users.
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    let cd = run.join("calls").join("call_001_tid100_5r_2ms");
    fs::create_dir_all(&cd).unwrap();

    let mut trace_file = fs::File::create(cd.join("trace.bin")).unwrap();
    let mut regs0 = [0u64; 31];
    regs0[2] = 0x1122_3344_5566_7788;
    let mut regs1 = [0u64; 31];
    regs1[0] = 0x1122_3344_5566_7788;
    let mut regs2 = [0u64; 31];
    regs2[0] = 0x1122_3344_5566_7788;
    let regs3 = [0u64; 31];
    let mut regs4 = [0u64; 31];
    regs4[1] = 0x1122_3344_5566_7788;
    for (pc, regs, sp, inst) in [
        (0x100000u64, regs0, 0x7000u64, 0xaa0203e0u32), // mov x0, x2
        (0x100004u64, regs1, 0x7000u64, 0xf90003e0u32), // str x0, [sp]
        (0x100008u64, regs2, 0x7000u64, 0x91000400u32), // add x0, x0, #1
        (0x10000cu64, regs3, 0x7000u64, 0xf94003e1u32), // ldr x1, [sp]
        (0x100010u64, regs4, 0x7000u64, 0x8b010023u32), // add x3, x1, x1
    ] {
        let mut buf = [0u8; 272];
        buf[0..8].copy_from_slice(&pc.to_le_bytes());
        for (i, value) in regs.iter().enumerate() {
            let start = 8 + i * 8;
            buf[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        buf[256..264].copy_from_slice(&sp.to_le_bytes());
        buf[268..272].copy_from_slice(&inst.to_le_bytes());
        trace_file.write_all(&buf).unwrap();
    }

    fs::write(
        cd.join("meta.json"),
        r#"{"records":5,"known_offsets":{"0x0":"f_root"}}"#,
    )
    .unwrap();
    fs::write(
        run.join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

async fn get(call_dir: PathBuf, uri: &str) -> (StatusCode, serde_json::Value) {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn forward_dep_tree_walks_def_to_use_direction() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/forward-dep-tree?idx=0&depth=4&limit=32").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["seed"]["kind"], "idx");
    assert_eq!(v["seed"]["idx"], 0);

    let nodes = v["graph"]["nodes"].as_array().unwrap();
    let idxs: Vec<u64> = nodes.iter().map(|n| n["idx"].as_u64().unwrap()).collect();
    assert!(idxs.contains(&0), "seed must be present: {idxs:?}");
    // x0 written at 0 is read by 1 (str x0,[sp]) and 2 (add x0,x0,#1)
    assert!(idxs.contains(&1), "downstream user 1 missing: {idxs:?}");
    assert!(idxs.contains(&2), "downstream user 2 missing: {idxs:?}");

    let edges = v["graph"]["edges"].as_array().unwrap();
    assert!(
        edges
            .iter()
            .any(|e| e["from"] == "idx:0" && e["to"] == "idx:1"),
        "missing forward edge 0→1: {edges:?}"
    );
}

#[tokio::test]
async fn forward_dep_tree_data_only_drops_control_users() {
    let (_tmp, cd) = synth_call_dir();
    let (status, loose) = get(cd.clone(), "/api/forward-dep-tree?idx=0&depth=8").await;
    assert_eq!(status, StatusCode::OK);
    let (status, strict) = get(cd, "/api/forward-dep-tree?idx=0&depth=8&data_only=true").await;
    assert_eq!(status, StatusCode::OK);
    let loose_nodes = loose["graph"]["nodes"].as_array().unwrap().len();
    let strict_nodes = strict["graph"]["nodes"].as_array().unwrap().len();
    assert!(strict_nodes <= loose_nodes, "data_only enlarged graph");
    assert_eq!(strict["graph"]["data_only"], true);
}

#[tokio::test]
async fn forward_dep_tree_seed_outside_trace_returns_note() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/forward-dep-tree?idx=999").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["graph"]["nodes"].as_array().unwrap().len(), 0);
    assert!(v["seed"]["note"]
        .as_str()
        .unwrap_or("")
        .contains("outside trace"));
}

#[tokio::test]
async fn forward_dep_tree_resolves_reg_seed() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/forward-dep-tree?reg=x0&before=3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["seed"]["kind"], "reg");
    assert_eq!(v["seed"]["reg"], "x0");
    // last def of x0 before idx 3 is idx 2 (add x0, x0, #1)
    assert_eq!(v["seed"]["idx"], 2);
}

#[tokio::test]
async fn forward_dep_tree_truncates_at_node_limit() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/forward-dep-tree?idx=0&limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["graph"]["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(v["graph"]["truncated"], true);
}

#[tokio::test]
async fn forward_dep_tree_invalid_addr_literal_reports_note() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/forward-dep-tree?addr=bogus").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["seed"]["kind"], "addr");
    assert!(v["seed"]["note"]
        .as_str()
        .unwrap_or("")
        .contains("invalid address"));
}

#[tokio::test]
async fn forward_dep_tree_addr_seed_resolves_to_writer() {
    let (_tmp, cd) = synth_call_dir();
    // The synthetic call dir stores x0 to [sp]=0x7000 at idx=1. addr seed
    // should resolve to that writer.
    let (status, v) = get(cd, "/api/forward-dep-tree?addr=0x7000&before=5").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["seed"]["kind"], "addr");
    assert_eq!(v["seed"]["addr"], "0x7000");
    assert_eq!(v["seed"]["idx"], 1);
}

#[tokio::test]
async fn forward_dep_tree_truncation_reports_hidden_edges() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/forward-dep-tree?idx=0&limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["graph"]["truncated"], true);
    let hidden = v["graph"]["hidden_edges"].as_u64().unwrap_or(0);
    assert!(hidden > 0, "expected hidden_edges > 0 when capped: {v}");
}

#[tokio::test]
async fn forward_dep_tree_depth_zero_returns_seed_only() {
    let (_tmp, cd) = synth_call_dir();
    // Audit P0-1: depth=0 must mean "seed only", not silently rewritten to 1.
    let (status, v) = get(cd, "/api/forward-dep-tree?idx=0&depth=0").await;
    assert_eq!(status, StatusCode::OK);
    let nodes = v["graph"]["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1, "depth=0 must emit only the seed: {nodes:?}");
    assert_eq!(nodes[0]["idx"], 0);
}
