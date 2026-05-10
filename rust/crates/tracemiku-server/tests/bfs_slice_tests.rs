//! Integration tests for `/api/bfs-slice`. Mirrors the synthetic call-dir
//! setup from `dep_graph_tests.rs` so the slice walks the same dependency
//! CSR.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    let cd = run.join("calls").join("call_001_tid100_5r_2ms");
    fs::create_dir_all(&cd).unwrap();

    // Sequence:
    //   idx 0: mov x0, x2
    //   idx 1: str x0, [sp]
    //   idx 2: cbz x0, +8         (conditional branch, not taken in this trace)
    //   idx 3: ldr x1, [sp]
    //   idx 4: add x3, x1, x2
    let mut trace_file = fs::File::create(cd.join("trace.bin")).unwrap();
    let mut regs0 = [0u64; 31];
    regs0[2] = 0x1122_3344_5566_7788;
    let mut regs1 = [0u64; 31];
    regs1[0] = 0x1122_3344_5566_7788;
    regs1[2] = 0x1122_3344_5566_7788;
    let mut regs2 = [0u64; 31];
    regs2[0] = 0x1122_3344_5566_7788;
    let mut regs3 = [0u64; 31];
    regs3[2] = 0x1122_3344_5566_7788;
    let mut regs4 = [0u64; 31];
    regs4[1] = 0x1122_3344_5566_7788;
    regs4[2] = 0x1122_3344_5566_7788;
    for (pc, regs, sp, inst) in [
        (0x100000u64, regs0, 0x7000u64, 0xaa0203e0u32), // mov x0, x2
        (0x100004u64, regs1, 0x7000u64, 0xf90003e0u32), // str x0, [sp]
        (0x100008u64, regs2, 0x7000u64, 0xb4000040u32), // cbz x0, +8
        (0x10000cu64, regs3, 0x7000u64, 0xf94003e1u32), // ldr x1, [sp]
        (0x100010u64, regs4, 0x7000u64, 0x8b020023u32), // add x3, x1, x2
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
async fn bfs_slice_walks_full_chain_from_idx_seed() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idx=4&limit=64").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["seed"]["kind"], "idx");
    assert_eq!(v["seed"]["idx"], 4);

    let slice = v["slice"].as_array().unwrap();
    let idxs: Vec<usize> = slice.iter().map(|n| n.as_u64().unwrap() as usize).collect();
    // 4 (seed) → x1 def at 3 → mem store at 1 → x2 / x0 def at 0
    assert!(idxs.contains(&4));
    assert!(idxs.contains(&3));
    assert!(idxs.contains(&1));
    assert!(idxs.contains(&0));
    assert!(v["slice_count"].as_u64().unwrap() >= 4);
    assert_eq!(v["truncated"], false);
    let stats = &v["edge_stats"];
    assert!(stats["total"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn bfs_slice_data_only_drops_control_edges() {
    let (_tmp, cd) = synth_call_dir();
    let (status, loose) = get(cd.clone(), "/api/bfs-slice?idx=4&limit=64&data_only=false").await;
    assert_eq!(status, StatusCode::OK);
    let (status, strict) = get(cd, "/api/bfs-slice?idx=4&limit=64&data_only=true").await;
    assert_eq!(status, StatusCode::OK);
    let loose_count = loose["slice_count"].as_u64().unwrap();
    let strict_count = strict["slice_count"].as_u64().unwrap();
    assert!(
        strict_count <= loose_count,
        "data_only must not enlarge slice (loose={loose_count}, strict={strict_count})"
    );
    assert_eq!(strict["data_only"], true);
    assert_eq!(loose["data_only"], false);
}

#[tokio::test]
async fn bfs_slice_resolves_reg_seed() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?reg=x1&before=4").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["seed"]["kind"], "reg");
    assert_eq!(v["seed"]["reg"], "x1");
    // last def of x1 strictly before idx 4 is the ldr at idx 3
    assert_eq!(v["seed"]["idx"], 3);
}

#[tokio::test]
async fn bfs_slice_resolves_addr_seed() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?addr=0x7000&before=4").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["seed"]["kind"], "addr");
    assert_eq!(v["seed"]["addr"], "0x7000");
    assert_eq!(v["seed"]["idx"], 1);
}

#[tokio::test]
async fn bfs_slice_missing_seed_returns_note() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["seed"]["kind"], "none");
    assert_eq!(v["slice_count"], 0);
    assert!(v["seed"]["note"].as_str().unwrap().contains("provide"));
}

#[tokio::test]
async fn bfs_slice_truncates_when_limit_is_smaller() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idx=4&limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["slice_count"], 1);
    assert_eq!(v["node_limit"], 1);
}

#[tokio::test]
async fn bfs_slice_invalid_addr_literal_reports_note() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?addr=bogus").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["seed"]["kind"], "addr");
    assert_eq!(v["slice_count"], 0);
    let note = v["seed"]["note"].as_str().unwrap_or("");
    assert!(
        note.contains("invalid address"),
        "expected invalid-address note, got {note:?}"
    );
}

#[tokio::test]
async fn bfs_slice_seed_past_trace_returns_note() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idx=999").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["slice_count"], 0);
    assert!(v["seed"]["note"]
        .as_str()
        .unwrap_or("")
        .contains("outside trace"));
}

#[tokio::test]
async fn bfs_slice_multi_seed_union_combines_lineages() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idxs=4,2&limit=64").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["mode"], "union");
    let seeds = v["seeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 2);
    let slice: Vec<usize> = v["slice"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as usize)
        .collect();
    // Union must include both seed lineages.
    assert!(slice.contains(&4), "{slice:?}");
    assert!(slice.contains(&2), "{slice:?}");
}

#[tokio::test]
async fn bfs_slice_multi_seed_intersection_finds_common_ancestor() {
    let (_tmp, cd) = synth_call_dir();
    // seeds: idx 3 (ldr x1, [sp]) and idx 4 (add x3, x1, x2). Both depend on
    // the str x0,[sp] at idx 1 transitively. Intersection should include 1 and
    // its ancestor 0 but not the seed-specific extras.
    let (status, v) = get(cd, "/api/bfs-slice?idxs=3,4&mode=intersection&limit=64").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["mode"], "intersection");
    let slice: Vec<usize> = v["slice"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as usize)
        .collect();
    assert!(
        slice.contains(&3),
        "intersection should retain ldr at 3: {slice:?}"
    );
    assert!(
        slice.contains(&1),
        "intersection should retain shared str at 1: {slice:?}"
    );
    assert!(
        !slice.contains(&4),
        "intersection should not include the second seed if it isn't an ancestor of the first: {slice:?}"
    );
}

#[tokio::test]
async fn bfs_slice_multi_seed_regs_resolves_each() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?regs=x1,x3&before=5&mode=union").await;
    assert_eq!(status, StatusCode::OK);
    let seeds = v["seeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 2);
    assert!(seeds.iter().any(|s| s["reg"] == "x1"));
    assert!(seeds.iter().any(|s| s["reg"] == "x3"));
}

#[tokio::test]
async fn bfs_slice_intersection_alias_accepted() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idxs=3,4&mode=intersect").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["mode"], "intersection");
}

#[tokio::test]
async fn bfs_slice_default_mode_is_union() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idx=4").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["mode"], "union");
}

#[tokio::test]
async fn bfs_slice_invalid_idxs_token_reports_note() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idxs=hello").await;
    assert_eq!(status, StatusCode::OK);
    let seeds = v["seeds"].as_array().unwrap();
    assert!(seeds.iter().any(|s| s["note"]
        .as_str()
        .unwrap_or("")
        .contains("invalid idx literal")));
}

#[tokio::test]
async fn bfs_slice_all_seeds_outside_returns_empty_slice_with_notes() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idxs=999,1000,1001").await;
    assert_eq!(status, StatusCode::OK);
    let seeds = v["seeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 3);
    assert_eq!(v["slice_count"], 0);
    assert!(seeds
        .iter()
        .all(|s| s["note"].as_str().unwrap_or("").contains("outside trace")));
}

#[tokio::test]
async fn bfs_slice_intersection_with_partial_validity_collapses_to_valid_seed() {
    let (_tmp, cd) = synth_call_dir();
    // idx=4 is valid, idx=999 is past trace; intersection should keep only the
    // valid seed's lineage and report the bad seed in `seeds[]`.
    let (status, v) = get(cd, "/api/bfs-slice?idxs=4,999&mode=intersection").await;
    assert_eq!(status, StatusCode::OK);
    let seeds = v["seeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 2, "{seeds:?}");
    assert!(seeds
        .iter()
        .any(|s| s["note"].as_str().unwrap_or("").contains("outside trace")));
    let slice: Vec<u64> = v["slice"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap())
        .collect();
    assert!(
        slice.contains(&4),
        "intersection should collapse to single valid seed: {slice:?}"
    );
}

#[tokio::test]
async fn bfs_slice_caps_seeds_at_16() {
    let (_tmp, cd) = synth_call_dir();
    let many = (0..20).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
    let uri = format!("/api/bfs-slice?idxs={many}");
    let (status, v) = get(cd, &uri).await;
    assert_eq!(status, StatusCode::OK);
    let seeds = v["seeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 16, "max 16 seeds; got {}", seeds.len());
}

#[tokio::test]
async fn bfs_slice_response_carries_enriched_rows() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/bfs-slice?idx=4&limit=64").await;
    assert_eq!(status, StatusCode::OK);
    let rows = v["rows"].as_array().unwrap();
    assert!(!rows.is_empty(), "rows must be enriched: {v}");
    let first = &rows[0];
    assert!(first["pc"].as_str().unwrap_or("").starts_with("0x"));
    assert!(!first["asm"].as_str().unwrap_or("").is_empty());
    assert_eq!(v["rows_capped"], false);
}

#[tokio::test]
async fn bfs_slice_edge_stats_per_kind_match_synthetic_fixture() {
    let (_tmp, cd) = synth_call_dir();
    // The synthetic fixture chains: mov→str→cbz→ldr→add. Backward from idx=4
    // should yield: reg edges (mov→x0, ldr→x1, add→x1+x2), an addr edge for
    // the load's base reg (sp), a mem edge for the str→ldr same-address pair,
    // and a control edge from the cbz at idx=2.
    let (status, v) = get(cd, "/api/bfs-slice?idx=4&limit=64").await;
    assert_eq!(status, StatusCode::OK);
    let stats = &v["edge_stats"];
    let total = stats["total"].as_u64().unwrap();
    assert!(total > 0);
    // total == sum of per-kind counts
    let parts = stats["reg"].as_u64().unwrap()
        + stats["address"].as_u64().unwrap()
        + stats["mem"].as_u64().unwrap()
        + stats["control"].as_u64().unwrap();
    assert_eq!(
        total, parts,
        "edge_stats.total must equal sum of kinds: {stats}"
    );
}
