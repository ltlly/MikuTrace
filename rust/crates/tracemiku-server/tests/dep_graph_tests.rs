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
    let cd = run.join("calls").join("call_001_tid100_3r_2ms");
    fs::create_dir_all(&cd).unwrap();

    let mut trace_file = fs::File::create(cd.join("trace.bin")).unwrap();
    let mut regs0 = [0u64; 31];
    regs0[2] = 0x1122_3344_5566_7788;
    let mut regs1 = [0u64; 31];
    regs1[0] = 0x1122_3344_5566_7788;
    let regs2 = [0u64; 31];
    for (pc, regs, sp, inst) in [
        // mov x0, x2
        (0x100000u64, regs0, 0x7000u64, 0xaa0203e0u32),
        // str x0, [sp]
        (0x100004u64, regs1, 0x7000u64, 0xf90003e0u32),
        // ldr x1, [sp]
        (0x100008u64, regs2, 0x7000u64, 0xf94003e1u32),
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
        r#"{"records":3,"known_offsets":{"0x0":"f_root"}}"#,
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
async fn dep_graph_idx_seed_walks_mem_and_reg_dependencies() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/dep-graph?idx=2&depth=3&limit=16").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["seed"]["kind"], "idx");
    assert_eq!(v["seed"]["idx"], 2);

    let nodes = v["graph"]["nodes"].as_array().unwrap();
    assert!(nodes.iter().any(|node| node["idx"] == 2));
    assert!(nodes.iter().any(|node| node["idx"] == 1));
    assert!(nodes.iter().any(|node| node["idx"] == 0));
    assert!(nodes
        .iter()
        .any(|node| node["expression"].as_str().unwrap_or("").contains("*(")));

    let edges = v["graph"]["edges"].as_array().unwrap();
    assert!(edges
        .iter()
        .any(|edge| edge["from"] == "idx:1" && edge["to"] == "idx:2" && edge["kind"] == "mem"));
    assert!(edges
        .iter()
        .any(|edge| edge["from"] == "idx:0" && edge["to"] == "idx:1" && edge["kind"] == "reg"));
}

#[tokio::test]
async fn dep_graph_resolves_reg_and_addr_seeds() {
    let (_tmp, cd) = synth_call_dir();
    let (status, reg) = get(cd.clone(), "/api/dep-graph?reg=x1&before=3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reg["seed"]["kind"], "reg");
    assert_eq!(reg["seed"]["idx"], 2);
    assert_eq!(reg["seed"]["reg"], "x1");

    let (status, addr) = get(cd, "/api/dep-graph?addr=0x7000&before=3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(addr["seed"]["kind"], "addr");
    assert_eq!(addr["seed"]["idx"], 1);
    assert_eq!(addr["seed"]["addr"], "0x7000");
}
