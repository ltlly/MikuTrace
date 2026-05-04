//! /api/dec/summary integration test.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::fs;
use tower::ServiceExt;

fn synth_root_only() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 3];
    for i in 0..3usize {
        let off = i * 272;
        let pc = 0x100000u64 + (i as u64) * 4;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":3,"known_offsets":{"0x0":"f_root"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096},"method":"f","cmd":42,"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    dir
}

fn call_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

#[tokio::test]
async fn dec_summary_emits_root_funcir_with_trace_ir_source() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["records"], 3);
    assert_eq!(v["module_name"], "libt.so");
    assert_eq!(v["module_base"], 0x100000);
    let fns = v["fns"].as_array().unwrap();
    assert!(
        !fns.is_empty(),
        "expected at least 1 fn (root FuncIR + maybe sym fallback): {v}"
    );
    // M3-ε: fixture has a single known_offset (f_root) that matches the
    // trace-ir root name, so the symbol-source fallback dedupes to nothing.
    // Future fixture changes may add sym-source entries — assert >= 1 only.
    let f0 = fns
        .iter()
        .find(|f| f["source"] == "trace-ir")
        .expect("expected at least one trace-ir source entry");
    assert_eq!(f0["id"], "trace:F0");
    assert_eq!(f0["source"], "trace-ir");
    assert_eq!(f0["trace_ir_id"], "F0");
    assert_eq!(f0["entry_idx"], 0);
    assert_eq!(f0["exit_idx"], 2);
    let blocks_count = f0["blocks"].as_u64().unwrap();
    assert!(
        blocks_count >= 1,
        "F0 should have at least 1 block now (M3-ζ); got {blocks_count}"
    );
    assert_eq!(f0["calls"], 0);
    assert!(v["vm_candidates"].as_array().unwrap().is_empty());
    assert!(
        v["summary_md"]
            .as_str()
            .unwrap()
            .contains("- records: **3**"),
        "summary_md should mention record count via render_summary_md: {v}"
    );
}

fn synth_two_callees_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_9r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 9] = [
        0x100000, 0x100004, 0x100100, 0x100104, 0x100008, 0x100200, 0x100204, 0x100208, 0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x9400003f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":9,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536},"method":"f","cmd":42}"#,
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn dec_summary_includes_symbol_source_fallback() {
    let dir = synth_two_callees_fixture();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let fns = v["fns"].as_array().unwrap();
    let sources: Vec<&str> = fns.iter().map(|f| f["source"].as_str().unwrap()).collect();
    assert!(
        sources.contains(&"symbol"),
        "expected at least one symbol-source entry; got sources={sources:?}"
    );
    let sym_names: Vec<&str> = fns
        .iter()
        .filter(|f| f["source"] == "symbol")
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert!(
        sym_names.iter().any(|n| *n == "f_alpha" || *n == "f_beta"),
        "expected f_alpha or f_beta in sym-source fns; got {sym_names:?}"
    );
}

#[tokio::test]
async fn dec_summary_no_vm_candidates_on_synth_root_only() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let cands = v["vm_candidates"].as_array().unwrap();
    assert!(
        cands.is_empty(),
        "synth has no OLLVM pattern → no candidates"
    );
    let md = v["summary_md"].as_str().unwrap();
    assert!(
        !md.contains("## VM Candidates"),
        "should omit VM section when empty: {md}"
    );
}

#[tokio::test]
async fn dec_summary_summary_md_uses_render_summary_md() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let md = v["summary_md"].as_str().unwrap();
    assert!(
        md.starts_with("# Trace Summary"),
        "summary_md should start with markdown header: {md}"
    );
    assert!(
        md.contains("## Functions"),
        "Functions section missing: {md}"
    );
    assert!(
        md.contains("| id | name |"),
        "Functions table header missing: {md}"
    );
}
