//! /api/forward-taint + /api/backward-taint integration tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::fs;
use tower::ServiceExt;

fn synth_x0_chain() -> tempfile::TempDir {
    // 5 records of `add x0, x0, #1` (opcode 0x91000400), PCs 0x100000..0x10000c stride 4.
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_5r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 5];
    for i in 0..5usize {
        let off = i * 272;
        let pc = 0x100000u64 + (i as u64) * 4;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0x91000400u32.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
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
async fn forward_taint_basic() {
    let dir = synth_x0_chain();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/forward-taint?start=0&reg=x0&max_count=10")
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
    assert_eq!(v["from"], 0);
    assert_eq!(v["reg"], "x0");
    assert_eq!(v["stopped_at_max"], false);
    let count = v["count"].as_u64().unwrap();
    assert!(count >= 1, "expected at least 1 hit on x0 chain, got {v}");
    let hits = v["hits"].as_array().unwrap();
    for h in hits {
        assert!(!h["pc"].as_str().unwrap().is_empty());
        assert!(!h["asm"].as_str().unwrap().is_empty());
        assert!(
            h["why"].as_str().unwrap().contains("x0"),
            "why must reference x0: {h}"
        );
    }
}

#[tokio::test]
async fn forward_taint_accepts_trace_idx_alias() {
    let dir = synth_x0_chain();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/forward-taint?trace_idx=0&reg=x0&max_count=10")
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
    assert_eq!(v["from"], 0);
    assert_eq!(v["reg"], "x0");
}

#[tokio::test]
async fn backward_taint_basic() {
    let dir = synth_x0_chain();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/backward-taint?start=4&reg=x0&max_count=10")
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
    assert_eq!(v["from"], 4);
    assert_eq!(v["reg"], "x0");
    let chain = v["chain"].as_array().unwrap();
    assert!(!chain.is_empty(), "expected backward chain on x0: {v}");
    for h in chain {
        // Wire-shape pin: `via` is the bare reg name ("x0"), not "via:x0".
        assert_eq!(
            h["via"].as_str().unwrap(),
            "x0",
            "via must be bare reg name: {h}"
        );
    }
}

#[tokio::test]
async fn forward_taint_cross_fn_call_emits_frame_depth() {
    // Use the existing 5-rec `add x0, x0, #1` chain (no bl/ret, so all
    // frame_depths are 0 — verifies the field shows up but doesn't pin
    // a non-trivial value).
    let dir = synth_x0_chain();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");

    // With cross_fn_call=true: each row has frame_depth (likely 0).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/forward-taint?start=0&reg=x0&max_count=10&cross_fn_call=true")
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
    let hits = v["hits"].as_array().unwrap();
    assert!(!hits.is_empty(), "expected at least 1 hit on x0 chain");
    for h in hits {
        assert!(
            h.get("frame_depth").is_some(),
            "frame_depth must be present when cross_fn_call=true: {h}"
        );
    }
}

#[tokio::test]
async fn forward_taint_no_cross_fn_call_omits_frame_depth() {
    let dir = synth_x0_chain();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/forward-taint?start=0&reg=x0&max_count=10")
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
    let hits = v["hits"].as_array().unwrap();
    for h in hits {
        assert!(
            h.get("frame_depth").is_none(),
            "frame_depth must be omitted (skip_serializing_if) when cross_fn_call absent: {h}"
        );
    }
}
