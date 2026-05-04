//! /api/dec/fn/{fn_id} integration test.

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

/// 3-record fixture with an in-trace branch:
///   idx 0 @ 0x100000  nop          (0xd503201f)
///   idx 1 @ 0x100004  bl  0x100200 (0x9400007f → +0x1FC)
///   idx 2 @ 0x100200  nop          (0xd503201f)
///
/// CFG should split into 2 blocks (B0=0x100000, B1=0x100200) with at
/// least one edge from B0 → B1, so BlockIR.exits is non-empty and the
/// rendered markdown contains a `**exits**` section.
fn synth_with_branch() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 3];
    let pcs: [u64; 3] = [0x100000, 0x100004, 0x100200];
    let insts: [u32; 3] = [0xd503201f, 0x9400007f, 0xd503201f];
    for i in 0..3usize {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pcs[i].to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&insts[i].to_le_bytes());
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
async fn dec_fn_returns_markdown_for_trace_f0() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/trace:F0")
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
    assert_eq!(v["fn_id"], "trace:F0");
    assert_eq!(v["tier"], "hot");
    let md = v["markdown"].as_str().unwrap();
    assert!(md.contains("# F0"), "markdown should have header: {md}");
    assert!(!md.is_empty());
}

#[tokio::test]
async fn dec_fn_accepts_bare_f0_legacy_id() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/F0")
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
    assert_eq!(v["fn_id"], "F0"); // route handler echoes the input fn_id
    let md = v["markdown"].as_str().unwrap();
    assert!(
        md.contains("# F0"),
        "bare F0 should resolve via parse_id legacy"
    );
}

#[tokio::test]
async fn dec_fn_returns_404_for_unknown() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/trace:F99")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dec_fn_returns_markdown_for_sym_source() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/sym:f")
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
    assert_eq!(v["fn_id"], "sym:f");
    assert_eq!(v["name"], "f");
    let md = v["markdown"].as_str().unwrap();
    assert!(
        md.contains("# sym:f"),
        "sym FuncIR should render with public sym id: {md}"
    );
    assert!(
        md.contains("- **blocks**: 1"),
        "symbol markdown should include blocks: {md}"
    );
}

#[tokio::test]
async fn dec_fn_accepts_legacy_cfg_symbol_id() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/cfg:f")
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
    assert_eq!(v["fn_id"], "cfg:f");
    assert_eq!(v["name"], "f");
    assert!(v["markdown"].as_str().unwrap().contains("# sym:f"));
}

#[tokio::test]
async fn dec_fn_returns_404_for_unknown_symbol() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/sym:missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dec_fn_returns_404_for_bn_source_until_backend_lands() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/bn:0x100000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dec_fn_markdown_contains_exits_section_when_branches_present() {
    // M3-ι Task 2 — verify per-block `**exits**` section is wired into
    // the markdown rendered by /api/dec/fn/{id}. Use ?tier=all so the
    // tier filter doesn't drop a block before exits can render.
    let dir = synth_with_branch();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/fn/trace:F0?tier=all")
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
    let md = v["markdown"].as_str().unwrap();
    assert!(
        md.contains("**exits**"),
        "markdown should carry an exits section when branches are present:\n{md}"
    );
}
