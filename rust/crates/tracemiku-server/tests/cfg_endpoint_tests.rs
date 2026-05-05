use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tokio::sync::Mutex;
use tower::ServiceExt;
use tracemiku_server::state::CfgSvgCached;

static DOT_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn dot_env_lock() -> &'static Mutex<()> {
    DOT_ENV_LOCK.get_or_init(|| Mutex::new(()))
}

fn synth_call_dir_with_known_offsets() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    // Use the corrected bl encoding from Task 5 / Task 3 fixtures:
    // bl 0x100100 from PC 0x100000 = 0x94000040
    // bl 0x100200 from PC 0x100008 = 0x9400007e
    let pcs = [
        0x100000u64,
        0x100004,
        0x100100,
        0x100104,
        0x100008,
        0x100200,
        0x100204,
        0x100208,
        0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x94000040, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(cd.join("meta.json"),
              r#"{"records":9,"truncated":false,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    (tmp, cd)
}

fn synth_large_cfg_call_dir() -> (tempfile::TempDir, PathBuf) {
    synth_cfg_call_dir(190, "f_big")
}

fn synth_edge_heavy_cfg_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let block_count = 80usize;
    let mut pc_indexes = Vec::new();
    for src in 0..20usize {
        for dst in 20..40usize {
            pc_indexes.push(src);
            pc_indexes.push(dst);
        }
    }
    let record_count = pc_indexes.len();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join(format!("call_001_tid100_{record_count}r_2ms"));
    fs::create_dir_all(&cd).unwrap();
    let base = 0x100000u64;
    let mut buf = vec![0u8; 272 * record_count];
    for (i, pc_index) in pc_indexes.into_iter().enumerate() {
        let pc = base + (pc_index as u64) * 4;
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0x14000001u32.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    let known_offsets = (0..block_count)
        .map(|i| format!(r#""0x{:x}":"f_edge""#, i * 4))
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        cd.join("meta.json"),
        format!(
            r#"{{"records":{record_count},"truncated":false,"known_offsets":{{{known_offsets}}}}}"#
        ),
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"pkg":"tst","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn synth_huge_cfg_call_dir() -> (tempfile::TempDir, PathBuf) {
    synth_cfg_call_dir(2_100, "f_huge")
}

fn synth_cfg_call_dir(block_count: usize, fn_name: &str) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join(format!("call_001_tid100_{}r_2ms", block_count * 2));
    fs::create_dir_all(&cd).unwrap();
    let base = 0x100000u64;
    let mut buf = vec![0u8; 272 * block_count * 2];
    for i in 0..block_count {
        let block_pc = base + (i as u64) * 8;
        let rows: [(u64, u32); 2] = [
            (block_pc, 0xd503201f), // nop
            (
                block_pc + 4,
                if i + 1 == block_count {
                    0xd65f03c0 // ret
                } else {
                    0x14000001 // b +4, observed target is next block head
                },
            ),
        ];
        for (j, (pc, inst)) in rows.iter().enumerate() {
            let off = (i * 2 + j) * 272;
            buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
            buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
            buf[off + 268..off + 272].copy_from_slice(&(*inst).to_le_bytes());
        }
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(
        cd.join("meta.json"),
        format!(
            r#"{{"records":{},"truncated":false,"known_offsets":{{"0x0":"{}"}}}}"#,
            block_count * 2,
            fn_name
        ),
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"pkg":"tst","method":"","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn cfg_svg_returns_ready_and_cache_when_dot_available() {
    let _guard = dot_env_lock().lock().await;
    std::env::remove_var("TRACEMIKU_DOT");
    let dot_available = std::process::Command::new("dot").arg("-V").output().is_ok();

    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=f_alpha")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    if !dot_available {
        assert_eq!(v["status"], "error");
        assert!(v["err"].as_str().unwrap_or("").contains("not found"));
        return;
    }

    assert_eq!(v["status"], "ready");
    assert_eq!(v["fn"], "f_alpha");
    assert_eq!(v["cached"], false);
    assert_eq!(v["block_count"].as_u64(), Some(1));
    assert!(v["total_block_count"].as_u64().unwrap_or(0) >= 1);
    assert!(
        v["svg"]
            .as_str()
            .is_some_and(|s| s.contains("<svg") && s.contains("insn_100100")),
        "expected graphviz SVG with instruction anchors: {v}"
    );

    let resp2 = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=f_alpha")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let v2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(v2["status"], "ready");
    assert_eq!(v2["cached"], true);
}

#[tokio::test]
async fn cfg_svg_unknown_fn_is_empty() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=does_not_exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "empty");
    assert_eq!(v["fn"], "does_not_exist");
    assert!(v["svg"].is_null());
}

#[tokio::test]
async fn cfg_svg_large_fn_returns_overview_without_dot() {
    let _guard = dot_env_lock().lock().await;
    std::env::set_var("TRACEMIKU_DOT", "/definitely/not/a/graphviz-dot");

    let (_tmp, call_dir) = synth_large_cfg_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=f_big")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    std::env::remove_var("TRACEMIKU_DOT");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "large");
    assert_eq!(v["fn"], "f_big");
    assert!(v["block_count"].as_u64().unwrap_or(0) > 180);
    assert!(
        v["svg"]
            .as_str()
            .is_some_and(|s| s.contains("<svg") && s.contains("hdr_b100000")),
        "expected lightweight overview SVG with block anchors: {v}"
    );
}

#[tokio::test]
async fn cfg_svg_edge_heavy_fn_returns_overview_without_dot() {
    let _guard = dot_env_lock().lock().await;
    std::env::set_var("TRACEMIKU_DOT", "/definitely/not/a/graphviz-dot");

    let (_tmp, call_dir) = synth_edge_heavy_cfg_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=f_edge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    std::env::remove_var("TRACEMIKU_DOT");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "large");
    assert_eq!(v["fn"], "f_edge");
    assert!(
        v["block_count"].as_u64().unwrap_or(usize::MAX as u64) < 120,
        "edge-heavy fixture should stay below the block threshold: {v}"
    );
    assert!(
        v["edge_count"].as_u64().unwrap_or(0) > 250,
        "edge-heavy fixture should trip the edge threshold: {v}"
    );
    assert!(
        v["svg"]
            .as_str()
            .is_some_and(|s| s.contains("<svg") && s.contains("hdr_b100004")),
        "expected lightweight overview SVG with block anchors: {v}"
    );
}

#[tokio::test]
async fn cfg_svg_auto_request_skips_large_cached_svg() {
    let _guard = dot_env_lock().lock().await;
    std::env::set_var("TRACEMIKU_DOT", "/definitely/not/a/graphviz-dot");

    let (_tmp, call_dir) = synth_large_cfg_call_dir();
    let state = tracemiku_server::AppState::load(call_dir).expect("load AppState");
    state.inner.cfg_svg_cache.lock().unwrap().insert(
        "f_big".to_string(),
        CfgSvgCached {
            svg: "<svg id=\"cached\"></svg>".to_string(),
            block_count: 190,
            total_block_count: 190,
        },
    );
    let app = tracemiku_server::routes::router(state);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=f_big")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "large");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=f_big&force=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    std::env::remove_var("TRACEMIKU_DOT");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["cached"], true);
}

#[tokio::test]
async fn cfg_svg_huge_fn_skips_overview_svg() {
    let _guard = dot_env_lock().lock().await;
    std::env::set_var("TRACEMIKU_DOT", "/definitely/not/a/graphviz-dot");

    let (_tmp, call_dir) = synth_huge_cfg_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=f_huge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    std::env::remove_var("TRACEMIKU_DOT");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "large");
    assert_eq!(v["fn"], "f_huge");
    assert!(v["block_count"].as_u64().unwrap_or(0) > 2_000);
    assert!(v["svg"].is_null());
}

#[tokio::test]
async fn cfg_svg_dot_failure_returns_error_json() {
    let _guard = dot_env_lock().lock().await;
    std::env::set_var("TRACEMIKU_DOT", "/definitely/not/a/graphviz-dot");

    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg-svg?fn=f_alpha")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    std::env::remove_var("TRACEMIKU_DOT");

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "error");
    assert!(
        v["err"]
            .as_str()
            .is_some_and(|s| s.contains("not found") || s.contains("failed")),
        "expected graphviz spawn error: {v}"
    );
}

#[tokio::test]
async fn cfg_returns_blocks_and_edges() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    let blocks = v["blocks"].as_array().expect("blocks array");
    assert!(!blocks.is_empty(), "synth trace must produce ≥1 block");

    let b0 = &blocks[0];
    assert!(b0["start_pc"].is_string() || b0["start_pc"].is_number());
    assert!(b0["executions"].is_number());
    assert!(b0["scc_id"].is_number());
}

#[tokio::test]
async fn cfg_block_with_known_fn_has_fn_name() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let blocks = v["blocks"].as_array().unwrap();

    let f_root_block = blocks.iter().find(|b| {
        b["start_pc"].as_str().unwrap_or("") == "0x100000"
            || b["start_pc"].as_u64() == Some(0x100000)
    });
    if let Some(b) = f_root_block {
        let name = b["fn_name"].as_str().unwrap_or("");
        assert!(
            name == "f" || name == "f_root",
            "fn_name should be f or f_root, got {name:?}"
        );
    }
}

#[tokio::test]
async fn cfg_empty_trace_no_blocks() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_0r_0ms");
    fs::create_dir_all(&cd).unwrap();
    fs::write(cd.join("trace.bin"), Vec::<u8>::new()).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":0}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/cfg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert!(v["blocks"].as_array().unwrap().is_empty());
    assert!(v["edges"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn idxs_for_block_returns_record_indices() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/idxs-for-block?pc=0x100000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["block"], "0x100000");
    assert_eq!(v["total"], 2);
    assert_eq!(v["truncated"], false);
    let idxs = v["idxs"].as_array().expect("idxs array");
    assert!(!idxs.is_empty(), "expected ≥1 record in block 0x100000");
    assert_eq!(idxs[0].as_u64(), Some(0));
}

#[tokio::test]
async fn idxs_for_block_near_prioritizes_closest_record() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/idxs-for-block?pc=0x100000&max_count=1&near=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["block"], "0x100000");
    assert_eq!(v["total"], 2);
    assert_eq!(v["truncated"], true);
    assert_eq!(
        v["idxs"].as_array().expect("idxs array")[0].as_u64(),
        Some(1)
    );
}

#[tokio::test]
async fn idxs_for_block_unknown_pc_404() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/idxs-for-block?pc=0xdeadbeef")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
