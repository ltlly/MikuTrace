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
    assert_eq!(fns.len(), 1, "skeleton emits exactly 1 root FuncIR: {v}");
    let f0 = &fns[0];
    assert_eq!(f0["id"], "trace:F0");
    assert_eq!(f0["source"], "trace-ir");
    assert_eq!(f0["trace_ir_id"], "F0");
    assert_eq!(f0["entry_idx"], 0);
    assert_eq!(f0["exit_idx"], 2);
    assert_eq!(f0["blocks"], 0);
    assert_eq!(f0["calls"], 0);
    assert!(v["vm_candidates"].as_array().unwrap().is_empty());
    assert!(
        v["summary_md"].as_str().unwrap().contains("trace: 3 records"),
        "summary_md should mention record count: {v}"
    );
}
