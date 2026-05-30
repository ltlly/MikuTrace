use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::fs;
use tower::ServiceExt;

fn synth_trace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 3] = [0x100000, 0x100004, 0x100008];
    let x0s: [u64; 3] = [0, 7, 7];
    let insts: [u32; 3] = [0xd503201f, 0xd503201f, 0xd65f03c0]; // nop; nop; ret
    let mut buf = vec![0u8; 272 * 3];
    for i in 0..3 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pcs[i].to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&x0s[i].to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&insts[i].to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
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
        .join("call_001_tid1_3r_1ms")
}

#[tokio::test]
async fn watchpoints_route_reports_register_changes() {
    let dir = synth_trace();
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/watchpoints?kind=reg-change&reg=x0&limit=10")
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
    assert_eq!(v["status"], "ready");
    assert!(v["hits"].as_array().unwrap().iter().any(|hit| {
        hit["idx"] == 1 && hit["kind"] == "reg_change" && hit["value"] == 7 && hit["previous"] == 0
    }));
}

#[tokio::test]
async fn watchpoints_route_reports_register_equals_after_cursor() {
    let dir = synth_trace();
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/watchpoints?kind=reg-equals&reg=x0&value=7&cursor=2&limit=10")
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
    assert_eq!(v["returned"], 1);
    assert_eq!(v["hits"][0]["idx"], 2);
    assert_eq!(v["hits"][0]["kind"], "reg_equals");
}

#[tokio::test]
async fn watchpoints_route_rejects_missing_register() {
    let dir = synth_trace();
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/watchpoints?kind=reg-change")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
