use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn openapi_json_lists_current_paths() {
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["openapi"], "3.0.3");
    assert!(v["paths"]["/api/bg-status"]["get"].is_object());
    assert!(v["paths"]["/api/decomp-status"]["get"].is_object());
    assert!(v["paths"]["/api/mem-writes-in-range"]["get"].is_object());
    assert!(v["paths"]["/api/hash-input-search"]["post"].is_object());
    assert!(v["paths"]["/ws/jobs"]["get"].is_object());
}

#[tokio::test]
async fn python_web_compat_status_endpoints_are_available() {
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");

    for uri in ["/api/bg-status", "/api/decomp-status"] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        if uri == "/api/bg-status" {
            assert_eq!(v["cfg"]["status"], "ready");
            assert_eq!(v["index"]["status"], "ready");
            assert_eq!(v["mem"]["status"], "ready");
            assert!(v["decomp"]["status"].is_string());
        } else {
            assert!(v["status"].is_string());
            assert!(v.get("so_path").is_some());
        }
    }
}

#[tokio::test]
async fn missing_api_route_returns_json_404() {
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/definitely-missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"], "unknown api endpoint");
    assert_eq!(v["path"], "/api/definitely-missing");
}

#[tokio::test]
async fn ws_jobs_requires_websocket_upgrade() {
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ws/jobs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
