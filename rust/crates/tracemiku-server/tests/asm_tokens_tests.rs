use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());

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
async fn asm_tokens_reports_not_ready_without_bn_backend() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("TRACEMIKU_BN_SO");
    std::env::remove_var("TRACEMIKU_BN_SIDECAR");
    let (_tmp, cd) = synth_call_dir();
    let app = tracemiku_server::build_router(cd).expect("build router");
    drop(_guard);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/asm-tokens-for-pcs?pcs=0x100000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ready"], false);
    assert_eq!(v["status"], "not-ready");
    assert_eq!(v["tokens"], serde_json::json!({}));
}

#[tokio::test]
async fn asm_tokens_forwards_to_bn_sidecar() {
    let (tmp, cd) = synth_call_dir();
    let sidecar = tmp.path().join("fake_asm_sidecar.py");
    fs::write(
        &sidecar,
        r#"#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    params = req.get("params") or {}
    if method == "asm_tokens":
        pcs = params.get("pcs") or []
        result = {
            "ok": True,
            "ready": True,
            "status": "ok",
            "tokens": {
                hex(int(pcs[0])): [
                    {"t": "mov", "c": "mnem", "a": None},
                    {"t": " x0", "c": "txt", "a": None},
                    {"t": "x1", "c": "reg", "a": None},
                ]
            },
        }
    else:
        result = {"ok": False, "ready": True, "error": f"unexpected method {method}"}
    print(json.dumps({"id": req.get("id"), "result": result}), flush=True)
"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&sidecar).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&sidecar, perms).unwrap();
    }

    let _guard = ENV_LOCK.lock().unwrap();
    std::env::set_var("TRACEMIKU_BN_SO", tmp.path().join("libt.so"));
    std::env::set_var("TRACEMIKU_BN_SIDECAR", &sidecar);
    let app = tracemiku_server::build_router(cd).expect("build router");
    std::env::remove_var("TRACEMIKU_BN_SO");
    std::env::remove_var("TRACEMIKU_BN_SIDECAR");
    drop(_guard);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/asm-tokens-for-pcs?pcs=0x100000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["ready"], true);
    assert_eq!(v["status"], "ok");
    assert_eq!(v["tokens"]["0x100000"][0]["c"], "mnem");
    assert_eq!(v["tokens"]["0x100000"][2]["t"], "x1");
}
