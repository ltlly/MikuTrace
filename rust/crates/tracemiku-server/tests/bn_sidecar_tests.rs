use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::fs;
use std::sync::Mutex;
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn synth_trace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 3] = [0x100000, 0x100004, 0x100008];
    let insts: [u32; 3] = [0xaa0103e0, 0xf9000020, 0xd65f03c0];
    let mut buf = vec![0u8; 272 * 3];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
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
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

#[tokio::test]
async fn bn_status_reports_unconfigured_without_env() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("TRACEMIKU_BN_SO");
    std::env::remove_var("TRACEMIKU_BN_SIDECAR");
    let dir = synth_trace();
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    drop(_guard);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/bn-sidecar/status")
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
    assert_eq!(v["configured"], false);
    assert_eq!(v["ready"], false);
}

#[tokio::test]
async fn hlil_and_bn_cfg_endpoints_degrade_when_sidecar_is_absent() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("TRACEMIKU_BN_SO");
    std::env::remove_var("TRACEMIKU_BN_SIDECAR");
    let dir = synth_trace();
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    drop(_guard);
    for uri in [
        "/api/hlil-for-pc?pc=0x100000",
        "/api/hlil-for-fn?fn_id=trace:F0",
        "/api/bn-cfg-for-pc?pc=0x100000",
        "/api/bn-cfg-svg-for-pc?pc=0x100000",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["ready"], false, "{uri}: {v}");
        assert!(v.get("error").is_some(), "{uri}: {v}");
    }
}

#[tokio::test]
async fn hlil_for_fn_rejects_unknown_trace_fn() {
    let _guard = ENV_LOCK.lock().unwrap();
    std::env::remove_var("TRACEMIKU_BN_SO");
    std::env::remove_var("TRACEMIKU_BN_SIDECAR");
    let dir = synth_trace();
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    drop(_guard);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/hlil-for-fn?fn_id=trace:F99")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn hlil_for_pc_adds_current_line_index() {
    let dir = synth_trace();
    let sidecar = dir.path().join("fake_hlil_sidecar.py");
    fs::write(
        &sidecar,
        r#"#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    if method == "hlil_for":
        result = {
            "ok": True,
            "ready": True,
            "fn": {"name": "bn_root", "start": 1048576, "end": 1048588},
            "lines": [
                {"pc": "0x100000", "text": "a", "tokens": []},
                {"pc": "0x100004", "text": "b", "tokens": []},
                {"pc": "0x100008", "text": "c", "tokens": []},
            ],
            "vars": [],
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
    std::env::set_var("TRACEMIKU_BN_SO", dir.path().join("libt.so"));
    std::env::set_var("TRACEMIKU_BN_SIDECAR", &sidecar);
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    std::env::remove_var("TRACEMIKU_BN_SO");
    std::env::remove_var("TRACEMIKU_BN_SIDECAR");
    drop(_guard);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/hlil-for-pc?pc=0x100004")
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
    assert_eq!(v["current_line_idx"], 1);
    assert_eq!(v["pc"], "0x100004");
    assert_eq!(v["status"], "ok");
}

#[tokio::test]
async fn functions_merges_bn_entries_when_sidecar_is_ready() {
    let dir = synth_trace();
    let sidecar = dir.path().join("fake_bn_sidecar.py");
    fs::write(
        &sidecar,
        r#"#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    if method == "functions":
        result = {
            "ok": True,
            "ready": True,
            "functions": [{"start": 1048576, "name": "bn_root"}],
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
    std::env::set_var("TRACEMIKU_BN_SO", dir.path().join("libt.so"));
    std::env::set_var("TRACEMIKU_BN_SIDECAR", &sidecar);
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    std::env::remove_var("TRACEMIKU_BN_SO");
    std::env::remove_var("TRACEMIKU_BN_SIDECAR");
    drop(_guard);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/functions")
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
    assert_eq!(v["counts"]["bn"], 1);
    assert!(
        v["functions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "bn:0x100000" && f["can_bn_hlil"] == true),
        "{v}"
    );
}

#[tokio::test]
async fn bn_cfg_for_pc_forwards_mode_and_timeout_to_sidecar() {
    let dir = synth_trace();
    let sidecar = dir.path().join("fake_bn_cfg_sidecar.py");
    fs::write(
        &sidecar,
        r#"#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    req = json.loads(line)
    method = req.get("method")
    params = req.get("params") or {}
    if method == "cfg_for":
        mode = params.get("mode")
        timeout = params.get("timeout")
        result = {
            "ok": True,
            "ready": True,
            "mode": mode,
            "timeout": timeout,
            "blocks": [],
            "edges": [],
            "svg": f"mode={mode};timeout={timeout}",
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
    std::env::set_var("TRACEMIKU_BN_SO", dir.path().join("libt.so"));
    std::env::set_var("TRACEMIKU_BN_SIDECAR", &sidecar);
    let app = tracemiku_server::build_router(call_dir(&dir)).expect("router builds");
    std::env::remove_var("TRACEMIKU_BN_SO");
    std::env::remove_var("TRACEMIKU_BN_SIDECAR");
    drop(_guard);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/bn-cfg-for-pc?pc=0x100000&mode=llil")
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
    assert_eq!(v["mode"], "llil");

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/bn-cfg-svg-for-pc?pc=0x100000&mode=hlil&timeout=17")
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
    assert_eq!(v["svg"], "mode=hlil;timeout=17");
}
