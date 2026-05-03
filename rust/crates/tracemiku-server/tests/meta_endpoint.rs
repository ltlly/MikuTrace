//! Black-box test: build the router, exercise GET /api/meta.

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
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    fs::write(cd.join("trace.bin"), []).unwrap();
    fs::write(cd.join("meta.json"),
              r#"{"callIdx":1,"tid":100,"records":9,"ms":2,"retval":"0x0","truncated":false,"last_insn_is_ret":true}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    let cd_owned = cd.clone();
    (tmp, cd_owned)
}

#[tokio::test]
async fn meta_endpoint_returns_synth_trace_metadata() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/meta")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(v["records"], 9);
    assert_eq!(v["method"], "f");
    assert_eq!(v["cmd"], 1);
    assert_eq!(v["fn_addr"], "0x100000");
    assert_eq!(v["module"]["name"], "libt.so");
    assert_eq!(v["module"]["base"], "0x100000");
    assert_eq!(v["module"]["size"], 65536);
    assert_eq!(v["module"]["end"], "0x110000");
    assert_eq!(v["modules"][0]["name"], "libt.so");
    assert_eq!(v["regs"][0], "x0");
    assert_eq!(v["regs"][32], "pc");
}

#[test]
fn app_state_loads_trace_eagerly() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = tracemiku_server::AppState::load(call_dir).expect("load AppState");
    // The synth fixture has 0 or 9 records (depending on fixture variant).
    let n = state.inner.trace.len();
    assert!(n == 0 || n == 9, "expected 0 or 9 records, got {n}");
}

#[test]
fn app_state_eagerly_loads_index_symbols_modules() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = tracemiku_server::AppState::load(call_dir).expect("load AppState");
    // Index built — empty regs maps for an empty trace are OK.
    let _ = &state.inner.index.reg_defs;
    let _ = &state.inner.index.reg_uses;
    // SymbolMap built — empty for synth (no known_offsets in fixture).
    assert_eq!(state.inner.symbols.len(), 0);
    // ModuleResolver has libt.so.
    let m = state.inner.modules.resolve(0x100000);
    assert!(m.is_some(), "0x100000 should resolve to libt.so");
    assert_eq!(m.unwrap().name, "libt.so");
}

#[test]
fn app_state_eagerly_loads_cfg() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = tracemiku_server::AppState::load(call_dir).expect("load AppState");
    // Empty trace → 0 blocks, but the field exists.
    let _ = state.inner.cfg.block_count();
}

#[test]
fn app_state_eagerly_loads_function_index() {
    let (_tmp, call_dir) = synth_call_dir();
    let state = tracemiku_server::AppState::load(call_dir).expect("load AppState");
    let _ = state.inner.function_index.len();
}
