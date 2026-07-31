//! Contract test for the field-at route.
//!
//! field-at was a sentinel stub: it always returned `hit: false` regardless
//! of input, because real struct-field resolution needs the type database
//! (decompiler territory). A route that can never hit is a trap for AI
//! consumers — the honest shape is a 404 (route removed).

use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
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
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

async fn get_status(call_dir: PathBuf, uri: &str) -> StatusCode {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn field_at_route_is_removed_not_sentinel() {
    let (_tmp, cd) = synth_call_dir();
    let status = get_status(cd, "/api/field-at?pc=0x100000&reg=x0&offset=0").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "field-at must not be a route: a sentinel that always returns hit:false \
         misleads AI consumers into trusting a field that never resolves"
    );
}
