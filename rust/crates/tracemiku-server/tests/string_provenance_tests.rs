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
        .join("call_001_tid100_2r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let specs: [(u64, u32, u64, u64); 2] = [
        (0x100000, 0xf9000020, 0x41, 0),    // str x0,[x1]
        (0x100004, 0xf9400022, 0x41, 0x41), // ldr x2,[x1]; x2 in next-state approximation
    ];
    let mut buf = vec![0u8; 272 * specs.len()];
    for (i, (pc, inst, x0, x2)) in specs.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&x0.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 24..off + 32].copy_from_slice(&x2.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":2}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

async fn get(call_dir: PathBuf, uri: &str) -> (StatusCode, serde_json::Value) {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn string_provenance_reports_writers_and_readers() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/string-provenance?addr=0x7000&length=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["addr"], "0x7000");
    assert_eq!(v["length"], 2);
    assert_eq!(v["bytes"][0]["addr"], "0x7000");
    assert_eq!(v["bytes"][0]["byte"], 65);
    assert_eq!(v["bytes"][0]["current_idx"], 0);
    assert_eq!(v["bytes"][0]["current_writer_idx"], 0);
    assert_eq!(v["bytes"][0]["writers"], serde_json::json!([0]));
    assert_eq!(v["bytes"][0]["readers"], serde_json::json!([1]));
    assert_eq!(v["bytes"][0]["writers_total"], 1);
    assert_eq!(v["bytes"][0]["readers_total"], 1);
}

#[tokio::test]
async fn string_provenance_bad_addr_is_400() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _v) = get(cd, "/api/string-provenance?addr=bogus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
