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
        .join("call_001_tid100_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let specs: [(u64, u32, u64); 3] = [
        (0x100000, 0xf9000020, 0x41), // str x0,[x1], x0='A'
        (0x100004, 0xf9000020, 0x42), // str x0,[x1], x0='B'
        (0x100008, 0xd65f03c0, 0x42),
    ];
    let mut buf = vec![0u8; 272 * specs.len()];
    for (i, (pc, inst, x0)) in specs.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&x0.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
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
async fn reg_timeline_reports_distinct_values() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/reg-timeline?reg=x0&start=0&end=3").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["reg"], "x0");
    assert_eq!(v["count"], 2);
    assert_eq!(v["points"][0]["value"], "0x41");
    assert_eq!(v["points"][1]["idx"], 1);
}

#[tokio::test]
async fn reg_timeline_unknown_reg_is_400() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _v) = get(cd, "/api/reg-timeline?reg=bogus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mem_diff_compares_idx_minus_one_to_idx() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/mem-diff?idx=1&addr=0x7000&size=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["idx"], 1);
    assert_eq!(v["changed_count"], 1);
    assert_eq!(v["bytes"][0]["before"], 65);
    assert_eq!(v["bytes"][0]["after"], 66);
    assert_eq!(v["bytes"][1]["changed"], false);
}
