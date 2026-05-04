//! Black-box tests for GET /api/search.

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
        .join("call_001_tid100_5r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let rows: [(u64, u32); 5] = [
        (0x100000, 0xd503201f), // nop
        (0x100004, 0xd65f03c0), // ret
        (0x100000, 0xd503201f), // nop at repeated PC
        (0x100008, 0xd65f03c0), // ret at another PC
        (0x100004, 0xd65f03c0), // ret at repeated PC
    ];
    let mut buf = vec![0u8; 272 * rows.len()];
    for (i, (pc, inst)) in rows.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
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
async fn search_returns_hits_in_trace_order() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/search?pattern=ret&max_results=10").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 3);
    assert_eq!(
        v["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["idx"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 3, 4]
    );
    assert_eq!(v["hits"][0]["asm"], "ret");
}

#[tokio::test]
async fn search_caps_returned_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/search?pattern=ret&max_results=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 2);
    assert_eq!(
        v["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["idx"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
}

#[tokio::test]
async fn search_no_hit_returns_empty() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/search?pattern=does_not_exist&max_results=10").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 0);
    assert_eq!(v["hits"], serde_json::json!([]));
}
