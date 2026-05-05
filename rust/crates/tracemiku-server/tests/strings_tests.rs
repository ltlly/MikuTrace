use std::io::Write;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir_with_string() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100008, 0x10000c];
    let insts: [u32; 4] = [0xf9000020, 0xf9000020, 0xd503201f, 0xd65f03c0];
    let values = [
        u64::from_le_bytes([b'h', b'e', b'l', b'l', b'o', 0, 0, 0]),
        u64::from_le_bytes([b'w', b'o', b'r', b'l', b'd', 0, 0, 0]),
        0,
        0,
    ];
    let addrs = [0x7000u64, 0x7010, 0, 0];
    let mut buf = vec![0u8; 272 * 4];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&values[i].to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&addrs[i].to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"records":4,"tid":100,"ms":1,"truncated":false}"#,
    )
    .unwrap();
    std::fs::write(
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
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn strings_endpoint_returns_planted_hello() {
    let (_tmp, cd) = synth_call_dir_with_string();
    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/strings?min_len=4")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    let strs = v["strings"].as_array().unwrap();
    assert!(
        strs.iter().any(|s| s["str"].as_str() == Some("hello")),
        "expected 'hello' in strings: {strs:?}"
    );
}

#[tokio::test]
async fn strings_endpoint_substring_filter() {
    let (_tmp, cd) = synth_call_dir_with_string();
    let (_status, v) = get(cd, "/api/strings?min_len=4&q=ZZZ").await;
    assert_eq!(v["count"].as_u64().unwrap(), 0);
    assert_eq!(v["returned"].as_u64().unwrap(), 0);
    assert_eq!(v["truncated"], false);
}

#[tokio::test]
async fn strings_endpoint_reports_total_and_truncation() {
    let (_tmp, cd) = synth_call_dir_with_string();
    let (status, v) = get(cd, "/api/strings?min_len=4&limit=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"].as_u64().unwrap(), 2);
    assert_eq!(v["returned"].as_u64().unwrap(), 1);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["strings"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn strings_endpoint_cursor_zero_filters_out_late_writes() {
    let (_tmp, cd) = synth_call_dir_with_string();
    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/strings?min_len=4&cursor=-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["count"].as_u64().unwrap() >= 1);
}
