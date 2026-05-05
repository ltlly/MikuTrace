//! Black-box tests for GET /api/idxs-for-pc.

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

    // 9 records, with intentional duplicate: pc 0x100000 at idx 0 AND idx 5.
    let pcs = [
        0x100000u64,
        0x100004,
        0x100100,
        0x100104,
        0x100008,
        0x100000,
        0x100204,
        0x100208,
        0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x94000040, 0xd503201f, 0xd65f03c0, 0x94000080, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":9,"tid":100,"ms":2,"truncated":false}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn idxs_for_pc_finds_duplicates() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/idxs-for-pc?pc=0x100000&cursor=3&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["pc"], "0x100000");
    assert_eq!(v["cursor"], 3);
    assert_eq!(v["before"], serde_json::json!([0]));
    assert_eq!(v["after"], serde_json::json!([5]));
    assert_eq!(v["total_before"], 1);
    assert_eq!(v["total_after"], 1);
    assert_eq!(v["before_capped"], false);
    assert_eq!(v["after_capped"], false);
}

#[tokio::test]
async fn idxs_for_pc_no_match_empty() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/idxs-for-pc?pc=0xdeadbeef&cursor=0&limit=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["before"], serde_json::json!([]));
    assert_eq!(v["after"], serde_json::json!([]));
    assert_eq!(v["total_before"], 0);
    assert_eq!(v["total_after"], 0);
}

#[tokio::test]
async fn idxs_for_pc_limit_caps_results() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/idxs-for-pc?pc=0x100000&cursor=10&limit=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["before"], serde_json::json!([]));
    assert_eq!(v["after"], serde_json::json!([]));
    assert_eq!(v["total_before"], 2);
    assert_eq!(v["total_after"], 0);
    assert_eq!(v["before_capped"], true);
    assert_eq!(v["after_capped"], false);
}

#[tokio::test]
async fn idxs_for_pc_default_cursor_zero() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/idxs-for-pc?pc=0x100000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["after"], serde_json::json!([0, 5]));
    assert_eq!(v["total_after"], 2);
    assert_eq!(v["total_before"], 0);
}
