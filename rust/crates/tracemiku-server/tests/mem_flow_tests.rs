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
        (0x100000, 0xf9000020, 0x41), // str x0,[x1]
        (0x100004, 0xf9000020, 0x42), // str x0,[x1]
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

fn synth_many_write_call_dir(
    record_count: usize,
    addr_groups: usize,
) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join(format!("call_001_tid100_{record_count}r_1ms"));
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * record_count];
    for i in 0..record_count {
        let off = i * 272;
        let pc = 0x100000u64 + (i as u64 * 4);
        let x0 = (i & 0xff) as u64;
        let x1 = 0x7000u64 + ((i % addr_groups) as u64 * 8);
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&x0.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xf9000020u32.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        format!(r#"{{"records":{record_count}}}"#),
    )
    .unwrap();
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
async fn mem_flow_returns_byte_event_history() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/mem-flow?addr=0x7000&count=1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["addr"], "0x7000");
    assert_eq!(v["count"], 1);
    assert_eq!(v["bytes"][0]["total"], 2);
    assert_eq!(v["bytes"][0]["events"][0]["idx"], 0);
    assert_eq!(v["bytes"][0]["events"][0]["byte"], 65);
    assert_eq!(v["bytes"][0]["events"][0]["kind"], "w");
    assert_eq!(v["bytes"][0]["events"][0]["pc"], "0x100000");
    assert_eq!(v["bytes"][0]["events"][0]["rel"], "0x0");
}

#[tokio::test]
async fn mem_flow_filters_and_caps_newest_events() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(
        cd,
        "/api/mem-flow?addr=0x7000&count=1&idx_lo=0&idx_hi=2&writers_only=true&events_per_byte=1",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["bytes"][0]["total"], 2);
    assert_eq!(v["bytes"][0]["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["bytes"][0]["events"][0]["idx"], 1);
    assert_eq!(v["bytes"][0]["events"][0]["byte"], 66);
}

#[tokio::test]
async fn mem_flow_caps_total_returned_events() {
    let (_tmp, cd) = synth_many_write_call_dir(10_080, 21);
    let (status, v) = get(
        cd,
        "/api/mem-flow?addr=0x7000&count=168&events_per_byte=500",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["events_returned"], 3_000);
    assert_eq!(v["truncated"], true);
    let returned: usize = v["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["events"].as_array().unwrap().len())
        .sum();
    assert_eq!(returned, 3_000);
}

#[tokio::test]
async fn mem_writes_in_range_filters_by_idx_addr_and_src_byte() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(
        cd,
        "/api/mem-writes-in-range?idx_lo=0&idx_hi=2&addr_lo=0x7000&addr_hi=0x7001&src_byte=0x42&max=10",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["idx_range"][0], 0);
    assert_eq!(v["idx_range"][1], 2);
    assert_eq!(v["matched"], 1);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["writes"][0]["idx"], 1);
    assert_eq!(v["writes"][0]["pc"], "0x100004");
    assert_eq!(v["writes"][0]["dst_addr"], "0x7000");
    assert_eq!(v["writes"][0]["src_reg"], "x0");
    assert_eq!(v["writes"][0]["src_value"], "0x42");
    assert_eq!(v["writes"][0]["byte0"], 66);
}

#[tokio::test]
async fn mem_writes_in_range_bad_filter_is_400() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _v) = get(cd, "/api/mem-writes-in-range?idx_lo=0&src_byte=bogus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn mem_flow_bad_addr_is_400() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _v) = get(cd, "/api/mem-flow?addr=bogus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
