use std::io::Write;
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
        .join("call_001_tid100_4r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100008, 0x10000c];
    let insts: [u32; 4] = [
        0xf9000020, // str x0, [x1]
        0xf9400022, // ldr x2, [x1]
        0xd503201f, // nop
        0xd65f03c0, // ret
    ];
    let hello: u64 = u64::from_le_bytes([b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
    let x1: u64 = 0x7000;
    let mut buf = vec![0u8; 272 * 4];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&hello.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes());
        buf[off + 24..off + 32].copy_from_slice(&hello.to_le_bytes());
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

async fn get_json(call_dir: PathBuf, uri: &str) -> serde_json::Value {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn last_write_of_addr_reports_writer_context() {
    let (_tmp, cd) = synth_call_dir();
    let v = get_json(cd, "/api/last-write-of-addr?addr=0x7000&before_idx=3").await;
    assert_eq!(v["status"], "found");
    assert_eq!(v["writer_idx"], 0);
    assert_eq!(v["writer_pc"], "0x100000");
    assert_eq!(v["src_reg"], "x0");
    assert_eq!(v["src_value"], "0x6f6c6c6568");
    assert_eq!(v["writes_before"], 1);
}

#[tokio::test]
async fn touching_addr_splits_reads_and_writes_around_cursor() {
    let (_tmp, cd) = synth_call_dir();
    let v = get_json(cd, "/api/idxs-touching-addr?addr=0x7000&cursor=1&limit=10").await;
    assert_eq!(v["status"], "ready");
    assert_eq!(v["before"], serde_json::json!([{"idx":0,"kind":"w"}]));
    assert_eq!(v["after"], serde_json::json!([{"idx":1,"kind":"r"}]));
    assert_eq!(v["total_before"], 1);
    assert_eq!(v["total_after"], 1);
}

#[tokio::test]
async fn touching_range_counts_overlapping_reads_and_writes() {
    let (_tmp, cd) = synth_call_dir();
    let v = get_json(
        cd,
        "/api/idxs-touching-range?addr=0x7004&size=4&cursor=1&limit=10",
    )
    .await;
    assert_eq!(v["status"], "ready");
    assert_eq!(v["writers_before"], serde_json::json!([0]));
    assert_eq!(v["readers_after"], serde_json::json!([1]));
    assert_eq!(v["writers_total"], 1);
    assert_eq!(v["readers_total"], 1);
}

#[tokio::test]
async fn mem_writes_in_range_reports_write_details() {
    let (_tmp, cd) = synth_call_dir();
    let v = get_json(
        cd,
        "/api/mem-writes-in-range?idx_lo=0&idx_hi=3&addr_lo=0x7000&addr_hi=0x7008&max=5",
    )
    .await;
    assert_eq!(v["idx_range"], serde_json::json!([0, 3]));
    assert_eq!(v["matched"], 1);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["writes"][0]["idx"], 0);
    assert_eq!(v["writes"][0]["dst_addr"], "0x7000");
    assert_eq!(v["writes"][0]["src_reg"], "x0");
}

#[tokio::test]
async fn mem_writes_in_range_matches_overlapping_write() {
    let (_tmp, cd) = synth_call_dir();
    let v = get_json(
        cd,
        "/api/mem-writes-in-range?idx_lo=0&idx_hi=3&addr_lo=0x7004&addr_hi=0x7008&max=5",
    )
    .await;
    assert_eq!(v["matched"], 1);
    assert_eq!(v["writes"][0]["idx"], 0);
    assert_eq!(v["writes"][0]["dst_addr"], "0x7000");
}

#[tokio::test]
async fn find_mem_pattern_finds_latest_bytes() {
    let (_tmp, cd) = synth_call_dir();
    let v = get_json(cd, "/api/find-mem-pattern?bytes_hex=68656c6c6f&max=5").await;
    assert_eq!(v["pattern"], "68656c6c6f");
    assert_eq!(v["count"], 1);
    assert_eq!(v["hits"][0]["addr"], "0x7000");
    assert_eq!(v["hits"][0]["first_idx"], 1);
}
