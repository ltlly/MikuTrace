use std::fs;
use std::io::Write;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_query_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100008, 0x10000c];
    // mov x0, x1; str x0, [sp]; ldr x2, [sp]; ret
    let insts = [0xaa0103e0u32, 0xf90003e0, 0xf94003e2, 0xd65f03c0];
    let mut buf = vec![0u8; 272 * pcs.len()];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":4,"known_offsets":{"0x0":"f_query"}}"#,
    )
    .unwrap();
    fs::write(
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
async fn query_records_searches_asm_and_functions() {
    let (_tmp, cd) = synth_query_call_dir();
    let v = get_json(cd, "/api/query?kind=records&q=ldr&limit=10").await;
    assert_eq!(v["status"], "ready");
    assert_eq!(v["kind"], "records");
    assert_eq!(v["count"].as_u64(), Some(1));
    assert_eq!(v["rows"][0]["idx"].as_u64(), Some(2));
    assert_eq!(v["rows"][0]["func"], "f_query");
}

#[tokio::test]
async fn query_regs_returns_defs_and_uses_near_cursor() {
    let (_tmp, cd) = synth_query_call_dir();
    let v = get_json(cd, "/api/query?kind=regs&reg=x0&idx=2&limit=10").await;
    assert_eq!(v["status"], "ready");
    assert!(v["count"].as_u64().unwrap_or(0) >= 2, "{v}");
    let accesses = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["extra"]["access"].as_str())
        .collect::<Vec<_>>();
    assert!(accesses.contains(&"def"), "{v}");
    assert!(accesses.contains(&"use"), "{v}");
}

#[tokio::test]
async fn query_mem_returns_read_and_write_touches() {
    let (_tmp, cd) = synth_query_call_dir();
    let v = get_json(cd, "/api/query?kind=mem&addr=0x7000&len=8&idx=2&limit=10").await;
    assert_eq!(v["status"], "ready");
    let accesses = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["extra"]["access"].as_str())
        .collect::<Vec<_>>();
    assert!(accesses.contains(&"write"), "{v}");
    assert!(accesses.contains(&"read"), "{v}");
}

#[tokio::test]
async fn query_writes_filters_memory_writes() {
    let (_tmp, cd) = synth_query_call_dir();
    let v = get_json(cd, "/api/query?kind=writes&q=0x7000&len=8&idx=2&limit=10").await;
    assert_eq!(v["status"], "ready");
    assert_eq!(v["kind"], "writes");
    let accesses = v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| row["extra"]["access"].as_str())
        .collect::<Vec<_>>();
    assert!(!accesses.is_empty(), "{v}");
    assert!(accesses.iter().all(|access| *access == "write"), "{v}");
}

#[tokio::test]
async fn query_jni_returns_hook_events() {
    let (_tmp, cd) = synth_query_call_dir();
    fs::write(
        cd.join("jni_hooks.jsonl"),
        r#"{"id":"NewStringUTF","trace_idx":2,"tid":100,"value":"hello"}
{"id":"ReleaseStringUTFChars","trace_idx":3,"tid":100,"value":"hello"}
"#,
    )
    .unwrap();
    let v = get_json(cd, "/api/query?kind=jni&q=NewString&limit=10").await;
    assert_eq!(v["status"], "ready");
    assert_eq!(v["kind"], "jni");
    assert_eq!(v["count"].as_u64(), Some(1));
    assert_eq!(v["rows"][0]["type"], "event");
    assert_eq!(v["rows"][0]["id"], "NewStringUTF");
    assert_eq!(v["rows"][0]["idx"].as_u64(), Some(2));
}
