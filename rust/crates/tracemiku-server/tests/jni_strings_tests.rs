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
    let pcs = [0x100000u64, 0x100004, 0x100008];
    let insts = [0xf9000043u32, 0xf942a809, 0xd63f0120];
    let hello = u64::from_le_bytes([b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
    let mut buf = vec![0u8; 272 * 3];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        for (reg_i, value) in [0x1111u64, 0x2222, 0x7000, hello, 0x4444]
            .into_iter()
            .enumerate()
        {
            let roff = off + 8 + reg_i * 8;
            buf[roff..roff + 8].copy_from_slice(&value.to_le_bytes());
        }
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":3,"known_offsets":{"0x0":"f_root"}}"#,
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
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn jni_strings_recovers_observed_input_buffer() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/jni-strings?max=5&max_len=16").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 1);
    assert_eq!(v["with_observed_string"], 1);
    assert_eq!(v["without_observed_string"], 0);
    assert_eq!(v["hits"][0]["idx"], 2);
    assert_eq!(v["hits"][0]["jni_fn"], "ReleaseStringUTFChars");
    assert_eq!(v["hits"][0]["arg_name"], "x2");
    assert_eq!(v["hits"][0]["direction"], "in");
    assert_eq!(v["hits"][0]["buffer_addr"], "0x7000");
    assert_eq!(v["hits"][0]["observed_bytes"], 6);
    assert_eq!(v["hits"][0]["string"], "hello");
}

#[tokio::test]
async fn jni_strings_max_zero_returns_all_hits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/jni-strings?max=0").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 1);
}
