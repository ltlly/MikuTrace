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
    let pcs = [0x100000u64, 0x100004];
    let insts = [0xf9401809u32, 0xd63f0120]; // ldr x9,[x0,#0x30]; blr x9
    let mut buf = vec![0u8; 272 * 2];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        for (reg_i, value) in [0x1111u64, 0x2222, 0x3333, 0x4444, 0x5555]
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
        r#"{"records":2,"known_offsets":{"0x0":"f_root"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

async fn get(call_dir: PathBuf, uri: &str) -> (StatusCode, Option<serde_json::Value>) {
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json = (!body.is_empty()).then(|| serde_json::from_slice(&body).unwrap());
    (status, json)
}

#[tokio::test]
async fn jobj_history_filters_matching_jobject_args() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/jobj-history?jobject=0x2222&start=0&end=2&max=5").await;
    let v = v.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["jobject"], "0x2222");
    assert_eq!(v["start"], 0);
    assert_eq!(v["end"], 2);
    assert_eq!(v["count"], 1);
    assert_eq!(v["hits"][0]["idx"], 1);
    assert_eq!(v["hits"][0]["jni_fn"], "FindClass");
    assert_eq!(v["hits"][0]["vtable_offset"], "0x30");
    assert_eq!(v["hits"][0]["match_arg"], "x1");
    assert_eq!(v["hits"][0]["args"]["x2"], "0x3333");
}

#[tokio::test]
async fn jobj_history_returns_empty_when_object_is_absent() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "/api/jobj-history?jobject=0x9999").await;
    let v = v.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["count"], 0);
    assert!(v["hits"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn jobj_history_rejects_invalid_jobject() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _) = get(cd, "/api/jobj-history?jobject=bogus").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
