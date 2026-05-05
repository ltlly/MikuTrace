use std::fs;
use std::io::Write;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn synth_call_dir_with_known_offsets() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [
        0x100000u64,
        0x100004,
        0x100100,
        0x100104,
        0x100008,
        0x100200,
        0x100204,
        0x100208,
        0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x94000040, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
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
    fs::write(cd.join("meta.json"),
              r#"{"records":9,"truncated":false,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn functions_returns_known_offsets_as_symbol_source() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/functions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let funcs = v["functions"].as_array().expect("functions array");
    assert!(funcs.len() >= 3, "expected ≥3 fns, got {}", funcs.len());

    assert!(v["counts"]["symbol"].as_u64().unwrap() >= 3);
    assert_eq!(v["counts"]["trace-ir"].as_u64().unwrap_or(0), 0);
    assert_eq!(v["counts"]["bn"].as_u64().unwrap_or(0), 0);

    let f0 = &funcs[0];
    assert!(f0["id"].is_string());
    assert!(f0["name"].is_string());
    assert!(f0["source"].is_string());

    let names: Vec<&str> = funcs.iter().filter_map(|f| f["name"].as_str()).collect();
    assert!(
        names.contains(&"f_alpha"),
        "expected f_alpha in names, got {names:?}"
    );
    assert!(names.contains(&"f_beta"));

    let f_alpha = funcs
        .iter()
        .find(|f| f["name"] == "f_alpha")
        .expect("f_alpha");
    assert!(
        f_alpha["blocks"].as_u64().unwrap_or(0) > 0,
        "f_alpha should inherit CFG block count"
    );
    assert!(
        f_alpha["records"].as_u64().unwrap_or(0) > 0,
        "f_alpha should inherit CFG execution count"
    );

    let f_beta = funcs
        .iter()
        .find(|f| f["name"] == "f_beta")
        .expect("f_beta");
    assert!(
        f_beta["blocks"].as_u64().unwrap_or(0) > 0,
        "f_beta should inherit CFG block count"
    );
    assert!(
        f_beta["records"].as_u64().unwrap_or(0) > 0,
        "f_beta should inherit CFG execution count"
    );
}

#[tokio::test]
async fn functions_empty_trace_yields_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_0r_0ms");
    fs::create_dir_all(&cd).unwrap();
    fs::write(cd.join("trace.bin"), Vec::<u8>::new()).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":0}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let app = tracemiku_server::build_router(cd).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/functions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["functions"].as_array().unwrap().is_empty());
    assert_eq!(v["counts"]["symbol"].as_u64().unwrap(), 0);
}

#[tokio::test]
async fn last_write_of_reg_finds_last_def() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_2r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 2];
    // idx 0: pc=0x100000 mov x0, x1 (0xaa0103e0)
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xaa0103e0u32.to_le_bytes());
    // idx 1: pc=0x100004 mov x0, x2 (0xaa0203e0)
    buf[272..280].copy_from_slice(&0x100004u64.to_le_bytes());
    buf[272 + 268..272 + 272].copy_from_slice(&0xaa0203e0u32.to_le_bytes());
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":2}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let app = tracemiku_server::build_router(cd).expect("build router");

    // last write of x0 BEFORE idx 5 → idx 1
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/last-write-of-reg?reg=x0&before=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 1);
    assert_eq!(v["status"], "ready");

    // last write of x0 BEFORE idx 1 → idx 0
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/last-write-of-reg?reg=x0&before=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 0);

    // Python web compatibility: old UI sends cursor= instead of before=.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/last-write-of-reg?reg=x0&cursor=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 1);

    // x99 has no defs → null
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/last-write-of-reg?reg=x99&before=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["idx"].is_null(), "non-existent reg should return null");
}
