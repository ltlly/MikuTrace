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

fn synth_multi_so_cross_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100100, 0x100004, 0x200100];
    let insts: [u32; 4] = [
        0x94000040, // bl 0x100100, same module offset 0x100
        0xd65f03c0, // ret
        0x9404003f, // bl 0x200100, helper module offset 0x100
        0xd65f03c0, // ret
    ];
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
    fs::write(cd.join("meta.json"), r#"{"records":4,"truncated":false}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{
            "pkg":"tst",
            "method":"f",
            "cmd":1,
            "module":{"name":"libmain.so","base":"0x100000","size":4096,"end":"0x101000"},
            "modules":[
                {"name":"libmain.so","base":"0x100000","size":4096,"end":"0x101000"},
                {"name":"libhelper.so","base":"0x200000","size":4096,"end":"0x201000"}
            ],
            "fn_addr":"0x100000"
        }"#,
    )
    .unwrap();
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
async fn functions_disambiguates_auto_symbols_across_modules() {
    let (_tmp, call_dir) = synth_multi_so_cross_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .clone()
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
    let sub_100: Vec<&serde_json::Value> =
        funcs.iter().filter(|f| f["name"] == "sub_100").collect();
    assert_eq!(
        sub_100.len(),
        2,
        "expected one sub_100 per module, got {funcs:?}"
    );
    assert!(
        sub_100.iter().all(|f| f["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("symaddr:"))),
        "duplicate auto symbols should use address ids: {sub_100:?}"
    );
    let modules: Vec<&str> = sub_100
        .iter()
        .filter_map(|f| f["module"].as_str())
        .collect();
    assert!(modules.contains(&"libmain.so"));
    assert!(modules.contains(&"libhelper.so"));
    assert!(sub_100
        .iter()
        .all(|f| f["entry_rel"].as_u64() == Some(0x100)));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/records?start=3&count=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let row = &v["records"][0];
    assert_eq!(row["module"], "libhelper.so");
    assert_eq!(row["rel"], "0x100");
    assert_eq!(row["func"], "sub_100");
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

#[tokio::test]
async fn next_use_of_reg_finds_next_use() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_3r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 3];
    let pcs = [0x100000u64, 0x100004, 0x100008];
    let insts = [
        0xaa0103e0u32, // mov x0, x1
        0xaa0003e2u32, // mov x2, x0
        0xaa0003e3u32, // mov x3, x0
    ];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        if i == 1 {
            buf[off + 8..off + 16].copy_from_slice(&0x1111u64.to_le_bytes());
        } else if i == 2 {
            buf[off + 8..off + 16].copy_from_slice(&0x2222u64.to_le_bytes());
        }
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let app = tracemiku_server::build_router(cd).expect("build router");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/next-use-of-reg?reg=x0&after=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 1);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["value"], "0x1111");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/next-use-of-reg?reg=x0&after=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 2);
    assert_eq!(v["value"], "0x2222");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/next-use-of-reg?reg=w0&after=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 1);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/next-use-of-reg?reg=x0&after=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        v["idx"].is_null(),
        "no use after the last x0 use should return null"
    );

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/next-use-of-reg?reg=x0&cursor=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/next-use-of-reg?reg=x99&after=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v["idx"].is_null(), "non-existent reg should return null");
}

#[tokio::test]
async fn reg_flow_routes_normalize_fp_lr_aliases() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_2ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 4];
    let insts = [
        0xaa0003fdu32, // mov x29, x0
        0xaa1d03e2u32, // mov x2, x29
        0xaa0003feu32, // mov x30, x0
        0xaa1e03e2u32, // mov x2, x30
    ];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + i as u64 * 4).to_le_bytes());
        if i == 1 {
            buf[off + 240..off + 248].copy_from_slice(&0x2929u64.to_le_bytes());
        } else if i == 3 {
            buf[off + 248..off + 256].copy_from_slice(&0x3030u64.to_le_bytes());
        }
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let app = tracemiku_server::build_router(cd).expect("build router");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/last-write-of-reg?reg=x29&before=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 0);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/next-use-of-reg?reg=x29&after=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 1);
    assert_eq!(v["value"], "0x2929");

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/next-use-of-reg?reg=x30&after=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"].as_u64().unwrap_or(99), 3);
    assert_eq!(v["value"], "0x3030");
}
