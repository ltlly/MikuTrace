//! Black-box tests for GET /api/records and GET /api/record/{idx}.

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

    // Write 9 records with known PCs + insts.
    let mut buf = vec![0u8; 272 * 9];
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
        0xd503201f, // 0: nop
        0x94000040, // 1: bl  (call+branch)
        0xd503201f, // 2: nop
        0xd65f03c0, // 3: ret
        0x94000080, // 4: bl
        0xd503201f, // 5: nop
        0xd503201f, // 6: nop
        0xd65f03c0, // 7: ret
        0xd65f03c0, // 8: ret
    ];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"),
              r#"{"callIdx":1,"tid":100,"records":9,"ms":2,"retval":"0x0","truncated":false,"last_insn_is_ret":true}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    let cd_owned = cd.clone();
    (tmp, cd_owned)
}

#[tokio::test]
async fn records_default_window() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/records")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(v["start"], 0);
    assert_eq!(v["end"], 9);
    assert_eq!(v["count"], 9);
    assert_eq!(v["records"].as_array().unwrap().len(), 9);

    let r0 = &v["records"][0];
    assert_eq!(r0["idx"], 0);
    assert_eq!(r0["pc"], "0x100000");
    assert_eq!(r0["rel"], "0x0");
    assert_eq!(r0["module"], "libt.so");
    assert!(r0["asm"].as_str().unwrap().starts_with("nop"));
    assert_eq!(r0["is_branch"], false);
    assert_eq!(r0["is_call"], false);
    assert_eq!(r0["is_ret"], false);
    assert!(r0["func"].is_null());
    assert!(r0["off"].is_null());
    assert!(r0["annotation"].is_null());
    assert_eq!(r0["exec_count"], 1);
    assert!(r0.get("regs").is_none_or(|v| v.is_null()));

    let r1 = &v["records"][1];
    assert_eq!(r1["pc"], "0x100004");
    assert_eq!(r1["is_branch"], true);
    assert_eq!(r1["is_call"], true);
    assert_eq!(r1["is_ret"], false);

    let r3 = &v["records"][3];
    assert_eq!(r3["is_ret"], true);
    assert_eq!(r3["is_branch"], true);
    assert_eq!(r3["is_call"], false);
}

#[tokio::test]
async fn records_start_count_window() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/records?start=2&count=3")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["start"], 2);
    assert_eq!(v["end"], 5);
    assert_eq!(v["count"], 3);
    assert_eq!(v["records"].as_array().unwrap().len(), 3);
    assert_eq!(v["records"][0]["idx"], 2);
    assert_eq!(v["records"][2]["idx"], 4);
}

#[tokio::test]
async fn records_start_out_of_range_empty() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/records?start=999&count=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["start"], 999);
    assert_eq!(v["end"], 999);
    assert_eq!(v["count"], 0);
    assert_eq!(v["records"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn records_with_regs_filter() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/records?start=0&count=1&regs=sp,pc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let r0 = &v["records"][0];
    let regs = r0["regs"]
        .as_object()
        .expect("regs object present when filter set");
    assert_eq!(regs["pc"], "0x100000");
    assert_eq!(regs["sp"], "0x7000");
    assert!(
        !regs.contains_key("x0"),
        "x0 must be absent when not filtered"
    );
}

#[tokio::test]
async fn record_single_returns_full_regs() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/record/0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"], 0);
    assert_eq!(v["pc"], "0x100000");
    assert!(v["asm"].as_str().unwrap().contains("nop"));

    let regs = v["regs"].as_object().expect("regs always required");
    // 31 GPR (x0..x28, fp, lr) + sp + pc + nzcv = 34 entries.
    assert!(
        regs.len() >= 33,
        "expected ≥33 reg entries, got {}",
        regs.len()
    );
    assert_eq!(regs["pc"], "0x100000");
    assert_eq!(regs["sp"], "0x7000");
    assert_eq!(regs["x0"], "0x0");
}

#[tokio::test]
async fn record_out_of_range_404() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/record/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

fn synth_call_dir_with_symbols() -> (tempfile::TempDir, PathBuf) {
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
    fs::write(cd.join("meta.json"),
              r#"{"records":9,"tid":100,"ms":2,"truncated":false,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#).unwrap();
    fs::write(tmp.path().join("run").join("meta.json"),
              r#"{"pkg":"tst","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn records_with_symbols_populates_func_off() {
    let (_tmp, call_dir) = synth_call_dir_with_symbols();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/records?count=9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // The fixture sets meta.method="f" + fn_addr=0x100000, which matches
    // known_offsets["0x0"]="f_root". Python's symbols.py priority rule (and
    // Rust's mirror) substitutes meta.method ("f") for the hooked function,
    // so idx 0/1 resolve to "f" not "f_root". This is wire-parity with Python.
    assert_eq!(v["records"][0]["func"], "f");
    assert_eq!(v["records"][0]["off"], "0x0");
    assert_eq!(v["records"][0]["module"], "libt.so");

    assert_eq!(v["records"][1]["func"], "f");
    assert_eq!(v["records"][1]["off"], "0x4");
    assert_eq!(v["records"][1]["annotation"], "→ f_alpha+0x0");
    assert_eq!(v["records"][1]["exec_count"], 1);

    // f_alpha (0x100100) and f_beta (0x100200) are not the hooked fn; their
    // names come straight from known_offsets.
    assert_eq!(v["records"][2]["func"], "f_alpha");
    assert_eq!(v["records"][2]["off"], "0x0");

    assert_eq!(v["records"][5]["func"], "f_beta");
    assert_eq!(v["records"][5]["off"], "0x0");
}

#[tokio::test]
async fn record_detail_with_symbols_populates_func_off() {
    let (_tmp, call_dir) = synth_call_dir_with_symbols();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/record/2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["func"], "f_alpha");
    assert_eq!(v["off"], "0x0");
}
