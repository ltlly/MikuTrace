//! Integration tests for `GET /api/call-tree`.
//!
//! Synthetic 9-record trace identical to the calltree unit-test fixture
//! and `cfg_endpoint_tests.rs::synth_call_dir_with_known_offsets`:
//!
//! ```text
//! idx | pc        | mnem | comment
//!   0 | 0x100000  | nop  | f_root entry
//!   1 | 0x100004  | bl   | call f_alpha @ 0x100100
//!   2 | 0x100100  | nop  | f_alpha entry
//!   3 | 0x100104  | ret  | f_alpha return
//!   4 | 0x100008  | bl   | call f_beta  @ 0x100200
//!   5 | 0x100200  | nop  | f_beta entry
//!   6 | 0x100204  | nop
//!   7 | 0x100208  | ret  | f_beta return
//!   8 | 0x10000c  | ret  | f_root return
//! ```

use std::fs;
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
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    // ARM64 little-endian:
    //   nop                        = 0xd503201f
    //   ret                        = 0xd65f03c0
    //   bl 0x100100 from 0x100004  = 0x9400003f  (rel +0xfc)
    //   bl 0x100200 from 0x100008  = 0x9400007e  (rel +0x1f8)
    // build_call_tree resolves callees from trace.pc(i+1), not from the
    // bl immediate, but we still emit faithful opcodes so the synth
    // matches the static-disasm story and stays aligned with the core
    // fixture in tracemiku-core/src/calltree.rs.
    let pcs: [u64; 9] = [
        0x100000, 0x100004, 0x100100, 0x100104, 0x100008, 0x100200, 0x100204, 0x100208, 0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x9400003f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        // 31 GPRs already zero. sp at offset 256, nzcv at 264, inst at 268.
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":9,"truncated":false,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"pkg":"tst","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    (tmp, cd)
}

#[tokio::test]
async fn call_tree_default_max_depth() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/call-tree")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let tree = &v["tree"];
    assert_eq!(
        tree["fn"].as_str(),
        Some("?"),
        "root fn must be ? (got {tree})"
    );
    assert_eq!(tree["depth"].as_u64(), Some(0));
    assert_eq!(tree["enter_idx"].as_u64(), Some(0));
    assert_eq!(tree["exit_idx"].as_u64(), Some(8));
    let children = tree["children"].as_array().expect("children array");
    assert_eq!(
        children.len(),
        2,
        "expected 2 children, got {} ({tree})",
        children.len()
    );
    assert_eq!(children[0]["fn"].as_str(), Some("f_alpha"));
    assert_eq!(children[1]["fn"].as_str(), Some("f_beta"));
    // Default depth means no truncation key.
    assert!(
        tree.get("truncated_children")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "default max_depth must omit truncated_children, got: {tree}"
    );
}

#[tokio::test]
async fn call_tree_max_depth_zero_flattens_children() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = tracemiku_server::build_router(call_dir).expect("build router");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/call-tree?max_depth=0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let tree = &v["tree"];
    let children = tree["children"].as_array().expect("children array");
    assert!(
        children.is_empty(),
        "max_depth=0 must yield no nested children, got {tree}"
    );
    assert_eq!(
        tree["truncated_children"].as_u64(),
        Some(2),
        "two callees should flatten into root.truncated_children, got {tree}"
    );
}
