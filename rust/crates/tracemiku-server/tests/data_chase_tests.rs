use std::fs;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

type RecSpec<'a> = (u64, u32, &'a [(usize, u64)]);

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let specs: [RecSpec<'_>; 4] = [
        // mov x1, x3
        (0x100000, 0xaa0303e1, &[]),
        // str x1, [x2], x1=hello, x2=0x7000
        (0x100004, 0xf9000041, &[(1, 0x6f6c6c6568), (2, 0x7000)]),
        // ldr x0, [x2], x2=0x7000
        (0x100008, 0xf9400040, &[(2, 0x7000)]),
        // ret, x0=hello post-load
        (0x10000c, 0xd65f03c0, &[(0, 0x6f6c6c6568)]),
    ];
    let mut buf = vec![0u8; 272 * specs.len()];
    for (i, (pc, inst, regs)) in specs.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        for (reg_idx, value) in *regs {
            let roff = off + 8 + reg_idx * 8;
            buf[roff..roff + 8].copy_from_slice(&value.to_le_bytes());
        }
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
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
async fn data_chase_follows_load_store_and_reg_source() {
    let (_tmp, cd) = synth_call_dir();
    let v = get_json(cd, "/api/data-chase?start=3&reg=x0&max_steps=10").await;
    assert_eq!(v["from"], 3);
    assert_eq!(v["reg"], "x0");
    assert_eq!(v["steps"][0]["via"], "mem-load");
    assert_eq!(v["steps"][0]["src"], "0x7000");
    assert_eq!(v["steps"][1]["via"], "mem-store-src");
    assert_eq!(v["steps"][1]["src"], "x1");
    assert_eq!(v["steps"][2]["via"], "reg");
    assert_eq!(v["steps"][2]["src"], "x3");
}
