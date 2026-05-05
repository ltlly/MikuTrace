use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::fs;
use tower::ServiceExt;

fn synth_trace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 3] = [0x100000, 0x100004, 0x100008];
    let insts: [u32; 3] = [0xaa0103e0, 0xf9000020, 0xd65f03c0]; // mov x0,x1; str x0,[x1]; ret
    let mut buf = vec![0u8; 272 * 3];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn llil_render_route_returns_pseudocode() {
    let dir = synth_trace();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/llil/render")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"fn_id":"trace:F0","max_records":3}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["fn_id"], "trace:F0");
    assert_eq!(v["records"], 3);
    let code = v["pseudocode"].as_str().unwrap();
    assert!(code.contains("x0_1 = x1_0;"), "{code}");
    assert!(code.contains("return;"), "{code}");
}

#[tokio::test]
async fn llil_llm_route_returns_model_error_without_key() {
    let dir = synth_trace();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/llil/llm")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"fn_id":"trace:F0","model":"mimo","max_records":3,"max_tokens":256}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["fn_id"], "trace:F0");
    assert_eq!(v["llil_records"], 3);
    assert!(v.get("ok").is_some());
    assert!(v.get("estimated_prompt_tokens").is_some());
}
