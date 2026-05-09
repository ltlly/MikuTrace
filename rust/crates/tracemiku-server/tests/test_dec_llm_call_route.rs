//! /api/dec/llm-call integration tests.

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;

fn synth_root_only() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 3];
    for i in 0..3usize {
        let off = i * 272;
        let pc = 0x100000u64 + (i as u64) * 4;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    fs::write(
        cd.join("meta.json"),
        r#"{"records":3,"known_offsets":{"0x0":"f_root"}}"#,
    )
    .unwrap();
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096},"method":"f","cmd":42,"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    dir
}

fn synth_two_callees() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_9r_1ms");
    fs::create_dir_all(&cd).unwrap();
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
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":9,"known_offsets":{"0x0":"f_root","0x100":"f_alpha","0x200":"f_beta"}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536},"method":"f","cmd":42}"#,
    )
    .unwrap();
    dir
}

fn call_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

async fn start_mock_openai() -> (String, Arc<AtomicUsize>) {
    async fn handler(
        State(count): State<Arc<AtomicUsize>>,
        Json(body): Json<serde_json::Value>,
    ) -> Json<serde_json::Value> {
        count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(body["model"], "mimo-v2.5-pro");
        assert!(body["messages"].as_array().unwrap().len() >= 2);
        Json(serde_json::json!({
            "id": "chatcmpl-test",
            "choices": [{"message": {"content": "```c\nint f(void) { return 0; }\n```"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 123, "completion_tokens": 45}
        }))
    }

    let count = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/v1/chat/completions", post(handler))
        .with_state(count.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/v1"), count)
}

#[tokio::test]
async fn dec_models_lists_llm_aliases() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/dec/models")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let models = v["models"].as_array().unwrap();
    assert!(models.iter().any(|m| m == "mimo"));
    assert!(models.iter().any(|m| m == "claude"));
}

#[tokio::test]
async fn dec_llm_call_returns_404_for_unknown_fn_before_network() {
    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/dec/llm-call")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"fn_id":"trace:F99","model":"mimo"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dec_llm_call_uses_mock_mimo_and_caches_success() {
    let (base_url, count) = start_mock_openai().await;
    std::env::set_var("MIMO_BASE_URL", base_url);
    std::env::set_var("MIMO_API_KEY", "test-key");

    let dir = synth_root_only();
    let cd = call_dir(&dir);
    let app = tracemiku_server::build_router(cd).expect("router builds");
    let body = serde_json::json!({
        "fn_id": "trace:F0",
        "model": "mimo",
        "tier": "hot",
        "lang": "en",
        "max_tokens": 64
    })
    .to_string();

    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/dec/llm-call")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let bytes1 = axum::body::to_bytes(resp1.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v1: serde_json::Value = serde_json::from_slice(&bytes1).unwrap();
    assert_eq!(v1["ok"], true);
    assert_eq!(v1["cache_hit"], false);
    assert_eq!(v1["in_tokens"], 123);
    assert!(v1["c_code"].as_str().unwrap().contains("return 0"));

    let resp2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/dec/llm-call")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let bytes2 = axum::body::to_bytes(resp2.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v2: serde_json::Value = serde_json::from_slice(&bytes2).unwrap();
    assert_eq!(v2["cache_hit"], true);
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "second request should hit cache"
    );

    let resp3 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/dec/llm-call")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"fn_id":"symaddr:0x100000","model":"mimo","max_tokens":64})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let bytes3 = axum::body::to_bytes(resp3.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v3: serde_json::Value = serde_json::from_slice(&bytes3).unwrap();
    assert_eq!(v3["ok"], true);
    assert!(v3["c_code"].as_str().unwrap().contains("return 0"));
    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "sym request should call mock once"
    );

    let split_dir = synth_two_callees();
    let split_app = tracemiku_server::build_router(call_dir(&split_dir)).expect("router builds");
    let resp4 = split_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/dec/llm-call")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "fn_id":"trace:F1",
                        "model":"mimo",
                        "max_tokens":64,
                        "split_top_k":2,
                        "split_min_records":1
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp4.status(), StatusCode::OK);
    let bytes4 = axum::body::to_bytes(resp4.into_body(), 64 * 1024)
        .await
        .unwrap();
    let v4: serde_json::Value = serde_json::from_slice(&bytes4).unwrap();
    assert_eq!(v4["ok"], true);
    assert_eq!(
        count.load(Ordering::SeqCst),
        3,
        "split trace-ir request should resolve F1 and call mock once"
    );

    std::env::remove_var("MIMO_BASE_URL");
    std::env::remove_var("MIMO_API_KEY");
}
