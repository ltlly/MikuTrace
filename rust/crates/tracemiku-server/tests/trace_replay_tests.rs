use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use tracemiku_core::trace::Record;
fn fixture(inst: u32, observed_x0: u64) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp.path().join("run/calls/call_001_tid1_2r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let mut before = Record::zero(0x1000);
    before.inst = inst;
    let mut after = Record::zero(0x1004);
    after.inst = 0xd503201f;
    after.regs[0] = observed_x0;
    let mut raw = Vec::new();
    for r in [before, after] {
        raw.extend(r.pc.to_le_bytes());
        for v in r.regs {
            raw.extend(v.to_le_bytes());
        }
        raw.extend(r.sp.to_le_bytes());
        raw.extend(r.nzcv.to_le_bytes());
        raw.extend(r.inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), raw).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":2}"#).unwrap();
    std::fs::write(
        tmp.path().join("run/meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x1000","size":4096}}"#,
    )
    .unwrap();
    (tmp, cd)
}
#[tokio::test]
async fn replay_success_and_divergence_are_distinct() {
    for (observed, status) in [(1, "matched"), (2, "diverged")] {
        let (_tmp, cd) = fixture(0xd2800020, observed);
        let app = tracemiku_server::build_router(cd).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/trace-replay?count=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], status);
        assert_eq!(json["checked"], if observed == 1 { 1 } else { 0 });
        if observed != 1 {
            assert_eq!(json["stop"]["reason"], "register_mismatch");
        }
    }
}
#[tokio::test]
async fn replay_rejects_empty_and_out_of_range_queries() {
    for query in ["count=0", "start=2", "start=-1"] {
        let (_tmp, cd) = fixture(0xd503201f, 0);
        let app = tracemiku_server::build_router(cd).unwrap();
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/trace-replay?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
