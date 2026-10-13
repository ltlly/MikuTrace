use super::analysis_support;
use std::fs;
use tracemiku_core::analysis::AnalysisContext;

fn synth_trace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 3] = [0x100000, 0x100004, 0x100008];
    let x0s: [u64; 3] = [0, 7, 7];
    let insts: [u32; 3] = [0xd503201f, 0xd503201f, 0xd65f03c0]; // nop; nop; ret
    let mut buf = vec![0u8; 272 * 3];
    for i in 0..3 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pcs[i].to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&x0s[i].to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&insts[i].to_le_bytes());
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

fn call_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_3r_1ms")
}

#[test]
fn register_timeline_reports_changes() {
    let dir = synth_trace();
    let app = AnalysisContext::load(call_dir(&dir)).unwrap();
    let resp = analysis_support::query(&app, "reg-inspect?reg=x0&max_points=10", None);
    assert_eq!(resp.error_code(), None);
    let v: serde_json::Value = serde_json::from_slice(&resp.bytes()).unwrap();
    assert_eq!(v["mode"], "changes");
    assert_eq!(
        v["points"],
        serde_json::json!([{"idx":0,"value":"0x0"},{"idx":1,"value":"0x7"}])
    );
}

#[test]
fn register_equals_reports_each_match_after_start() {
    let dir = synth_trace();
    let app = AnalysisContext::load(call_dir(&dir)).unwrap();
    let resp = analysis_support::query(
        &app,
        "reg-inspect?reg=x0&equals=7&start=2&max_points=10",
        None,
    );
    assert_eq!(resp.error_code(), None);
    let v: serde_json::Value = serde_json::from_slice(&resp.bytes()).unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["points"][0]["idx"], 2);
    assert_eq!(v["mode"], "equals");
}

#[test]
fn watchpoints_query_rejects_missing_register() {
    let dir = synth_trace();
    let app = AnalysisContext::load(call_dir(&dir)).expect("analysis context loads");
    let resp = analysis_support::query(&app, "reg-inspect", None);
    assert_eq!(resp.error_code(), Some("invalid_argument"));
}
