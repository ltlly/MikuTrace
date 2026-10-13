use super::analysis_support;
use std::fs;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_12r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 12];
    for i in 0..12 {
        let off = i * 272;
        let pc = 0x100000u64 + i as u64 * 4;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd61f0000u32.to_le_bytes());
        // br x0
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":12}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn get(call_dir: PathBuf, uri: &str) -> (Option<&'static str>, serde_json::Value) {
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, uri, None);
    let status = resp.error_code();
    let body = resp.bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[test]
fn ollvm_detect_vm_exposes_core_findings() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "ollvm-detect-vm?min_entries=10&threshold=0.3");
    assert_eq!(status, None);
    assert_eq!(v["min_entries"], 10);
    assert_eq!(v["threshold"], 0.3);
    assert_eq!(v["count"], 1);
    assert_eq!(v["candidates"][0]["fn_pc"], "0x100000");
    assert_eq!(v["candidates"][0]["entry_count"], 12);
    assert!(v["candidates"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("indirect"));
}

#[test]
fn ollvm_detect_vm_threshold_filters_findings() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "ollvm-detect-vm?min_entries=10&threshold=0.9");
    assert_eq!(status, None);
    assert_eq!(v["count"], 0);
    assert!(v["candidates"].as_array().unwrap().is_empty());
}
