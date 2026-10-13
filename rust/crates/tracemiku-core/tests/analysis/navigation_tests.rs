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
        .join("call_001_tid100_5r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100100, 0x100104, 0x100008];
    let insts: [u32; 5] = [
        0xd503201f, // nop
        0x9400003f, // bl 0x100100
        0xd503201f, // nop
        0xd65f03c0, // ret
        0xd65f03c0, // ret
    ];
    let mut buf = vec![0u8; 272 * pcs.len()];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        let lr = if i == 2 { 0x100008u64 } else { 0 };
        buf[off + 248..off + 256].copy_from_slice(&lr.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":5,"known_offsets":{"0x0":"root","0x100":"callee"}}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn synth_deep_call_dir(depth: usize) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join(format!("call_001_tid100_{depth}r_1ms"));
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * depth];
    for i in 0..depth {
        let off = i * 272;
        let pc = 0x100000u64 + (i as u64) * 4;
        let inst = 0x94000000u32; // bl
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), format!(r#"{{"records":{depth}}}"#)).unwrap();
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
fn block_finds_containing_block() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "block?pc=0x100104");
    assert_eq!(status, None);
    assert_eq!(v["start"], "0x100100");
}

#[test]
fn block_detail_returns_insns_and_exits() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "block?pc=0x100000");
    assert_eq!(status, None);
    assert_eq!(v["start"], "0x100000");
    assert_eq!(v["func"], "root");
    assert!(v["insns"].as_array().unwrap().len() >= 2);
    assert!(v["exits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["to"] == "0x100100"));
}

#[test]
fn loops_query_returns_ready_shape() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "loops");
    assert_eq!(status, None);
    assert_eq!(v["status"], "ready");
    assert!(v["loops"].is_array());
}

#[test]
fn backtrace_replays_calls_before_idx() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "backtrace?idx=2");
    assert_eq!(status, None);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["depth"], 1);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["stack"][0]["call_site_idx"], 1);
    assert_eq!(v["stack"][0]["callee_pc"], "0x100100");
}

#[test]
fn backtrace_caps_returned_stack_to_limit() {
    let (_tmp, cd) = synth_deep_call_dir(5);
    let (status, v) = get(cd, "backtrace?idx=4&limit=2");
    assert_eq!(status, None);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["depth"], 5);
    assert_eq!(v["returned"], 2);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["stack"].as_array().unwrap().len(), 2);
    assert_eq!(v["stack"][0]["call_site_idx"], 3);
    assert_eq!(v["stack"][1]["call_site_idx"], 4);
}

#[test]
fn call_chain_walks_lr_to_call_site() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "call-chain?idx=2&depth=3");
    assert_eq!(status, None);
    assert_eq!(v["start_idx"], 2);
    assert_eq!(v["depth"], 2);
    assert_eq!(v["chain"][0]["idx"], 2);
    assert_eq!(v["chain"][0]["lr"], "0x100008");
    assert_eq!(v["chain"][0]["caller_pc"], "0x100004");
    assert_eq!(v["chain"][1]["idx"], 1);
}
