use super::analysis_support;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;
fn synth_call_dir_with_known_offsets() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_9r_2ms");
    fs::create_dir_all(&cd).unwrap();
    // Use the corrected bl encoding from Task 5 / Task 3 fixtures:
    // bl 0x100100 from PC 0x100000 = 0x94000040
    // bl 0x100200 from PC 0x100008 = 0x9400007e
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
              r#"{"pkg":"tst","method":"f","module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    (tmp, cd)
}

#[test]
fn cfg_returns_blocks_and_edges() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "cfg", None);
    assert_eq!(resp.error_code(), None);

    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    let blocks = v["blocks"].as_array().expect("blocks array");
    assert!(!blocks.is_empty(), "synth trace must produce ≥1 block");

    let b0 = &blocks[0];
    assert!(b0["start_pc"].is_string() || b0["start_pc"].is_number());
    assert!(b0["executions"].is_number());
    assert!(b0["scc_id"].is_number());
}

#[test]
fn cfg_block_with_known_fn_has_fn_name() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "cfg", None);
    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let blocks = v["blocks"].as_array().unwrap();

    let f_root_block = blocks.iter().find(|b| {
        b["start_pc"].as_str().unwrap_or("") == "0x100000"
            || b["start_pc"].as_u64() == Some(0x100000)
    });
    if let Some(b) = f_root_block {
        let name = b["fn_name"].as_str().unwrap_or("");
        assert!(
            name == "f" || name == "f_root",
            "fn_name should be f or f_root, got {name:?}"
        );
    }
}

#[test]
fn cfg_empty_trace_no_blocks() {
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

    let app = AnalysisContext::load(cd).expect("load analysis context");
    let resp = analysis_support::query(&app, "cfg", None);
    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert!(v["blocks"].as_array().unwrap().is_empty());
    assert!(v["edges"].as_array().unwrap().is_empty());
}

#[test]
fn idxs_for_block_returns_record_indices() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "block-hits?pc=0x100000", None);
    assert_eq!(resp.error_code(), None);

    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["block"], "0x100000");
    assert_eq!(v["total"], 2);
    assert_eq!(v["truncated"], false);
    let idxs = v["idxs"].as_array().expect("idxs array");
    assert!(!idxs.is_empty(), "expected ≥1 record in block 0x100000");
    assert_eq!(idxs[0].as_u64(), Some(0));
}

#[test]
fn idxs_for_block_near_prioritizes_closest_record() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "block-hits?pc=0x100000&max_count=1&near=1", None);
    assert_eq!(resp.error_code(), None);

    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["block"], "0x100000");
    assert_eq!(v["total"], 2);
    assert_eq!(v["truncated"], true);
    assert_eq!(
        v["idxs"].as_array().expect("idxs array")[0].as_u64(),
        Some(1)
    );
}

#[test]
fn idxs_for_block_unknown_pc_returns_not_found() {
    let (_tmp, call_dir) = synth_call_dir_with_known_offsets();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "block-hits?pc=0xdeadbeef", None);
    assert_eq!(resp.error_code(), Some("not_found"));
}
