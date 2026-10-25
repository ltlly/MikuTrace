//! Black-box tests for GET records and GET record/{idx}.

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
              r#"{"pkg":"tst","so":"libt","method":"f","module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    let cd_owned = cd.clone();
    (tmp, cd_owned)
}

fn synth_large_call_dir(records: usize) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join(format!("call_001_tid100_{records}r_2ms"));
    fs::create_dir_all(&cd).unwrap();

    let mut buf = vec![0u8; 272 * records];
    for i in 0..records {
        let off = i * 272;
        let pc = 0x100000u64 + i as u64 * 4;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), format!(r#"{{"records":{records}}}"#)).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

#[test]
fn records_default_window() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "records", None);
    assert_eq!(resp.error_code(), None);

    let body = resp.bytes();
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
    assert!(r0["exec_count"].is_null());
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

#[test]
fn records_start_count_window() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "records?start=2&count=3", None);
    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["start"], 2);
    assert_eq!(v["end"], 5);
    assert_eq!(v["count"], 3);
    assert_eq!(v["returned"], 3);
    assert_eq!(v["requested_count"], 3);
    assert_eq!(v["max_count_used"], 3);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["records"].as_array().unwrap().len(), 3);
    assert_eq!(v["records"][0]["idx"], 2);
    assert_eq!(v["records"][2]["idx"], 4);
}

#[test]
fn records_count_is_capped_for_large_windows() {
    let (_tmp, call_dir) = synth_large_call_dir(5_100);
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "records?start=0&count=100000", None);
    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["start"], 0);
    assert_eq!(v["end"], 1000);
    assert_eq!(v["count"], 1000);
    assert_eq!(v["returned"], 1000);
    assert_eq!(v["requested_count"], 100000);
    assert_eq!(v["max_count_used"], 1000);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["records"].as_array().unwrap().len(), 1000);
}

#[test]
fn records_start_out_of_range_empty() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "records?start=999&count=10", None);
    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["start"], 999);
    assert_eq!(v["end"], 999);
    assert_eq!(v["count"], 0);
    assert_eq!(v["returned"], 0);
    assert_eq!(v["requested_count"], 10);
    assert_eq!(v["max_count_used"], 10);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["records"].as_array().unwrap().len(), 0);
}

#[test]
fn records_with_regs_filter() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "records?start=0&count=1&regs=sp,pc", None);
    let body = resp.bytes();
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

#[test]
fn record_single_returns_full_regs() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "record/0", None);
    assert_eq!(resp.error_code(), None);

    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["idx"], 0);
    assert_eq!(v["pc"], "0x100000");
    assert!(v["asm"].as_str().unwrap().contains("nop"));
    assert_eq!(v["exec_count"], 1);
    assert_eq!(v["block_pc"], "0x100000");
    assert_eq!(v["cfg_status"], "ready");
    assert_eq!(v["is_branch"], false);
    assert_eq!(v["is_call"], false);
    assert_eq!(v["is_ret"], false);

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

#[test]
fn record_out_of_range_returns_not_found() {
    let (_tmp, call_dir) = synth_call_dir();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "record/999", None);
    assert_eq!(resp.error_code(), Some("not_found"));
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
              r#"{"pkg":"tst","so":"libt","method":"f","module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#).unwrap();
    (tmp, cd)
}

#[test]
fn records_with_symbols_populates_func_off() {
    let (_tmp, call_dir) = synth_call_dir_with_symbols();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "records?count=9&detail=true", None);
    let body = resp.bytes();
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

#[test]
fn record_detail_with_symbols_populates_func_off() {
    let (_tmp, call_dir) = synth_call_dir_with_symbols();
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, "record/2", None);
    let body = resp.bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["func"], "f_alpha");
    assert_eq!(v["off"], "0x0");
    assert_eq!(v["block_pc"], "0x100100");
    assert_eq!(v["cfg_status"], "ready");
}

#[test]
fn records_emits_writes_reg_mem_access_and_supports_end() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_3r_1ms");
    fs::create_dir_all(&cd).unwrap();

    // 3 records:
    // 0: ldrb w3, [x4, x20] (0x38746883)
    // 1: str x0, [x1, #16]  (0xf9000820)
    // 2: nop                (0xd503201f)
    let mut buf = vec![0u8; 272 * 3];

    // Record 0: pc=0x100000, x3=0, x4=0x6fc704ab00, x20=0xbf, sp=0x7000
    let off0 = 0;
    buf[off0..off0 + 8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[off0 + 8 + 4 * 8..off0 + 8 + 5 * 8].copy_from_slice(&0x6fc704ab00u64.to_le_bytes()); // x4
    buf[off0 + 8 + 20 * 8..off0 + 8 + 21 * 8].copy_from_slice(&0xbfu64.to_le_bytes()); // x20
    buf[off0 + 256..off0 + 264].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[off0 + 268..off0 + 272].copy_from_slice(&0x38746883u32.to_le_bytes());

    // Record 1: pc=0x100004, x0=0xdeadbeef, x1=0x8000, x3=0x35 (result of ldrb at 0), sp=0x7000
    let off1 = 272;
    buf[off1..off1 + 8].copy_from_slice(&0x100004u64.to_le_bytes());
    buf[off1 + 8..off1 + 16].copy_from_slice(&0xdeadbeefu64.to_le_bytes()); // x0
    buf[off1 + 8 + 8..off1 + 8 + 16].copy_from_slice(&0x8000u64.to_le_bytes()); // x1
    buf[off1 + 8 + 3 * 8..off1 + 8 + 4 * 8].copy_from_slice(&0x35u64.to_le_bytes()); // x3
    buf[off1 + 256..off1 + 264].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[off1 + 268..off1 + 272].copy_from_slice(&0xf9000820u32.to_le_bytes());

    // Record 2: pc=0x100008, same regs except sp=0x6ff0
    let off2 = 272 * 2;
    buf[off2..off2 + 8].copy_from_slice(&0x100008u64.to_le_bytes());
    buf[off2 + 8..off2 + 16].copy_from_slice(&0xdeadbeefu64.to_le_bytes()); // x0
    buf[off2 + 8 + 8..off2 + 8 + 16].copy_from_slice(&0x8000u64.to_le_bytes()); // x1
    buf[off2 + 8 + 3 * 8..off2 + 8 + 4 * 8].copy_from_slice(&0x35u64.to_le_bytes()); // x3
    buf[off2 + 256..off2 + 264].copy_from_slice(&0x6ff0u64.to_le_bytes());
    buf[off2 + 268..off2 + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());

    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let app = AnalysisContext::load(cd).expect("load analysis context");
    let resp = analysis_support::query(&app, "records?start=0&end=2", None);
    assert_eq!(resp.error_code(), None);
    let v: serde_json::Value = serde_json::from_slice(&resp.bytes()).unwrap();
    assert_eq!(v["start"], 0);
    assert_eq!(v["end"], 2);
    assert_eq!(v["count"], 2);

    let r0 = &v["records"][0];
    assert_eq!(r0["idx"], 0);
    assert_eq!(r0["mem_access"]["kind"], "r");
    assert_eq!(r0["mem_access"]["ea"], "0x6fc704abbf");
    assert_eq!(r0["mem_access"]["size"], 1);
    assert_eq!(r0["mem_access"]["val"], "0x35");
    let writes0 = r0["writes_reg"].as_array().expect("writes_reg on r0");
    assert!(writes0
        .iter()
        .any(|w| w["reg"] == "x3" && w["before"] == "0x0" && w["after"] == "0x35"));

    let r1 = &v["records"][1];
    assert_eq!(r1["idx"], 1);
    assert_eq!(r1["mem_access"]["kind"], "w");
    assert_eq!(r1["mem_access"]["ea"], "0x8010");
    assert_eq!(r1["mem_access"]["size"], 8);
    assert_eq!(r1["mem_access"]["val"], "0xdeadbeef");
    let writes1 = r1["writes_reg"].as_array().expect("writes_reg on r1");
    assert!(writes1
        .iter()
        .any(|w| w["reg"] == "sp" && w["before"] == "0x7000" && w["after"] == "0x6ff0"));
}
