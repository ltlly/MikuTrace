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

    let pcs = [0x100000u64, 0x100004, 0x200000, 0x200004, 0x300000];
    let insts: [u32; 5] = [
        0xd503201f, // nop
        0x94000040, // bl
        0xd503201f, // nop
        0xd65f03c0, // ret
        0xd503201f, // nop outside modules
    ];
    let mut buf = vec![0u8; 272 * pcs.len()];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&(0xabc0u64 + i as u64).to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{
          "module":{"name":"liba.so","base":"0x100000","size":4096},
          "modules":[
            {"name":"liba.so","base":"0x100000","size":4096},
            {"name":"libb.so","base":"0x200000","size":4096}
          ],
          "fn_addr":"0x100000"
        }"#,
    )
    .unwrap();
    (tmp, cd)
}

fn get_json(call_dir: PathBuf, uri: &str) -> (Option<&'static str>, serde_json::Value) {
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, uri, None);
    let status = resp.error_code();
    let body = resp.bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[test]
fn search_query_matches_decoded_asm_regex() {
    let (_tmp, call_dir) = synth_call_dir();
    let (status, v) = get_json(call_dir, "search?pattern=ret&max_results=10");
    assert_eq!(status, None);
    assert_eq!(v["count"], 1);
    assert_eq!(v["pattern"], "ret");
    assert_eq!(v["hits"][0]["idx"], 3);
    assert_eq!(v["hits"][0]["pc"], "0x200004");
    assert!(v["hits"][0]["asm"].as_str().unwrap().starts_with("ret"));
}

#[test]
fn so_stats_counts_modules_and_unknown_pcs() {
    let (_tmp, call_dir) = synth_call_dir();
    let (status, v) = get_json(call_dir, "so-stats?top=10");
    assert_eq!(status, None);
    assert_eq!(v["records"], 5);
    assert_eq!(v["modules_total"], 2);
    assert_eq!(v["unknown_records"], 1);
    assert_eq!(v["modules"][0]["name"], "liba.so");
    assert_eq!(v["modules"][0]["records"], 2);
    assert_eq!(v["modules"][1]["name"], "libb.so");
    assert_eq!(v["modules"][1]["records"], 2);
}

#[test]
fn records_reads_register_width_aliases_and_rejects_unknown_names() {
    let (_tmp, call_dir) = synth_call_dir();
    for (start, reg, expected) in [(2, "x0", "0xabc2"), (0, "w0", "0xabc0"), (0, "nzcv", "0x0")] {
        let (status, v) = get_json(
            call_dir.clone(),
            &format!("records?start={start}&count=1&regs={reg}"),
        );
        assert_eq!(status, None);
        assert_eq!(v["records"][0]["regs"][reg], expected);
    }
    let (status, _) = get_json(call_dir, "records?start=0&count=1&regs=bogus");
    assert_eq!(status, Some("invalid_argument"));
}
