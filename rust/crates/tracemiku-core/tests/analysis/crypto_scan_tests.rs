use super::analysis_support;
use std::fs;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;

fn synth_call_dir(x0: u64) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[8..16].copy_from_slice(&x0.to_le_bytes());
    buf[16..24].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[256..264].copy_from_slice(&0x8000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xf9000020u32.to_le_bytes()); // str x0,[x1]
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":1}"#).unwrap();
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
fn crypto_scan_finds_sha1_md5_iv_bytes() {
    let (_tmp, cd) = synth_call_dir(0x67452301);
    let (status, v) = get(cd, "crypto-analysis");
    let v = &v["mem_scan"];
    assert_eq!(status, None);
    assert!(v["scanned"].as_u64().unwrap() > 0);
    assert_eq!(v["any_hit"], true);
    let primitives = v["primitives"].as_array().unwrap();
    let sha1 = primitives
        .iter()
        .find(|p| p["name"] == "SHA1_H[0]/MD5_A")
        .unwrap();
    assert_eq!(sha1["pattern"], "01234567");
    assert_eq!(sha1["hit_count"], 1);
    assert_eq!(sha1["hits"][0]["addr"], "0x7000");
    assert_eq!(sha1["hits"][0]["first_idx"], 0);
}

#[test]
fn crypto_scan_finds_round_constants() {
    let (_tmp, cd) = synth_call_dir(0xd76aa478);
    let (status, v) = get(cd, "crypto-analysis");
    let v = &v["mem_scan"];
    assert_eq!(status, None);
    assert_eq!(v["any_hit"], true);
    let primitives = v["primitives"].as_array().unwrap();
    let md5 = primitives.iter().find(|p| p["name"] == "MD5_T[1]").unwrap();
    assert_eq!(md5["pattern"], "78a46ad7");
    assert_eq!(md5["hit_count"], 1);
    assert_eq!(md5["hits"][0]["addr"], "0x7000");
}

#[test]
fn crypto_scan_finds_hash_table_constants() {
    let (_tmp, cd) = synth_call_dir(0x82f63b78);
    let (status, v) = get(cd, "crypto-analysis");
    let v = &v["mem_scan"];
    assert_eq!(status, None);
    assert_eq!(v["any_hit"], true);
    let primitives = v["primitives"].as_array().unwrap();
    let crc32c = primitives
        .iter()
        .find(|p| p["name"] == "CRC32C_table[1]")
        .unwrap();
    assert_eq!(crc32c["pattern"], "783bf682");
    assert_eq!(crc32c["hit_count"], 1);
    assert_eq!(crc32c["hits"][0]["addr"], "0x7000");
}

#[test]
fn crypto_scan_reports_zero_hits_for_non_crypto_bytes() {
    let (_tmp, cd) = synth_call_dir(0x11111111);
    let (status, v) = get(cd, "crypto-analysis");
    let v = &v["mem_scan"];
    assert_eq!(status, None);
    assert_eq!(v["any_hit"], false);
}

#[test]
fn crypto_analysis_returns_all_three_scan_types() {
    let (_tmp, cd) = synth_call_dir(0x67452301);
    let (status, v) = get(cd, "crypto-analysis");
    assert_eq!(status, None);
    // Check mem_scan present
    assert!(v["mem_scan"]["scanned"].as_u64().unwrap() > 0);
    assert!(v["mem_scan"]["primitives"].is_array());
    // Check const_scan present
    assert!(v["const_scan"]["records_scanned"].as_u64().unwrap() > 0);
    assert!(v["const_scan"]["hits"].is_array());
    assert!(v["const_scan"]["summaries"].is_array());
    // Check crypto_instrs present
    assert!(v["crypto_instrs"]["records_scanned"].as_u64().unwrap() > 0);
    assert!(v["crypto_instrs"]["hits"].is_array());
    // 有发现时不输出空结果提示
    assert!(
        v.get("note").is_none(),
        "note only appears for empty results"
    );
    assert!(v["detected_contexts"].is_array());
}

#[test]
fn crypto_analysis_adds_note_when_all_scans_are_empty() {
    // 无加密指示物时 server 必须给出 note（无发现 + 建议下一步），
    // 该语义由 server 统一提供，CLI 只透传。
    let (_tmp, cd) = synth_call_dir(0x11111111);
    let (status, v) = get(cd, "crypto-analysis");
    assert_eq!(status, None);
    assert_eq!(v["mem_scan"]["any_hit"], false);
    assert!(v["const_scan"]["hits"].as_array().unwrap().is_empty());
    assert!(v["crypto_instrs"]["hits"].as_array().unwrap().is_empty());
    assert!(v["detected_contexts"].as_array().unwrap().is_empty());
    let note = v["note"].as_str().unwrap_or_default();
    assert!(!note.is_empty(), "empty result must carry a note: {v}");
    assert!(
        note.contains("no crypto indicators"),
        "note should state the finding: {note}"
    );
    assert!(
        note.contains("next steps"),
        "note should suggest next steps: {note}"
    );
}

#[test]
fn crypto_analysis_detects_md5_and_sha1_contexts_and_deduplicates_regs() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_10r_1ms");
    fs::create_dir_all(&cd).unwrap();

    // Helper to build a 272-byte record
    let make_rec = |pc: u64, x0: u64, x1: u64, inst: u32| -> [u8; 272] {
        let mut r = [0u8; 272];
        r[0..8].copy_from_slice(&pc.to_le_bytes());
        r[8..16].copy_from_slice(&x0.to_le_bytes());
        r[16..24].copy_from_slice(&x1.to_le_bytes());
        r[256..264].copy_from_slice(&0x8000u64.to_le_bytes());
        r[268..272].copy_from_slice(&inst.to_le_bytes());
        r
    };

    let str_x0_x1 = 0xf9000020u32; // str x0, [x1]
    let str_w0_x1 = 0xb9000020u32; // str w0, [x1]
    let nop = 0xd503201fu32; // nop

    let md5_iv_lo = 0xefcdab89_67452301u64;
    let md5_iv_hi = 0x10325476_98badcfeu64;
    let sha1_iv4 = 0xc3d2e1f0u64;

    let mut buf = Vec::new();
    // 0..2: Initialize MD5_CTX at 0x7000 (16 bytes)
    buf.extend_from_slice(&make_rec(0x100000, md5_iv_lo, 0x7000, str_x0_x1));
    buf.extend_from_slice(&make_rec(0x100004, md5_iv_hi, 0x7008, str_x0_x1));
    // 2: Update MD5_CTX at 0x7000 with final state bytes
    buf.extend_from_slice(&make_rec(
        0x100008,
        0x859df5ee_216da98bu64,
        0x7000,
        str_x0_x1,
    ));
    buf.extend_from_slice(&make_rec(
        0x10000c,
        0x64e1983c_dae64c21u64,
        0x7008,
        str_x0_x1,
    ));
    // 4..7: Initialize SHA1_CTX at 0x7100 (20 bytes)
    buf.extend_from_slice(&make_rec(0x100010, md5_iv_lo, 0x7100, str_x0_x1));
    buf.extend_from_slice(&make_rec(0x100014, md5_iv_hi, 0x7108, str_x0_x1));
    buf.extend_from_slice(&make_rec(0x100018, sha1_iv4, 0x7110, str_w0_x1));
    // 7: Repeat same x0 value on nop — should be deduplicated in register scan!
    buf.extend_from_slice(&make_rec(0x10001c, sha1_iv4, 0x7110, nop));
    // 8..11: Update SHA1_CTX at 0x7100 with final state bytes
    buf.extend_from_slice(&make_rec(
        0x100020,
        0xbb5b14d6_350ea850u64,
        0x7100,
        str_x0_x1,
    ));
    buf.extend_from_slice(&make_rec(
        0x100024,
        0xaea03d1b_5c8de3f4u64,
        0x7108,
        str_x0_x1,
    ));
    buf.extend_from_slice(&make_rec(0x100028, 0x55b572dau64, 0x7110, str_w0_x1));

    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":11}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let (status, v) = get(cd, "crypto-analysis");
    assert_eq!(status, None);

    let ctxs = v["detected_contexts"].as_array().unwrap();
    assert_eq!(ctxs.len(), 2, "expected MD5 and SHA-1 contexts: {ctxs:?}");

    let md5_ctx = ctxs.iter().find(|c| c["algorithm"] == "MD5").unwrap();
    assert_eq!(md5_ctx["state_addr"], "0x7000");
    assert_eq!(md5_ctx["init_idx"], 1);
    assert_eq!(md5_ctx["final_update_idx"], 3);
    assert_eq!(md5_ctx["state_le_hex"], "8ba96d21eef59d85214ce6da3c98e164");
    assert_eq!(md5_ctx["digest_hex"], "8ba96d21eef59d85214ce6da3c98e164");

    let sha1_ctx = ctxs.iter().find(|c| c["algorithm"] == "SHA-1").unwrap();
    assert_eq!(sha1_ctx["state_addr"], "0x7100");
    assert_eq!(sha1_ctx["init_idx"], 6);
    assert_eq!(sha1_ctx["final_update_idx"], 10);
    assert_eq!(
        sha1_ctx["state_le_hex"],
        "50a80e35d6145bbbf4e38d5c1b3da0aeda72b555"
    );
    assert_eq!(
        sha1_ctx["digest_hex"],
        "350ea850bb5b14d65c8de3f4aea03d1b55b572da"
    );

    // Verify 64-bit high-word scanning & register transition deduplication:
    // SHA1.IV4 was in x0 at idx=6 and unchanged at idx=7 -> only hit at idx=6.
    // MD5.IV1 (0xefcdab89) was in the upper 32 bits of x0 at idx=0 and idx=4 -> hit at both!
    let hits = v["const_scan"]["hits"].as_array().unwrap();
    let iv4_hits: Vec<_> = hits
        .iter()
        .filter(|h| h["fingerprint"] == "SHA1.IV4")
        .collect();
    assert_eq!(iv4_hits.len(), 1);
    assert_eq!(iv4_hits[0]["idx"], 6);

    let iv1_hits: Vec<_> = hits
        .iter()
        .filter(|h| h["fingerprint"] == "MD5.IV1")
        .collect();
    assert_eq!(iv1_hits.len(), 2);
}
