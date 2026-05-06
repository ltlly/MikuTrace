use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100008, 0x10000c];
    let insts: [u32; 4] = [0xf9000020, 0xf9400022, 0xd503201f, 0xd65f03c0]; // str x0,[x1]; ldr x2,[x1]; nop; ret
    let hello: u64 = u64::from_le_bytes([b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
    let x1: u64 = 0x7000;
    let mut buf = vec![0u8; 272 * 4];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&hello.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes());
        let lr = if i == 2 { 0x100008u64 } else { 0 };
        buf[off + 248..off + 256].copy_from_slice(&lr.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"records":4,"tid":100,"ms":1,"truncated":false,"known_offsets":{"0x0":"f_root"},"fork_events":[{"child_pid":123,"attach_status":"success"},{"child_pid":456,"attach_status":"failed_ptrace_conflict"}]}"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn synth_taint_tree_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_4r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 4] = [0x100000, 0x100004, 0x100008, 0x10000c];
    let insts: [u32; 4] = [0xd2801560, 0xf9000000, 0xb9400401, 0xd503201f];
    let mut buf = vec![0u8; 272 * 4];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&0xabu64.to_le_bytes()); // x0
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes()); // sp
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
    std::fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn run_json(args: &[String]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
        .args(args)
        .output()
        .expect("run tracemiku-cli");
    assert!(
        out.status.success(),
        "cli failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout is json")
}

fn make_diff_trace(root: &std::path::Path, name: &str, x_sign: &[u8]) -> PathBuf {
    make_diff_trace_value(root, name, &STANDARD.encode(x_sign))
}

fn make_diff_trace_value(root: &std::path::Path, name: &str, value: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    std::fs::write(dir.join("trace.bin"), &buf).unwrap();
    std::fs::write(dir.join("meta.json"), r#"{"records":1}"#).unwrap();
    let events = [
        serde_json::json!({"id":"NewStringUTF","trace_idx":1,"args":{"bytes":"x-sign"}}),
        serde_json::json!({"id":"NewStringUTF","trace_idx":2,"args":{"bytes":value}}),
    ];
    std::fs::write(
        dir.join("jni_hooks.jsonl"),
        events
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    dir
}

fn make_output_map_hit_order_trace(root: &std::path::Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let output = STANDARD.encode([0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(output.len(), 8);
    let output_word = u64::from_le_bytes(output.as_bytes().try_into().unwrap());
    let addrs = [0x8000u64, 0x7000u64];
    let mut buf = vec![0u8; 272 * addrs.len()];
    for (i, addr) in addrs.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&output_word.to_le_bytes()); // x0
        buf[off + 16..off + 24].copy_from_slice(&addr.to_le_bytes()); // x1
        let str_x0_x1 = 0xf9000020u32;
        buf[off + 268..off + 272].copy_from_slice(&str_x0_x1.to_le_bytes());
    }
    std::fs::write(dir.join("trace.bin"), &buf).unwrap();
    std::fs::write(dir.join("meta.json"), r#"{"records":2}"#).unwrap();
    let events = [
        serde_json::json!({"id":"NewStringUTF","trace_idx":9,"args":{"bytes":"x-sign"}}),
        serde_json::json!({"id":"NewStringUTF","trace_idx":10,"args":{"bytes":output}}),
    ];
    std::fs::write(
        dir.join("jni_hooks.jsonl"),
        events
            .iter()
            .map(serde_json::Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    dir
}

fn make_word_load_byte_branch_trace(root: &std::path::Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let mut buf = vec![0u8; 272 * 6];
    for i in 0..4 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&((b'A' + i as u8) as u64).to_le_bytes()); // x0
        buf[off + 16..off + 24].copy_from_slice(&(0x7000u64 + i as u64).to_le_bytes()); // x1
        let strb_w0_x1 = 0x39000020u32;
        buf[off + 268..off + 272].copy_from_slice(&strb_w0_x1.to_le_bytes());
    }
    let ldr_off = 4 * 272;
    buf[ldr_off..ldr_off + 8].copy_from_slice(&0x100010u64.to_le_bytes());
    buf[ldr_off + 16..ldr_off + 24].copy_from_slice(&0x7000u64.to_le_bytes()); // x1
    let ldr_w2_x1 = 0xb9400022u32;
    buf[ldr_off + 268..ldr_off + 272].copy_from_slice(&ldr_w2_x1.to_le_bytes());

    let str_off = 5 * 272;
    buf[str_off..str_off + 8].copy_from_slice(&0x100014u64.to_le_bytes());
    buf[str_off + 24..str_off + 32].copy_from_slice(&0x44434241u64.to_le_bytes()); // x2
    buf[str_off + 32..str_off + 40].copy_from_slice(&0x8000u64.to_le_bytes()); // x3
    let str_x2_x3 = 0xf9000062u32;
    buf[str_off + 268..str_off + 272].copy_from_slice(&str_x2_x3.to_le_bytes());

    std::fs::write(dir.join("trace.bin"), &buf).unwrap();
    std::fs::write(dir.join("meta.json"), r#"{"records":6}"#).unwrap();
    dir
}

fn set_trace_reg(buf: &mut [u8], rec: usize, reg: usize, value: u64) {
    let off = rec * 272 + 8 + reg * 8;
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn make_vm_ops_trace(root: &std::path::Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let insts: [u32; 5] = [
        0x394016a6, // ldrb w6, [x21, #5]
        0xf8667b28, // ldr x8, [x25, x6, lsl #3]
        0xf94006ae, // ldr x14, [x21, #8]
        0xf8256b21, // str x1, [x25, x5]
        0xd61f0100, // br x8
    ];
    let mut buf = vec![0u8; 272 * insts.len()];
    for (idx, inst) in insts.iter().enumerate() {
        let off = idx * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + idx as u64 * 4).to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
        set_trace_reg(&mut buf, idx, 21, 0x5000);
        set_trace_reg(&mut buf, idx, 25, 0x7000);
    }
    set_trace_reg(&mut buf, 1, 6, 0x3);
    set_trace_reg(&mut buf, 2, 8, 0x1234);
    set_trace_reg(&mut buf, 3, 1, 0xaa);
    set_trace_reg(&mut buf, 3, 5, 0x18);
    set_trace_reg(&mut buf, 3, 14, 0x1122_3344_5566_7788);
    set_trace_reg(&mut buf, 4, 8, 0x1234);
    std::fs::write(dir.join("trace.bin"), &buf).unwrap();
    std::fs::write(dir.join("meta.json"), r#"{"records":5}"#).unwrap();
    dir
}

#[test]
fn info_json_reports_call_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&["info".into(), cd.display().to_string(), "--json".into()]);
    assert_eq!(v["records"], 4);
    assert_eq!(v["last_insn_is_ret"], true);
    assert_eq!(v["is_complete"], true);
}

#[test]
fn records_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "records".into(),
        cd.display().to_string(),
        "--start".into(),
        "0".into(),
        "--count".into(),
        "1".into(),
    ]);
    assert_eq!(v["status"], serde_json::Value::Null);
    assert_eq!(v["count"], 1);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["records"][0]["idx"], 0);
    assert_eq!(v["records"][0]["pc"], "0x100000");
}

#[test]
fn string_provenance_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "string-provenance".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
        "--length".into(),
        "4".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["addr"], "0x7000");
    assert_eq!(v["length"], 4);
    assert_eq!(v["bytes"].as_array().unwrap().len(), 4);
}

#[test]
fn functions_wrapper_lists_symbol_functions() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&["functions".into(), cd.display().to_string()]);
    assert!(v["functions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| { f["source"] == "symbol" && (f["name"] == "f" || f["name"] == "f_root") }));
}

#[test]
fn fn_summary_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "fn-summary".into(),
        cd.display().to_string(),
        "--fn".into(),
        "f".into(),
        "--top-blocks".into(),
        "2".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["fn"], "f");
    assert_eq!(v["pc"], "0x100000");
    assert!(v["hot_blocks"].is_array());
}

#[test]
fn inspect_wrappers_use_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();

    let v = run_json(&[
        "search-pc".into(),
        cd.display().to_string(),
        "0x100000".into(),
        "--limit".into(),
        "1".into(),
    ]);
    assert_eq!(v["pc"], "0x100000");
    assert_eq!(v["count"], 1);
    assert_eq!(v["idxs"], serde_json::json!([0]));

    let v = run_json(&[
        "idxs-for-pc".into(),
        cd.display().to_string(),
        "0x100000".into(),
        "--cursor".into(),
        "1".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["before"], serde_json::json!([0]));

    let v = run_json(&[
        "search-asm".into(),
        cd.display().to_string(),
        "ret".into(),
        "--max-results".into(),
        "5".into(),
    ]);
    assert_eq!(v["count"], 1);
    assert_eq!(v["hits"][0]["idx"], 3);

    let v = run_json(&[
        "so-stats".into(),
        cd.display().to_string(),
        "--top".into(),
        "5".into(),
    ]);
    assert_eq!(v["records"], 4);
    assert_eq!(v["modules"][0]["name"], "libt.so");

    let v = run_json(&[
        "reg-at-idx".into(),
        cd.display().to_string(),
        "--idx".into(),
        "0".into(),
        "--reg".into(),
        "x0".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["value"], "0x6f6c6c6568");
}

#[test]
fn fork_events_wrapper_filters_status() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "fork-events".into(),
        cd.display().to_string(),
        "--status".into(),
        "failed_ptrace_conflict".into(),
    ]);
    assert_eq!(v["count"], 1);
    assert_eq!(v["events"][0]["child_pid"], 456);
}

#[test]
fn memory_query_wrappers_use_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();

    let v = run_json(&[
        "last-write-of-addr".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
    ]);
    assert_eq!(v["status"], "found");
    assert_eq!(v["writer_idx"], 0);

    let v = run_json(&[
        "idxs-touching-addr".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
        "--cursor".into(),
        "1".into(),
    ]);
    assert_eq!(v["before"], serde_json::json!([{"idx":0,"kind":"w"}]));
    assert_eq!(v["after"], serde_json::json!([{"idx":1,"kind":"r"}]));

    let v = run_json(&[
        "idxs-touching-range".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7004".into(),
        "--size".into(),
        "4".into(),
        "--cursor".into(),
        "1".into(),
    ]);
    assert_eq!(v["writers_before"], serde_json::json!([0]));
    assert_eq!(v["readers_after"], serde_json::json!([1]));

    let v = run_json(&[
        "find-mem-pattern".into(),
        cd.display().to_string(),
        "--bytes-hex".into(),
        "68656c6c6f".into(),
        "--since".into(),
        "0".into(),
        "--max".into(),
        "5".into(),
    ]);
    assert_eq!(v["count"], 1);
    assert_eq!(v["hits"][0]["addr"], "0x7000");
}

#[test]
fn call_chain_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "call-chain".into(),
        cd.display().to_string(),
        "--idx".into(),
        "2".into(),
        "--depth".into(),
        "3".into(),
    ]);
    assert_eq!(v["start_idx"], 2);
    assert_eq!(v["chain"][0]["lr"], "0x100008");
    assert_eq!(v["chain"][0]["caller_pc"], "0x100004");
}

#[test]
fn data_chase_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "data-chase".into(),
        cd.display().to_string(),
        "--start".into(),
        "2".into(),
        "--reg".into(),
        "x2".into(),
        "--max-steps".into(),
        "5".into(),
    ]);
    assert_eq!(v["from"], 2);
    assert_eq!(v["reg"], "x2");
    assert_eq!(v["steps"][0]["via"], "mem-load");
}

#[test]
fn taint_wrappers_include_dependency_metadata() {
    let (_tmp, cd) = synth_taint_tree_call_dir();
    let v = run_json(&[
        "taint-fwd".into(),
        cd.display().to_string(),
        "--start".into(),
        "0".into(),
        "--reg".into(),
        "x0".into(),
        "--max-count".into(),
        "10".into(),
        "--through-mem".into(),
        "--cross-fn-call".into(),
    ]);
    assert_eq!(v["status"], "ready");
    let hits = v["hits"].as_array().unwrap();
    assert!(
        hits.iter().all(|hit| hit.get("taint_depth").is_some()),
        "forward taint hits must carry taint_depth"
    );
    assert!(
        hits.iter().any(|hit| hit
            .get("parent_idxs")
            .and_then(|v| v.as_array())
            .is_some_and(|parents| !parents.is_empty())),
        "forward taint should expose at least one dependency edge"
    );
}

#[test]
fn timeline_diff_wrappers_use_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "reg-timeline".into(),
        cd.display().to_string(),
        "--reg".into(),
        "x0".into(),
    ]);
    assert_eq!(v["reg"], "x0");
    assert_eq!(v["count"], 1);
    assert_eq!(v["points"][0]["value"], "0x6f6c6c6568");

    let v = run_json(&[
        "mem-diff".into(),
        cd.display().to_string(),
        "--idx".into(),
        "1".into(),
        "--addr".into(),
        "0x7000".into(),
        "--size".into(),
        "1".into(),
    ]);
    assert_eq!(v["idx"], 1);
    assert_eq!(v["size"], 1);
    assert_eq!(v["bytes"].as_array().unwrap().len(), 1);
}

#[test]
fn mem_flow_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "mem-flow".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
        "--count".into(),
        "1".into(),
        "--writers-only".into(),
        "--events-per-byte".into(),
        "1".into(),
    ]);
    assert_eq!(v["addr"], "0x7000");
    assert_eq!(v["count"], 1);
    assert_eq!(v["bytes"].as_array().unwrap().len(), 1);
    assert_eq!(v["bytes"][0]["events"].as_array().unwrap().len(), 1);
}

#[test]
fn crypto_scan_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&["crypto-scan".into(), cd.display().to_string()]);
    assert!(v["scanned"].as_u64().unwrap() > 0);
    assert_eq!(v["primitives"].as_array().unwrap().len(), 22);
    assert!(v["any_hit"].is_boolean());
}

#[test]
fn hash_finalize_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "hash-finalize-detect".into(),
        cd.display().to_string(),
        "--window".into(),
        "500".into(),
        "--min-size".into(),
        "16".into(),
    ]);
    assert_eq!(v["window"], 500);
    assert_eq!(v["min_size"], 16);
    assert!(v["candidates"].is_array());
}

#[test]
fn hash_input_search_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "hash-input-search".into(),
        cd.display().to_string(),
        "--target-bytes".into(),
        "aaf4c61d".into(),
        "--inputs".into(),
        "hello,world".into(),
        "--algos".into(),
        "sha1".into(),
        "--combos".into(),
        "plain".into(),
        "--prefix-bytes".into(),
        "4".into(),
    ]);
    assert_eq!(v["target_prefix"], "aaf4c61d");
    assert_eq!(v["found_count"], 1);
    assert_eq!(v["found"][0]["input"], "hello");
}

#[test]
fn diff_traces_wrapper_uses_server_wire_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let run1 = make_diff_trace(tmp.path(), "run1", &[0xaa, 0xbb, 0xcc, 0xdd]);
    let run2 = make_diff_trace(tmp.path(), "run2", &[0xaa, 0xee, 0xcc, 0xdd]);
    let v = run_json(&[
        "diff-traces".into(),
        run1.display().to_string(),
        run2.display().to_string(),
        "--show-offsets".into(),
    ]);
    assert_eq!(v["n_traces"], 2);
    assert_eq!(v["headers"]["x-sign"]["stable_count"], 3);
    assert_eq!(v["headers"]["x-sign"]["variable_count"], 1);
}

#[test]
fn field_at_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "field-at".into(),
        cd.display().to_string(),
        "--pc".into(),
        "0x100000".into(),
        "--reg".into(),
        "x8".into(),
        "--offset".into(),
        "0x80".into(),
    ]);
    assert_eq!(v["hit"], false);
    assert_eq!(v["offset"], 128);
}

#[test]
fn auto_phase_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&["auto-phase-detect".into(), cd.display().to_string()]);
    assert_eq!(v["trace_records"], 4);
    assert!(v["phases"].is_array());
}

#[test]
fn jni_calls_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "jni-calls".into(),
        cd.display().to_string(),
        "--max".into(),
        "5".into(),
    ]);
    assert!(v["vtable_size"].as_u64().unwrap() > 100);
    assert!(v["hits"].is_array());
}

#[test]
fn jobj_history_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "jobj-history".into(),
        cd.display().to_string(),
        "--jobject".into(),
        "0x2222".into(),
        "--max".into(),
        "5".into(),
    ]);
    assert_eq!(v["jobject"], "0x2222");
    assert!(v["hits"].is_array());
}

#[test]
fn jni_strings_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "jni-strings".into(),
        cd.display().to_string(),
        "--max".into(),
        "5".into(),
        "--max-len".into(),
        "32".into(),
    ]);
    assert!(v["note"].as_str().unwrap().contains("GetStringUTFChars"));
    assert!(v["hits"].is_array());
}

#[test]
fn output_backtrace_starts_from_jni_output_pair() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_diff_trace(tmp.path(), "run1", &[0xaa, 0xbb, 0xcc, 0xdd]);
    let v = run_json(&[
        "output-backtrace".into(),
        cd.display().to_string(),
        "--key".into(),
        "x-sign".into(),
        "--max-mem-hits".into(),
        "1".into(),
        "--writes-per-hit".into(),
        "0".into(),
        "--skip-taint".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["strategy"], "output_to_input_backward_trace");
    assert_eq!(v["source"]["kind"], "jni_output_string_pair");
    assert_eq!(v["source"]["pair"]["key"], "x-sign");
    assert_eq!(
        v["source"]["pair"]["value"],
        STANDARD.encode([0xaa, 0xbb, 0xcc, 0xdd])
    );
    assert_eq!(v["patterns"][0]["kind"], "observed");
    assert_eq!(v["taint"]["skipped"], true);
    assert_eq!(
        v["taint"]["queued"][0]["kind"],
        "jni_new_string_utf_callsite"
    );
}

#[test]
fn output_map_defaults_to_earliest_generation_hit() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_output_map_hit_order_trace(tmp.path(), "run1");
    let base_args = vec![
        "output-map".into(),
        cd.display().to_string(),
        "--key".into(),
        "x-sign".into(),
        "--max-mem-hits".into(),
        "2".into(),
        "--groups".into(),
        "1".into(),
    ];

    let v = run_json(&base_args);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["selected_hit_order"], "earliest");
    assert_eq!(v["tree_frontier_with_next"], false);
    assert_eq!(v["selected_hit"]["addr"], "0x8000");
    assert_eq!(v["selected_hit"]["first_idx"], 0);
    assert_eq!(v["hit_candidates"][0]["rank"], 0);
    assert_eq!(v["hit_candidates"][0]["addr"], "0x8000");
    assert_eq!(v["groups"][0]["base64"]["indices"][0]["char"], "q");
    assert_eq!(v["groups"][0]["base64"]["indices"][0]["index"], 42);
    assert_eq!(
        v["groups"][0]["base64"]["decoded_bytes"][0]["formula"],
        "(i0 << 2) | (i1 >> 4)"
    );

    let mut nearest_args = base_args;
    nearest_args.push("--hit-order".into());
    nearest_args.push("nearest".into());
    nearest_args.push("--tree-frontier-with-next".into());
    let v = run_json(&nearest_args);
    assert_eq!(v["selected_hit_order"], "nearest");
    assert_eq!(v["tree_frontier_with_next"], true);
    assert_eq!(v["selected_hit"]["addr"], "0x7000");
    assert_eq!(v["selected_hit"]["first_idx"], 1);
}

#[test]
fn output_map_can_group_aligned_base64_tail() {
    let tmp = tempfile::tempdir().unwrap();
    let fixed = "azYBCM007xAA";
    let tail = &STANDARD.encode([0x00, 0x0a, 0x62, 0x61, 0x05])[2..];
    let cd = make_diff_trace_value(tmp.path(), "run1", &format!("{fixed}{tail}"));
    let v = run_json(&[
        "output-map".into(),
        cd.display().to_string(),
        "--key".into(),
        "x-sign".into(),
        "--max-mem-hits".into(),
        "0".into(),
        "--base64-tail-start".into(),
        fixed.len().to_string(),
        "--base64-tail-align-prefix".into(),
        "AA".into(),
        "--base64-tail-drop".into(),
        "1".into(),
        "--groups".into(),
        "2".into(),
        "--summary".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["base64_context"]["mode"], "aligned_tail");
    assert_eq!(v["base64_context"]["semantic_drop_bytes"], 1);
    assert_eq!(v["groups"][0]["chars"], "AApi");
    assert_eq!(v["groups"][0]["original_output_start"], fixed.len());
    assert_eq!(v["groups"][0]["original_output_end"], fixed.len() + 2);
    assert_eq!(
        v["groups"][0]["decoded_payload"][0]["dropped_by_alignment"],
        true
    );
    assert_eq!(v["groups"][0]["decoded_payload"][1]["semantic_offset"], 0);
    assert_eq!(v["groups"][0]["decoded_payload"][1]["value_hex"], "0a");
    assert_eq!(v["groups"][0]["decoded_payload"][2]["semantic_offset"], 1);
    assert_eq!(v["groups"][0]["decoded_payload"][2]["value_hex"], "62");
    assert_eq!(v["groups"][1]["chars"], "YQU=");
    assert_eq!(v["groups"][1]["decoded_payload"][0]["semantic_offset"], 2);
    assert_eq!(v["groups"][1]["decoded_payload"][0]["value_hex"], "61");

    let v = run_json(&[
        "output-map".into(),
        cd.display().to_string(),
        "--key".into(),
        "x-sign".into(),
        "--max-mem-hits".into(),
        "0".into(),
        "--base64-tail-start".into(),
        fixed.len().to_string(),
        "--base64-tail-align-prefix".into(),
        "AA".into(),
        "--base64-tail-drop".into(),
        "1".into(),
        "--semantic-offset".into(),
        "2".into(),
        "--semantic-count".into(),
        "3".into(),
        "--summary".into(),
    ]);
    assert_eq!(
        v["selected_semantic_range"],
        serde_json::json!({"start": 2, "end": 5, "length": 3})
    );
    assert_eq!(v["selected_group_start"], 1);
    assert_eq!(v["selected_group_end"], 2);
    assert_eq!(v["groups"][0]["chars"], "YQU=");
}

#[test]
fn vm_backtree_branches_word_load_to_byte_writers() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_word_load_byte_branch_trace(tmp.path(), "run1");
    let v = run_json(&[
        "vm-backtree".into(),
        cd.display().to_string(),
        "--idx".into(),
        "5".into(),
        "--reg".into(),
        "x2".into(),
        "--depth".into(),
        "1".into(),
        "--max-nodes".into(),
        "8".into(),
    ]);
    let byte_nexts = v["nodes"][0]["upstream"]["byte_nexts"].as_array().unwrap();
    assert_eq!(byte_nexts.len(), 4);
    assert_eq!(byte_nexts[0]["idx"], 0);
    assert_eq!(byte_nexts[0]["src_value"], "0x41");
    assert_eq!(byte_nexts[0]["offsets"], serde_json::json!([0]));
    assert_eq!(byte_nexts[3]["idx"], 3);
    assert_eq!(byte_nexts[3]["src_value"], "0x44");
    assert_eq!(byte_nexts[3]["offsets"], serde_json::json!([3]));
    assert_eq!(v["highlights"]["word_loads"][0]["ascii"], "ABCD");
    assert_eq!(v["highlights"]["word_loads"][0]["bytes_hex"], "41424344");

    let summary = run_json(&[
        "vm-backtree".into(),
        cd.display().to_string(),
        "--idx".into(),
        "5".into(),
        "--reg".into(),
        "x2".into(),
        "--depth".into(),
        "1".into(),
        "--max-nodes".into(),
        "8".into(),
        "--summary".into(),
    ]);
    assert_eq!(summary["status"], "ready");
    assert_eq!(summary["nodes_returned"], 5);
    assert!(summary.get("nodes").is_none());
    assert_eq!(summary["highlights"]["word_loads"][0]["ascii"], "ABCD");
}

#[test]
fn vm_backstep_uses_target_row_when_it_defines_requested_reg() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_word_load_byte_branch_trace(tmp.path(), "run1");
    let v = run_json(&[
        "vm-backstep".into(),
        cd.display().to_string(),
        "--idx".into(),
        "4".into(),
        "--reg".into(),
        "x2".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["source_value"], "0x44434241");
    assert_eq!(v["local_def"]["idx"], 4);
    assert_eq!(v["local_def"]["asm"], "ldr w2, [x1]");
    assert_eq!(v["upstream"]["status"], "ready");
    assert_eq!(v["upstream"]["byte_nexts"].as_array().unwrap().len(), 4);
}

#[test]
fn byte_lineage_starts_from_last_memory_writer() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_word_load_byte_branch_trace(tmp.path(), "run1");
    let v = run_json(&[
        "byte-lineage".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
        "--before-idx".into(),
        "4".into(),
        "--depth".into(),
        "3".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["steps"][0]["kind"], "last_write");
    assert_eq!(v["steps"][0]["write"]["writer_idx"], 0);
    assert_eq!(v["steps"][0]["write"]["src_value"], "0x41");
    assert_eq!(v["steps"][0]["next"]["idx"], 0);
    assert_eq!(v["steps"][1]["kind"], "reg_source");
    assert_eq!(v["steps"][1]["backstep"]["source_reg"], "x0");
}

#[test]
fn vm_ops_groups_rows_by_vm_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_vm_ops_trace(tmp.path(), "run1");
    let v = run_json(&[
        "vm-ops".into(),
        cd.display().to_string(),
        "--start".into(),
        "0".into(),
        "--end".into(),
        "5".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["ops_returned"], 1);
    let op = &v["ops"][0];
    assert_eq!(op["vm_ip"], "0x5000");
    assert_eq!(op["bytecode_reads"][0]["offset"], "0x5");
    assert_eq!(op["bytecode_reads"][0]["width"], 1);
    assert_eq!(op["bytecode_reads"][0]["value"], "0x3");
    assert_eq!(op["bytecode_reads"][1]["offset"], "0x8");
    assert_eq!(op["bytecode_reads"][1]["width"], 8);
    assert_eq!(op["bytecode_reads"][1]["bytes_le_hex"], "8877665544332211");
    assert_eq!(op["vm_slot_reads"][0]["slot"], 3);
    assert_eq!(op["vm_slot_reads"][0]["value"], "0x1234");
    assert_eq!(op["vm_slot_writes"][0]["slot"], 3);
    assert_eq!(op["vm_slot_writes"][0]["value"], "0xaa");
    assert_eq!(op["dispatches"][0]["idx"], 4);
}

#[test]
fn scan_jni_output_strings_reads_hooks_without_trace_load() {
    let tmp = tempfile::tempdir().unwrap();
    let _cd = make_diff_trace(tmp.path(), "run1", &[0xaa, 0xbb, 0xcc, 0xdd]);
    let v = run_json(&[
        "scan-jni-output-strings".into(),
        tmp.path().display().to_string(),
        "--key".into(),
        "x-sign".into(),
        "--decode-base64".into(),
        "--decode-base64-full".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["count"], 1);
    assert_eq!(v["pairs"][0]["key"], "x-sign");
    assert_eq!(
        v["pairs"][0]["value"],
        STANDARD.encode([0xaa, 0xbb, 0xcc, 0xdd])
    );
    assert_eq!(v["pairs"][0]["base64"]["decoded_len"], 4);
    assert_eq!(v["pairs"][0]["base64"]["decoded_hex"], "aabbccdd");
}

#[test]
fn scan_jni_output_strings_diffs_decoded_base64_outputs() {
    let tmp = tempfile::tempdir().unwrap();
    let _cd1 = make_diff_trace(tmp.path(), "run1", &[0xaa, 0xbb, 0xcc, 0xdd]);
    let _cd2 = make_diff_trace(tmp.path(), "run2", &[0xaa, 0xbb, 0xee, 0xdd]);
    let v = run_json(&[
        "scan-jni-output-strings".into(),
        tmp.path().display().to_string(),
        "--key".into(),
        "x-sign".into(),
        "--diff-base64".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["count"], 2);
    assert_eq!(v["base64_diff"]["status"], "ready");
    assert_eq!(v["base64_diff"]["sample_count"], 2);
    assert_eq!(v["base64_diff"]["compared_len"], 4);
    assert_eq!(v["base64_diff"]["range_semantics"], "[start,end)");
    assert_eq!(v["base64_diff"]["stable_count"], 3);
    assert_eq!(v["base64_diff"]["variable_count"], 1);
    assert_eq!(
        v["base64_diff"]["stable_ranges"],
        serde_json::json!([
            {"start": 0, "end": 2, "length": 2, "hex": "aabb"},
            {"start": 3, "end": 4, "length": 1, "hex": "dd"},
        ])
    );
    assert_eq!(
        v["base64_diff"]["variable_ranges"],
        serde_json::json!([
            {
                "start": 2,
                "end": 3,
                "length": 1,
                "base64_group_start": 0,
                "base64_group_end": 1,
                "base64_groups": 1,
                "base64_char_start": 0,
                "base64_char_end": 4,
            },
        ])
    );
    assert_eq!(
        v["base64_diff"]["first_variable"],
        serde_json::json!({
            "off": 2,
            "base64_group": 0,
            "base64_char_start": 0,
            "base64_char_end": 4,
            "output_map_args": {
                "group_start": 0,
                "groups": 1,
            },
        })
    );
    assert_eq!(v["base64_diff"]["per_byte"][2]["kind"], "VARIABLE");
    assert_eq!(
        v["base64_diff"]["per_byte"][2]["values"],
        serde_json::json!(["0xcc", "0xee"])
    );
    assert_eq!(v["pairs"][0]["base64"]["decoded_hex"], "aabbccdd");
}

#[test]
fn scan_jni_output_strings_aligns_base64_tail_for_diffing() {
    let tmp = tempfile::tempdir().unwrap();
    let fixed = "azYBCM007xAA";
    let tail1 = &STANDARD.encode([0x00, 0x0a, 0x62, 0x61, 0x05])[2..];
    let tail2 = &STANDARD.encode([0x00, 0x0a, 0x63, 0x61, 0x05])[2..];
    let _cd1 = make_diff_trace_value(tmp.path(), "run1", &format!("{fixed}{tail1}"));
    let _cd2 = make_diff_trace_value(tmp.path(), "run2", &format!("{fixed}{tail2}"));
    let v = run_json(&[
        "scan-jni-output-strings".into(),
        tmp.path().display().to_string(),
        "--key".into(),
        "x-sign".into(),
        "--diff-base64".into(),
        "--base64-tail-start".into(),
        fixed.len().to_string(),
        "--base64-tail-align-prefix".into(),
        "AA".into(),
        "--base64-tail-drop".into(),
        "1".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["pairs"][0]["base64_tail"]["semantic_hex"], "0a626105");
    assert_eq!(v["pairs"][1]["base64_tail"]["semantic_hex"], "0a636105");
    assert_eq!(v["base64_tail_diff"]["status"], "ready");
    assert_eq!(v["base64_tail_diff"]["source"], "base64_tail.semantic_hex");
    assert_eq!(v["base64_tail_diff"]["stable_ranges"][0]["hex"], "0a");
    assert_eq!(v["base64_tail_diff"]["per_byte"][1]["kind"], "VARIABLE");
    assert_eq!(
        v["base64_tail_diff"]["per_byte"][1]["values"],
        serde_json::json!(["0x62", "0x63"])
    );
}

#[test]
fn scan_jni_output_strings_reports_tail_repeat_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    let fixed = "azYBCM007xAA";
    let tail1 = &STANDARD.encode([0x00, 0x0a, 0xaa, 0xbb, 0xcc, 0xdd, 0xaa, 0xbb, 0xcc])[2..];
    let tail2 = &STANDARD.encode([0x00, 0x0a, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33])[2..];
    let _cd1 = make_diff_trace_value(tmp.path(), "run1", &format!("{fixed}{tail1}"));
    let _cd2 = make_diff_trace_value(tmp.path(), "run2", &format!("{fixed}{tail2}"));
    let v = run_json(&[
        "scan-jni-output-strings".into(),
        tmp.path().display().to_string(),
        "--key".into(),
        "x-sign".into(),
        "--diff-base64".into(),
        "--base64-tail-start".into(),
        fixed.len().to_string(),
        "--base64-tail-align-prefix".into(),
        "AA".into(),
        "--base64-tail-drop".into(),
        "1".into(),
    ]);
    let repeats = v["base64_tail_diff"]["repeated_ranges_all_samples"]
        .as_array()
        .unwrap();
    assert!(repeats.iter().any(|row| {
        row["src_start"] == 1
            && row["src_end"] == 4
            && row["dst_start"] == 5
            && row["dst_end"] == 8
            && row["length"] == 3
    }));
}

#[test]
fn ollvm_detect_vm_wrapper_uses_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "ollvm-detect-vm".into(),
        cd.display().to_string(),
        "--min-entries".into(),
        "1".into(),
        "--threshold".into(),
        "0.3".into(),
    ]);
    assert_eq!(v["min_entries"], 1);
    assert_eq!(v["threshold"], 0.3);
    assert!(v["count"].as_u64().unwrap() <= 1);
    assert!(v["candidates"].is_array());
}
