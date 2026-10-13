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

fn append_external_write(cd: &std::path::Path, idx: u64, addr: u64, byte: u8) {
    let mut rec = Vec::with_capacity(17);
    rec.extend_from_slice(&idx.to_le_bytes());
    rec.extend_from_slice(&addr.to_le_bytes());
    rec.push(byte);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(cd.join("external_writes.bin"))
        .unwrap();
    f.write_all(&rec).unwrap();
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

fn make_output_trace(root: &std::path::Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    std::fs::write(dir.join("trace.bin"), &buf).unwrap();
    std::fs::write(dir.join("meta.json"), r#"{"records":1}"#).unwrap();
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
    let v = run_json(&["info".into(), cd.display().to_string()]);
    assert_eq!(v["records"], 4);
    assert_eq!(v["last_insn_is_ret"], true);
    assert_eq!(v["is_complete"], true);
}

#[test]
fn records_wrapper_preserves_core_output() {
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
fn string_provenance_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "mem-provenance".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
        "--count".into(),
        "4".into(),
    ]);
    assert_eq!(v["addr"], "0x7000");
    assert_eq!(v["count"], 4);
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
fn fn_summary_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "functions".into(),
        cd.display().to_string(),
        "--fn".into(),
        "f".into(),
    ]);
    let v = &v["summary"];
    assert_eq!(v["status"], "ready");
    assert_eq!(v["fn"], "f");
    assert_eq!(v["pc"], "0x100000");
    assert!(v["hot_blocks"].is_array());
}

#[test]
fn inspect_wrappers_use_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();

    let v = run_json(&[
        "pc-hits".into(),
        cd.display().to_string(),
        "0x100000".into(),
        "--cursor".into(),
        "1".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["before"], serde_json::json!([0]));

    let v = run_json(&[
        "last-write-of-reg".into(),
        cd.display().to_string(),
        "--reg".into(),
        "x2".into(),
        "--before".into(),
        "4".into(),
    ]);
    assert_eq!(v["idx"], 1);

    let v = run_json(&[
        "next-use-of-reg".into(),
        cd.display().to_string(),
        "--reg".into(),
        "x1".into(),
        "--after".into(),
        "0".into(),
    ]);
    assert_eq!(v["idx"], 1);

    let v = run_json(&[
        "search".into(),
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
        "records".into(),
        cd.display().to_string(),
        "--indices".into(),
        "0".into(),
        "--regs".into(),
        "x0".into(),
    ]);
    assert_eq!(v["records"][0]["regs"]["x0"], "0x6f6c6c6568");
}

#[test]
fn fork_events_wrapper_filters_status() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "events".into(),
        "--source".into(),
        "fork".into(),
        cd.display().to_string(),
        "--status".into(),
        "failed_ptrace_conflict".into(),
    ]);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["events"][0]["event"]["child_pid"], 456);
}
#[test]
fn memory_query_wrappers_use_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();
    append_external_write(&cd, 2, 0x7002, b'X');
    let call = cd.display().to_string();
    let v = run_json(&[
        "last-write-of-addr".into(),
        call.clone(),
        "--addr".into(),
        "0x7000".into(),
    ]);
    assert_eq!(v["writer_idx"], 0);
    let v = run_json(&[
        "last-write-of-addr".into(),
        call.clone(),
        "--addr".into(),
        "0x7002".into(),
        "--before-idx".into(),
        "3".into(),
        "--with-external".into(),
    ]);
    assert_eq!(v["writer_idx"], 2);
    assert_eq!(v["write_kind"], "x");
    assert_eq!(v["src_value"], "0x58");
    let v = run_json(&[
        "mem-accesses".into(),
        call.clone(),
        "--addr".into(),
        "0x7002".into(),
        "--start".into(),
        "2".into(),
        "--end".into(),
        "3".into(),
        "--kind".into(),
        "write".into(),
    ]);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["events"][0]["source"], "external");
    assert_eq!(v["events"][0]["bytes"], serde_json::json!([88]));
    let v = run_json(&[
        "mem-accesses".into(),
        call.clone(),
        "--addr".into(),
        "0x7000".into(),
    ]);
    assert_eq!(v["events"][0]["kind"], "write");
    assert_eq!(v["events"][0]["idx"], 0);
    assert_eq!(v["events"][1]["kind"], "read");
    assert_eq!(v["events"][1]["idx"], 1);
    let v = run_json(&[
        "mem-accesses".into(),
        call.clone(),
        "--addr".into(),
        "0x7004".into(),
        "--size".into(),
        "4".into(),
    ]);
    assert_eq!(v["events"][0]["size"], 4);
    assert_eq!(v["events"][1]["size"], 4);
    let v = run_json(&[
        "find-mem-pattern".into(),
        call,
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
fn call_chain_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "backtrace".into(),
        "--lr-clues".into(),
        cd.display().to_string(),
        "--idx".into(),
        "2".into(),
        "--limit".into(),
        "3".into(),
    ]);
    let v = &v["lr_clues"];
    assert_eq!(v["start_idx"], 2);
    assert_eq!(v["chain"][0]["lr"], "0x100008");
    assert_eq!(v["chain"][0]["caller_pc"], "0x100004");
}

#[test]
fn dep_graph_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "bfs-slice".into(),
        "--view".into(),
        "graph".into(),
        cd.display().to_string(),
        "--idx".into(),
        "1".into(),
        "--depth".into(),
        "2".into(),
        "--limit".into(),
        "16".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["seed"]["kind"], "idx");
    assert_eq!(v["seed"]["idx"], 1);
    assert!(v["graph"]["nodes"].as_array().unwrap().len() >= 2);
    assert!(v["graph"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|edge| edge["kind"] == "mem"));
}

#[test]
fn bfs_slice_wrapper_returns_enriched_rows() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "bfs-slice".into(),
        cd.display().to_string(),
        "--idx".into(),
        "1".into(),
        "--limit".into(),
        "32".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["mode"], "union");
    assert_eq!(v["seed"]["kind"], "idx");
    let slice = v["slice"].as_array().unwrap();
    assert!(slice.contains(&serde_json::json!(1)));
    let rows = v["rows"].as_array().unwrap();
    assert!(!rows.is_empty(), "rows must be enriched: {v}");
    assert!(rows[0]["pc"].as_str().unwrap_or("").starts_with("0x"));
}

#[test]
fn bfs_slice_intersection_combines_two_seeds() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "bfs-slice".into(),
        cd.display().to_string(),
        "--idxs".into(),
        "1,2".into(),
        "--mode".into(),
        "intersection".into(),
    ]);
    assert_eq!(v["mode"], "intersection");
    let seeds = v["seeds"].as_array().unwrap();
    assert_eq!(seeds.len(), 2);
}

#[test]
fn forward_dep_tree_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "bfs-slice".into(),
        "--direction".into(),
        "forward".into(),
        "--view".into(),
        "graph".into(),
        cd.display().to_string(),
        "--idx".into(),
        "0".into(),
        "--depth".into(),
        "4".into(),
        "--limit".into(),
        "16".into(),
    ]);
    assert_eq!(v["status"], "ready");
    let nodes = v["graph"]["nodes"].as_array().unwrap();
    assert!(!nodes.is_empty());
    assert_eq!(nodes[0]["idx"], 0);
}

#[test]
fn taint_wrappers_pass_scan_limit() {
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
        "--scan-limit".into(),
        "0".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert!(v["scan_limit_used"].is_null());
    assert!(v["stop_reason"].as_str().is_some());
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
        "mem-dump".into(),
        "--compare-at".into(),
        "0".into(),
        cd.display().to_string(),
        "--at".into(),
        "1".into(),
        "--addr".into(),
        "0x7000".into(),
        "--count".into(),
        "1".into(),
    ]);
    assert_eq!(v["at"], 1);
    assert_eq!(v["count"], 1);
    assert_eq!(v["bytes"].as_array().unwrap().len(), 1);
}

#[test]
fn mem_flow_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "mem-accesses".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
        "--size".into(),
        "1".into(),
        "--kind".into(),
        "write".into(),
        "--limit".into(),
        "1".into(),
    ]);
    assert_eq!(v["addr"], "0x7000");
    assert_eq!(v["returned"], 1);
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["events"][0]["bytes"].as_array().unwrap().len(), 1);
}

#[test]
fn crypto_includes_memory_fingerprints() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&["crypto".into(), cd.display().to_string()]);
    let v = &v["mem_scan"];
    assert!(v["scanned"].as_u64().unwrap() > 0);
    let primitives = v["primitives"].as_array().unwrap();
    assert!(
        primitives.len() >= 22,
        "crypto primitive catalog should stay populated"
    );
    assert!(primitives[0]["name"].is_string());
    assert!(primitives[0]["pattern"].is_string());
    assert!(primitives[0]["hit_count"].is_number());
    assert!(primitives[0]["hits"].is_array());
    assert!(v["any_hit"].is_boolean());
}

#[test]
fn jni_calls_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "jni-calls".into(),
        cd.display().to_string(),
        "--limit".into(),
        "5".into(),
    ]);
    assert!(v["vtable_size"].as_u64().unwrap() > 100);
    assert!(v["hits"].is_array());
}

#[test]
fn jobj_history_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "jni-calls".into(),
        cd.display().to_string(),
        "--jobject".into(),
        "0x2222".into(),
        "--limit".into(),
        "5".into(),
    ]);
    assert_eq!(v["returned"], 0);
    assert!(v["hits"].is_array());
}

#[test]
fn jni_strings_wrapper_preserves_core_output() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&[
        "jni-calls".into(),
        "--strings".into(),
        cd.display().to_string(),
        "--limit".into(),
        "5".into(),
        "--max-len".into(),
        "32".into(),
    ]);
    assert_eq!(v["encoding"], "modified_utf8");
    assert!(v["hits"].is_array());
}

#[test]
fn output_backtrace_starts_from_explicit_output_value() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_output_trace(tmp.path(), "run1");
    let v = run_json(&[
        "output-backtrace".into(),
        cd.display().to_string(),
        "--value".into(),
        STANDARD.encode([0xaa, 0xbb, 0xcc, 0xdd]),
        "--max-mem-hits".into(),
        "1".into(),
        "--writes-per-hit".into(),
        "0".into(),
        "--skip-taint".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["strategy"], "output_to_input_backward_trace");
    assert_eq!(v["source"]["kind"], "value");
    assert_eq!(
        v["source"]["value"],
        STANDARD.encode([0xaa, 0xbb, 0xcc, 0xdd])
    );
    assert_eq!(v["patterns"][0]["kind"], "observed");
    assert_eq!(v["taint"]["skipped"], true);
    assert!(v["taint"]["queued"].as_array().unwrap().is_empty());
}

#[test]
fn vm_backtree_branches_word_load_to_byte_writers() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_word_load_byte_branch_trace(tmp.path(), "run1");
    let v = run_json(&[
        "experimental".into(),
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
        "--vm-slot-bytes".into(),
        "8".into(),
        "--vm-ip-reg".into(),
        "x9".into(),
        "--vm-state-reg".into(),
        "x10".into(),
        "--vm-dispatch-reg".into(),
        "x11".into(),
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
        "experimental".into(),
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
        "--vm-slot-bytes".into(),
        "8".into(),
        "--vm-ip-reg".into(),
        "x9".into(),
        "--vm-state-reg".into(),
        "x10".into(),
        "--vm-dispatch-reg".into(),
        "x11".into(),
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
        "experimental".into(),
        "vm-backstep".into(),
        cd.display().to_string(),
        "--idx".into(),
        "4".into(),
        "--reg".into(),
        "x2".into(),
        "--vm-slot-bytes".into(),
        "8".into(),
        "--vm-ip-reg".into(),
        "x9".into(),
        "--vm-state-reg".into(),
        "x10".into(),
        "--vm-dispatch-reg".into(),
        "x11".into(),
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
fn byte_lineage_origin_classifies_sources() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_word_load_byte_branch_trace(tmp.path(), "run1");

    // ExternalWrite 种子先注入：确保任何分析上下文加载（含 sidecar 缓存）都包含它
    append_external_write(&cd, 5, 0x7001, b'X');

    // Register: 0x7000 的链 = last_write(strb w0, kind=w, src_reg=w0) -> reg_source(w0)
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
    assert_eq!(v["origin"]["register"]["reg"], "x0");
    assert_eq!(v["origin"]["register"]["idx"], 0);

    // ExternalWrite: 0x7001 的最后写入是 external（idx=5）
    let v2 = run_json(&[
        "byte-lineage".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7001".into(),
        "--before-idx".into(),
        "6".into(),
        "--depth".into(),
        "2".into(),
    ]);
    assert_eq!(v2["status"], "ready");
    assert_eq!(v2["origin"]["external_write"]["idx"], 5);
    assert_eq!(v2["origin"]["external_write"]["addr"], 0x7001);

    // Unknown: 从未被写的地址
    let v3 = run_json(&[
        "byte-lineage".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x9000".into(),
        "--before-idx".into(),
        "4".into(),
        "--depth".into(),
        "2".into(),
    ]);
    assert_eq!(v3["status"], "ready");
    assert_eq!(v3["origin"], "unknown");
}

#[test]
fn byte_lineage_count_traces_consecutive_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_word_load_byte_branch_trace(tmp.path(), "run1");
    let v = run_json(&[
        "byte-lineage".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
        "--before-idx".into(),
        "4".into(),
        "--count".into(),
        "2".into(),
        "--depth".into(),
        "2".into(),
        "--compact".into(),
    ]);
    assert_eq!(v["status"], "ready");
    assert_eq!(v["count"], 2);
    assert_eq!(v["error_count"], 0);
    assert_eq!(
        v["decision_counts"],
        serde_json::json!([{"decision": "stop", "count": 2}])
    );
    assert_eq!(v["step_stats"]["min"], 2);
    assert_eq!(v["step_stats"]["max"], 2);
    assert_eq!(v["frontier_groups"].as_array().unwrap().len(), 1);
    assert_eq!(v["frontier_groups"][0]["decision"], "stop");
    assert_eq!(v["frontier_groups"][0]["count"], 2);
    assert_eq!(
        v["frontier_groups"][0]["offset_ranges"],
        serde_json::json!([[0, 2]])
    );
    let results = v["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["addr"], "0x7000");
    assert_eq!(results[0]["lineage"]["path"][0]["writer_idx"], 0);
    assert_eq!(results[0]["lineage"]["path"][0]["src_value"], "0x41");
    assert_eq!(results[1]["addr"], "0x7001");
    assert_eq!(results[1]["lineage"]["path"][0]["writer_idx"], 1);
    assert_eq!(results[1]["lineage"]["path"][0]["src_value"], "0x42");

    let limited = run_json(&[
        "byte-lineage".into(),
        cd.display().to_string(),
        "--addr".into(),
        "0x7000".into(),
        "--before-idx".into(),
        "4".into(),
        "--count".into(),
        "2".into(),
        "--depth".into(),
        "1".into(),
        "--compact".into(),
    ]);
    assert_eq!(
        limited["decision_counts"],
        serde_json::json!([{"decision": "depth_limit", "count": 2}])
    );
}

#[test]
fn vm_ops_groups_rows_by_vm_ip() {
    let tmp = tempfile::tempdir().unwrap();
    let cd = make_vm_ops_trace(tmp.path(), "run1");
    let v = run_json(&[
        "experimental".into(),
        "vm-ops".into(),
        cd.display().to_string(),
        "--start".into(),
        "0".into(),
        "--end".into(),
        "5".into(),
        "--vm-slot-bytes".into(),
        "8".into(),
        "--vm-ip-reg".into(),
        "x21".into(),
        "--vm-state-reg".into(),
        "x25".into(),
        "--vm-dispatch-reg".into(),
        "x23".into(),
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

    let chunked = run_json(&[
        "experimental".into(),
        "vm-ops".into(),
        cd.display().to_string(),
        "--start".into(),
        "0".into(),
        "--end".into(),
        "5".into(),
        "--vm-slot-bytes".into(),
        "8".into(),
        "--vm-ip-reg".into(),
        "x21".into(),
        "--vm-state-reg".into(),
        "x25".into(),
        "--vm-dispatch-reg".into(),
        "x23".into(),
        "--chunk-size".into(),
        "2".into(),
        "--summary".into(),
    ]);
    assert_eq!(chunked["source_requested"], 5);
    assert_eq!(chunked["source_returned"], 5);
    assert_eq!(chunked["source_maybe_truncated"], false);
    assert_eq!(chunked["source_chunks"], 3);
    assert_eq!(chunked["vm_base_ip"], "0x5000");
    assert_eq!(chunked["ops_returned"], 1);
}
