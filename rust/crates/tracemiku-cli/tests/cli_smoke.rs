use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_3r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100008];
    let insts: [u32; 3] = [0xf9000020, 0xd503201f, 0xd65f03c0]; // str x0,[x1]; nop; ret
    let hello: u64 = u64::from_le_bytes([b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
    let x1: u64 = 0x7000;
    let mut buf = vec![0u8; 272 * 3];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&hello.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"records":3,"tid":100,"ms":1,"truncated":false,"known_offsets":{"0x0":"f_root"},"fork_events":[{"child_pid":123,"attach_status":"success"},{"child_pid":456,"attach_status":"failed_ptrace_conflict"}]}"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#,
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

#[test]
fn info_json_reports_call_shape() {
    let (_tmp, cd) = synth_call_dir();
    let v = run_json(&["info".into(), cd.display().to_string(), "--json".into()]);
    assert_eq!(v["records"], 3);
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
    assert_eq!(v["records"][0]["idx"], 0);
    assert_eq!(v["records"][0]["pc"], "0x100000");
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
fn inspect_wrappers_use_server_wire_shape() {
    let (_tmp, cd) = synth_call_dir();

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
    assert_eq!(v["hits"][0]["idx"], 2);

    let v = run_json(&[
        "so-stats".into(),
        cd.display().to_string(),
        "--top".into(),
        "5".into(),
    ]);
    assert_eq!(v["records"], 3);
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
