//! Shared black-box test helpers for CLI contract tests.
//!
//! `synth_call_dir` builds the 9-record trace_root_two_callees fixture with
//! known_offsets {0x0:f, 0x100:f_alpha, 0x200:f_beta}; `synth_deep_dir` builds
//! the 12-record deep trace with stores, JNI NewStringUTF pairs, and external
//! writes. `run_json` invokes the real CLI binary; `assert_valid` checks a
//! JSON value against a schema.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;

pub fn run_json(args: &[&str]) -> serde_json::Value {
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

pub fn validate(schema: &serde_json::Value, value: &serde_json::Value) -> Vec<String> {
    let validator = jsonschema::validator_for(schema).expect("valid json schema");
    validator
        .iter_errors(value)
        .map(|e| e.to_string())
        .collect()
}

pub fn assert_valid(schema: serde_json::Value, value: &serde_json::Value) {
    let errors = validate(&schema, value);
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

pub fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    std::fs::create_dir_all(run.join("calls")).unwrap();
    let cd = run.join("calls").join("call_001_tid100_9r_2ms");
    std::fs::create_dir(&cd).unwrap();
    let mut buf = vec![0u8; 272 * 9];
    let pcs: [u64; 9] = [
        0x100000, 0x100004, 0x100100, 0x100104, 0x100008, 0x100200, 0x100204, 0x100208, 0x10000c,
    ];
    for (i, pc) in pcs.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"callIdx":1,"tid":100,"records":9,"ms":2,"retval":"0x0","truncated":false,"last_insn_is_ret":true,"known_offsets":{"0x0":"f","0x100":"f_alpha","0x200":"f_beta"}}"#,
    )
    .unwrap();
    std::fs::write(
        run.join("meta.json"),
        r#"{"pkg":"tst","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    (tmp, cd)
}

pub fn synth_deep_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    std::fs::create_dir_all(run.join("calls")).unwrap();
    let cd = run.join("calls").join("call_002_tid200_12r_4ms");
    std::fs::create_dir(&cd).unwrap();
    let out_addr = 0x2000u64;
    let insts: [u32; 12] = [
        0xd503201f, 0xf9000020, 0x94000006, 0xd503201f, 0xb9000820, 0x94000008, 0xd503201f,
        0x39000020, 0xd503201f, 0xd65f03c0, 0xd503201f, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; 272 * 12];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        let (x0, x1) = match i {
            1 => (0x68676f2e6f727061u64, out_addr),
            4 => (0x65756c6176u64, out_addr),
            7 => (0x21u64, out_addr),
            _ => (0, 0),
        };
        buf[off + 8..off + 16].copy_from_slice(&x0.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"callIdx":2,"tid":200,"records":12,"ms":4,"retval":"0x0","truncated":false,"last_insn_is_ret":true,"known_offsets":{"0x0":"f_root","0x20":"f_builder","0x30":"f_builder2"}}"#,
    )
    .unwrap();
    std::fs::write(
        run.join("meta.json"),
        r#"{"pkg":"tst","so":"libt","method":"f","cmd":1,"module":{"name":"libt.so","base":"0x100000","size":65536},"fn_addr":"0x100000"}"#,
    )
    .unwrap();
    let jni = [
        r#"{"trace_idx":3,"id":"GetStringUTFChars","ret":"apro.oghvalue!"}"#,
        r#"{"trace_idx":6,"id":"NewStringUTF","args":{"bytes":"apro.oghvalue!"}}"#,
        r#"{"trace_idx":10,"id":"NewStringUTF","args":{"bytes":"apro.oghvalue!"}}"#,
    ];
    std::fs::write(cd.join("jni_hooks.jsonl"), jni.join("\n")).unwrap();
    let mut ext = Vec::new();
    for (i, b) in b"apro.oghvalue!".iter().enumerate() {
        ext.extend_from_slice(&(5u64 + (i as u64 % 3)).to_le_bytes());
        ext.extend_from_slice(&(out_addr + i as u64).to_le_bytes());
        ext.push(*b);
    }
    std::fs::write(cd.join("external_writes.bin"), ext).unwrap();
    (tmp, cd)
}
