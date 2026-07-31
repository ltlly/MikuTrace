//! Black-box contract tests for the `mem-tenet` CLI command.
//!
//! Tenet export reports per-byte provenance without fabricating missing
//! memory. Uses the shared synthetic fixture (synth_deep_dir writes bytes
//! via external_writes.bin, so sources are observable).

mod common;

use common::{run_json, synth_deep_dir};

#[test]
fn mem_tenet_returns_structured_provenance() {
    let (_tmp, cd) = synth_deep_dir();
    let v = run_json(&[
        "mem-tenet",
        cd.to_str().unwrap(),
        "--addr",
        "0x2000",
        "--length",
        "8",
    ]);
    assert_eq!(v["addr"], 8192, "0x2000 parsed");
    assert_eq!(v["len"], 8);
    let bytes = v["bytes"].as_array().expect("bytes array");
    assert_eq!(bytes.len(), 8, "one entry per byte");
    for b in bytes {
        let src = &b["source"];
        assert!(src["kind"].is_string(), "every byte has a source kind: {b}");
        assert!(b["offset"].is_u64());
        assert!(b["value"].is_u64());
    }
}

#[test]
fn mem_tenet_zero_length_is_error() {
    use std::process::Command;
    let (_tmp, cd) = synth_deep_dir();
    let out = Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
        .args([
            "mem-tenet",
            cd.to_str().unwrap(),
            "--addr",
            "0x2000",
            "--length",
            "0",
        ])
        .output()
        .expect("run tracemiku-cli");
    assert!(!out.status.success(), "len 0 must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("out of range"),
        "stderr explains the failure: {stderr}"
    );
}
