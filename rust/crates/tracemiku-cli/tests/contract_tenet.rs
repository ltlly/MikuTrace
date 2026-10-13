//! Black-box contract tests for the `mem-provenance` CLI command.
//!
//! Tenet export reports per-byte provenance without fabricating missing
//! memory. Uses the shared synthetic fixture (synth_deep_dir writes bytes
//! via external_writes.bin, so sources are observable).

mod common;

use common::{run_json, synth_deep_dir};

#[test]
fn mem_provenance_returns_structured_provenance() {
    let (_tmp, cd) = synth_deep_dir();
    let v = run_json(&[
        "mem-provenance",
        cd.to_str().unwrap(),
        "--addr",
        "0x2000",
        "--count",
        "8",
    ]);
    assert_eq!(v["addr"], "0x2000", "0x2000 parsed");
    assert_eq!(v["count"], 8);
    let bytes = v["bytes"].as_array().expect("bytes array");
    assert_eq!(bytes.len(), 8, "one entry per byte");
    for b in bytes {
        assert!(b["kind"].is_string(), "every byte has a source kind: {b}");
        assert!(b["addr"].is_string());
        assert!(b["byte"].is_u64());
        assert!(b["last_writer"].is_object());
    }
}

#[test]
fn mem_provenance_zero_length_is_error() {
    use std::process::Command;
    let (_tmp, cd) = synth_deep_dir();
    let out = Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
        .args([
            "mem-provenance",
            cd.to_str().unwrap(),
            "--addr",
            "0x2000",
            "--count",
            "0",
        ])
        .output()
        .expect("run tracemiku-cli");
    assert!(!out.status.success(), "len 0 must fail");
    assert_eq!(out.status.code(), Some(1));
    let failure: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(failure["status"], "error");
    assert_eq!(failure["error"]["code"], "invalid_argument");
    let message = failure["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("positive"),
        "error.message explains the failure: {message}"
    );
}
