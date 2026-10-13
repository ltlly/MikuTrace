//! 明确输出输入的边界契约：无输入、空输入、缺少内存证据。
mod common;
use common::{run_json, synth_deep_dir};

#[test]
fn base64_map_rejects_missing_or_empty_value() {
    let (_tmp, cd) = synth_deep_dir();
    for (extra, exit_code) in [(vec![], 2), (vec!["--value", ""], 1)] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
            .args(["base64-map", cd.to_str().unwrap()])
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(exit_code));
        if exit_code == 2 {
            assert!(String::from_utf8_lossy(&out.stderr).contains("--value"));
            continue;
        }
        let failure: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(failure["status"], "error");
        assert!(failure["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--value"));
    }
}

#[test]
fn output_backtrace_requires_exactly_one_explicit_input() {
    let (_tmp, cd) = synth_deep_dir();
    for extra in [vec![], vec!["--value", "text", "--bytes-hex", "aabb"]] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
            .args(["output-backtrace", cd.to_str().unwrap()])
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("--value"));
    }
}

#[test]
fn base64_map_without_matching_memory_preserves_the_explicit_value() {
    let (_tmp, cd) = synth_deep_dir();
    let value = run_json(&[
        "base64-map",
        cd.to_str().unwrap(),
        "--value",
        "qrvM3Q==",
        "--groups",
        "1",
    ]);
    assert_eq!(value["status"], "ready");
    assert_eq!(value["source"]["kind"], "value");
    assert_eq!(value["source"]["value"], "qrvM3Q==");
    assert!(value["selected_hit"].is_null());
    assert!(value["groups"].is_array());
}
