//! 明确输出输入的边界契约：无输入、空输入、缺少内存证据。
mod common;
use common::synth_deep_dir;

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
