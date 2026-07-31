//! Black-box contract tests for the `completions` CLI command.
//!
//! The completion generator is a committed surface: every supported shell
//! must emit a non-empty script that references the binary's subcommands, so
//! a refactor cannot silently break tab-completion for AI-driven shells.

use std::process::Command;

fn run_completion(shell: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_tracemiku-cli"))
        .args(["completions", shell])
        .output()
        .expect("run tracemiku-cli completions");
    assert!(
        out.status.success(),
        "completions {shell} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn bash_completion_is_non_empty_and_mentions_subcommands() {
    let script = run_completion("bash");
    assert!(script.len() > 200, "bash script too short");
    for sub in ["query", "records", "taint-bwd", "mem-tenet"] {
        assert!(script.contains(sub), "bash completion must reference {sub}");
    }
}

#[test]
fn zsh_completion_is_non_empty() {
    let script = run_completion("zsh");
    assert!(script.len() > 200, "zsh script too short");
}

#[test]
fn fish_completion_is_non_empty() {
    let script = run_completion("fish");
    assert!(script.len() > 100, "fish script too short");
}

#[test]
fn powershell_completion_is_non_empty() {
    let script = run_completion("powershell");
    assert!(script.len() > 100, "powershell script too short");
}
