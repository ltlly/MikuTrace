//! 统一 Python 入口的命令发现与调用契约；防止内部二进制测试掩盖包装层歧义。

mod common;

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use common::{assert_valid, run_json, synth_call_dir};
use serde_json::{json, Value};

const RETIRED: &[&str] = &[
    "web",
    "view",
    "api",
    "query",
    "search-asm",
    "search-pc",
    "asm-tokens-for-pcs",
    "reg-at-idx",
    "bg-status",
    "decomp-status",
    "bn-sidecar-status",
    "cfg-svg",
    "hlil-for-pc",
    "hlil-for-fn",
    "bn-cfg-for-pc",
    "bn-cfg-svg-for-pc",
];

fn entry(args: &[&str]) -> Output {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    Command::new("python3")
        .arg(root.join("tracemiku"))
        .args(args)
        .env("TRACEMIKU_CLI_BIN", env!("CARGO_BIN_EXE_tracemiku-cli"))
        .current_dir(root)
        .output()
        .expect("run unified entrypoint")
}

fn entry_json(args: &[&str]) -> Value {
    let out = entry(args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("one JSON document on stdout")
}

#[test]
fn discovery_is_compact_unique_and_has_no_retired_commands() {
    let value = entry_json(&["capabilities"]);
    assert_valid(
        json!({
            "type": "object",
            "required": ["schema_version", "tool", "commands", "output_contract", "capture_extensions"],
            "properties": {
                "schema_version": {"const": 2},
                "tool": {"const": "tracemiku"},
                "commands": {"type": "array", "items": {
                    "type": "object", "required": ["name", "about", "implementation"],
                    "properties": {
                        "name": {"type": "string"}, "about": {"type": "string"},
                        "implementation": {"enum": ["host", "rust"]}
                    }
                }}
            }
        }),
        &value,
    );
    let commands = value["commands"].as_array().unwrap();
    let names: HashSet<_> = commands
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), commands.len());
    for name in [
        "trace",
        "probe",
        "doctor",
        "capabilities",
        "records",
        "resolve",
        "vm-ops",
    ] {
        assert!(names.contains(name), "missing {name}");
    }
    for name in RETIRED {
        assert!(!names.contains(name), "retired command advertised: {name}");
    }
    assert!(
        commands.iter().all(|c| c.get("args").is_none()),
        "default discovery is a summary"
    );
}

#[test]
fn detailed_discovery_matches_capture_help_and_analysis_args() {
    for name in ["capabilities", "trace", "probe", "doctor", "records"] {
        let value = entry_json(&["capabilities", "--command", name]);
        let commands = value["commands"].as_array().unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0]["name"], name);
        assert_valid(
            json!({
                "type": "object", "required": ["args", "subcommands"],
                "properties": {"args": {"type": "array", "items": {
                    "type": "object",
                    "required": ["id", "long", "short", "positional", "required", "action", "help", "default_values", "possible_values"]
                }}}
            }),
            &commands[0],
        );
        let help = entry(&[name, "--help"]);
        assert!(help.status.success());
        let help = String::from_utf8_lossy(&help.stdout);
        for arg in commands[0]["args"].as_array().unwrap() {
            if let Some(flag) = arg["long"].as_str() {
                assert!(
                    help.contains(&format!("--{flag}")),
                    "{name}: undispatchable --{flag}"
                );
            }
        }
    }
}

#[test]
fn retired_commands_are_rejected_even_with_help() {
    for name in RETIRED {
        let out = entry(&[name, "--help"]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{name} must not remain an alias"
        );
    }
    let out = entry(&["capabilities", "--command", "query"]);
    assert_eq!(out.status.code(), Some(2));
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["code"], "unknown_command");
}

#[test]
fn specialized_queries_and_metadata_use_the_same_rust_contract() {
    let (_tmp, cd) = synth_call_dir();
    let call = cd.to_str().unwrap();
    let run = cd.parent().unwrap().parent().unwrap().to_str().unwrap();
    for args in [
        vec!["records", call, "--count", "2", "--regs", "x0,sp"],
        vec!["reg-value-at", call, "--idx", "0", "--reg", "x0"],
        vec!["resolve", call, "--so", "libt.so", "--off", "0x100"],
        vec!["list", run, "--json"],
        vec!["info", call, "--json"],
    ] {
        assert_eq!(entry_json(&args), run_json(&args), "{:?}", args);
    }
}
