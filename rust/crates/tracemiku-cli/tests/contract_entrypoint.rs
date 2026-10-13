//! 统一 Python 入口的命令发现与调用契约；防止内部二进制测试掩盖包装层歧义。

mod common;

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use common::{assert_valid, run_json, synth_call_dir};
use serde_json::{json, Value};

const RETIRED: &[&str] = &[
    "jni-output-strings",
    "scan-jni-output-strings",
    "diff-traces",
    "stats",
    "resolve-trace-addr",
    "crypto-scan",
    "block-for-pc",
    "auto-phase-detect",
    "ollvm-detect-vm",
    "idxs-for-pc",
    "idxs-for-block",
    "idxs-touching-addr",
    "idxs-touching-range",
    "mem-tenet",
    "string-provenance",
    "hash-finalize-detect",
    "output-map",
    "jobj-history",
    "forward-dep-tree",
    "coverage",
    "data-chase",
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
                    "type": "object", "required": ["name", "about", "implementation", "stability"],
                    "properties": {
                        "name": {"type": "string"}, "about": {"type": "string"},
                        "implementation": {"enum": ["host", "rust"]},
                        "stability": {"enum": ["stable", "experimental"]}
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
        "experimental",
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
        vec!["records", call, "--indices", "0", "--regs", "x0"],
        vec!["resolve", call, "--so", "libt.so", "--off", "0x100"],
        vec!["list", run, "--json"],
        vec!["info", call],
    ] {
        assert_eq!(entry_json(&args), run_json(&args), "{:?}", args);
    }
}

#[test]
fn every_discoverable_command_and_argument_has_help() {
    fn check(command: &Value, path: Vec<&str>) {
        let name = path.join(" ");
        assert!(
            !command["about"].as_str().unwrap_or("").trim().is_empty(),
            "{name}"
        );
        for arg in command["args"].as_array().unwrap() {
            assert!(
                !arg["help"].as_str().unwrap_or("").trim().is_empty(),
                "{name}: missing help for {}",
                arg["id"]
            );
        }
        for flag in ["-h", "--help"] {
            let mut args = path.clone();
            args.push(flag);
            let output = entry(&args);
            assert!(output.status.success(), "{name} {flag}");
            assert!(String::from_utf8_lossy(&output.stdout).contains(path.last().unwrap()));
        }
        for child in command["subcommands"].as_array().unwrap() {
            let mut child_path = path.clone();
            child_path.push(child["name"].as_str().unwrap());
            let detail = entry_json(&["capabilities", "--command", &child_path.join(" ")]);
            assert_eq!(detail["commands"][0]["stability"], "experimental");
            check(child, child_path);
        }
    }
    let caps = entry_json(&["capabilities"]);
    for command in caps["commands"].as_array().unwrap() {
        let name = command["name"].as_str().unwrap();
        assert!(
            !command["about"].as_str().unwrap_or("").trim().is_empty(),
            "{name}"
        );
        let detail = entry_json(&["capabilities", "--command", name]);
        check(&detail["commands"][0], vec![name]);
    }
}

#[test]
fn target_protocol_options_are_rejected() {
    let (_tmp, cd) = synth_call_dir();
    for name in ["output-backtrace", "base64-map"] {
        let result = entry(&[name, cd.to_str().unwrap(), "--key", "arbitrary"]);
        assert_eq!(result.status.code(), Some(2));
    }
}
