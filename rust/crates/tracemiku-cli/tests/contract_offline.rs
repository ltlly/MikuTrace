//! 统一入口与 core 的离线一致性；夹具不需要设备、服务或反编译器。
mod common;

use common::{assert_valid, synth_deep_dir};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};
use tracemiku_core::analysis::{self, AnalysisContext, Query};

fn entry(args: &[&str]) -> Output {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    Command::new("python3")
        .arg(root.join("tracemiku"))
        .args(args)
        .env("TRACEMIKU_CLI_BIN", env!("CARGO_BIN_EXE_tracemiku-cli"))
        .current_dir(root)
        .output()
        .unwrap()
}

fn request<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

// CFG 的集合顺序没有语义；其余字段须逐一相等，不能过滤掉证据或截断信息。
fn normalize(mut value: Value) -> Value {
    for field in ["blocks", "edges"] {
        if let Some(rows) = value.get_mut(field).and_then(Value::as_array_mut) {
            rows.sort_by_key(Value::to_string);
        }
    }
    value
}

#[test]
fn unified_entrypoint_matches_typed_core_queries_offline() {
    let (_tmp, cd) = synth_deep_dir();
    let context = AnalysisContext::load(cd.clone()).unwrap();
    let cases: Vec<(&str, Vec<&str>, Query)> = vec![
        ("meta", vec![], Query::Meta),
        (
            "trace-replay",
            vec!["--start", "0", "--count", "9"],
            Query::TraceReplay(request(json!({"start":0,"count":9}))),
        ),
        (
            "records",
            vec!["--start", "1", "--count", "3", "--regs", "x0,x1"],
            Query::Records(request(json!({"start":1,"count":3,"regs":"x0,x1"}))),
        ),
        ("record", vec!["1"], Query::Record(1)),
        ("cfg", vec![], Query::Cfg(request(json!({})))),
        ("functions", vec![], Query::Functions),
        (
            "search",
            vec!["ret", "--max-results", "4", "--cursor", "4"],
            Query::Search(request(json!({"pattern":"ret","max_results":4,"cursor":4}))),
        ),
        (
            "backtrace",
            vec!["--idx", "4", "--limit", "10"],
            Query::Backtrace(request(json!({"idx":4,"limit":10}))),
        ),
        (
            "block-for-pc",
            vec!["--pc", "0x100000"],
            Query::BlockForPc(request(json!({"pc":"0x100000"}))),
        ),
        (
            "idxs-for-block",
            vec!["--pc", "0x100000", "--max-count", "10", "--near", "4"],
            Query::IdxsForBlock(request(json!({"pc":"0x100000","max_count":10,"near":4}))),
        ),
        (
            "strings",
            vec!["--min-len", "4", "--cursor=-1", "--limit", "20"],
            Query::Strings(request(json!({"min_len":4,"cursor":-1,"limit":20}))),
        ),
        (
            "string-provenance",
            vec!["--addr", "0x2000", "--length", "4"],
            Query::StringProvenance(request(json!({"addr":"0x2000","length":4}))),
        ),
        (
            "mem-dump",
            vec!["--addr", "0x2000", "--count", "8"],
            Query::MemDump(request(json!({"addr":"0x2000","count":8}))),
        ),
        (
            "mem-writes-in-range",
            vec![
                "--idx-lo",
                "0",
                "--idx-hi",
                "9",
                "--addr-lo",
                "0x2000",
                "--addr-hi",
                "0x2008",
                "--with-external",
                "--max",
                "5",
            ],
            Query::MemWritesInRange(request(
                json!({"idx_lo":0,"idx_hi":9,"addr_lo":"0x2000","addr_hi":"0x2008","with_external":true,"max":5}),
            )),
        ),
        (
            "last-write-of-reg",
            vec!["--reg", "x0", "--before", "4"],
            Query::LastWriteOfReg(request(json!({"reg":"x0","before":4}))),
        ),
        (
            "taint-fwd",
            vec![
                "--start",
                "0",
                "--reg",
                "x0",
                "--max-count",
                "10",
                "--cross-fn-call",
            ],
            Query::ForwardTaint(request(
                json!({"start":0,"reg":"x0","max_count":10,"cross_fn_call":true}),
            )),
        ),
        (
            "jni-events",
            vec!["--limit", "10"],
            Query::JniEvents(request(json!({"limit":10}))),
        ),
        (
            "resolve",
            vec!["--so", "libt.so", "--off", "0x0"],
            Query::Resolve(request(json!({"so":"libt.so","off":"0x0"}))),
        ),
        (
            "coverage",
            vec!["--addr", "0x100000"],
            Query::Coverage(request(json!({"addr":"0x100000"}))),
        ),
        ("loops", vec![], Query::Loops),
        (
            "block",
            vec!["--pc", "0x100000"],
            Query::Block(request(json!({"pc":"0x100000"}))),
        ),
        (
            "reg-timeline",
            vec!["--reg", "x0", "--start", "0", "--end", "9"],
            Query::RegTimeline(request(json!({"reg":"x0","start":0,"end":9}))),
        ),
        (
            "mem-flow",
            vec!["--addr", "0x2000", "--count", "4"],
            Query::MemFlow(request(json!({"addr":"0x2000","count":4}))),
        ),
        (
            "fn-summary",
            vec!["--fn", "f_root"],
            Query::FnSummary(request(json!({"fn":"f_root"}))),
        ),
        (
            "idxs-touching-addr",
            vec!["--addr", "0x2000", "--with-bytes"],
            Query::IdxsTouchingAddr(request(json!({"addr":"0x2000","with_bytes":true}))),
        ),
    ];
    for (name, flags, query) in cases {
        let mut args = vec![name, cd.to_str().unwrap()];
        args.extend(flags);
        let out = entry(&args);
        assert!(
            out.status.success(),
            "{name}: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let actual: Value = serde_json::from_slice(&out.stdout).unwrap();
        let expected = analysis::execute(&context, query).unwrap();
        assert_eq!(normalize(actual), normalize(expected), "{name}");
    }
}

#[test]
fn core_query_failures_keep_machine_readable_limits() {
    let (_tmp, cd) = synth_deep_dir();
    for (args, code) in [
        (vec!["record", cd.to_str().unwrap(), "9999"], "not_found"),
        (
            vec!["mem-dump", cd.to_str().unwrap(), "--addr", "not-an-address"],
            "invalid_argument",
        ),
        (
            [vec!["diff-traces"], vec![cd.to_str().unwrap(); 9]].concat(),
            "limit_exceeded",
        ),
    ] {
        let out = entry(&args);
        assert_eq!(out.status.code(), Some(1));
        let value: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_valid(
            json!({"type":"object","required":["status","error"],"properties":{
                "status":{"const":"error"},"error":{"type":"object","required":["code","message"],"properties":{
                    "code":{"const":code},"message":{"type":"string"},"details":{"type":"object"}
                }}
            }}),
            &value,
        );
        if code == "limit_exceeded" {
            assert_eq!(value["error"]["details"]["limit"], 8);
            assert_eq!(value["error"]["details"]["requested"], 9);
        }
    }
}

#[test]
fn writer_evidence_points_to_a_public_command() {
    let (_tmp, cd) = synth_deep_dir();
    let out = entry(&[
        "byte-writer-map",
        cd.to_str().unwrap(),
        "--addr",
        "0x2000",
        "--size",
        "4",
    ]);
    assert!(out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["source"]["command"], "mem-writes-in-range");
    assert!(value["source"].get("endpoint").is_none());
    assert!(!value["bytes"].as_array().unwrap().is_empty());
}

#[test]
fn lazy_indexes_do_not_change_annotations_or_external_writes() {
    let (_tmp, cd) = synth_deep_dir();
    let warmed = AnalysisContext::load(cd.clone()).unwrap();
    analysis::execute(
        &warmed,
        Query::MemDump(request(json!({"addr":"0x2000","count":8}))),
    )
    .unwrap();
    let queries: [fn() -> Query; 4] = [
        || Query::Record(1),
        || Query::RegValueAt(request(json!({"idx":1,"reg":"x1"}))),
        || Query::IdxsTouchingRange(request(json!({"addr":"0x2000","size":4}))),
        || Query::IdxsTouchingAddr(request(json!({"addr":"0x2000","with_bytes":true}))),
    ];
    for make_query in queries {
        let cold = AnalysisContext::load(cd.clone()).unwrap();
        assert!(cold.inner.memshadow_if_ready().is_none());
        let actual = analysis::execute(&cold, make_query()).unwrap();
        let expected = analysis::execute(&warmed, make_query()).unwrap();
        assert_eq!(actual, expected);
    }
    let writes = analysis::execute(
        &warmed,
        Query::IdxsTouchingAddr(request(json!({"addr":"0x2000","with_bytes":true}))),
    )
    .unwrap();
    assert!(writes["after"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["kind"] == "x"));
}
