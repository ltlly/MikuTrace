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
        (
            "records",
            vec!["--indices", "1", "--detail"],
            Query::Records(request(json!({"indices":[1],"detail":true}))),
        ),
        (
            "cfg",
            vec![],
            Query::CfgInspect(request(
                json!({"fn_name":"","pc":null,"hits":false,"coverage":false,"cursor":0,"limit":100}),
            )),
        ),
        (
            "cfg",
            vec!["--pc", "100000", "--coverage", "--hits"],
            Query::CfgInspect(request(
                json!({"fn_name":"","pc":"100000","hits":true,"coverage":true,"cursor":0,"limit":100}),
            )),
        ),
        (
            "functions",
            vec!["--fn", "f_root"],
            Query::FunctionsInspect(request(json!({"fn_name":"f_root"}))),
        ),
        (
            "search",
            vec!["ret", "--max-results", "4", "--cursor", "4"],
            Query::Search(request(json!({"pattern":"ret","max_results":4,"cursor":4}))),
        ),
        (
            "backtrace",
            vec!["--idx", "4", "--limit", "10", "--lr-clues"],
            Query::BacktraceInspect(request(json!({"idx":4,"limit":10,"lr_clues":true}))),
        ),
        (
            "strings",
            vec!["--min-len", "4", "--cursor=-1", "--limit", "20"],
            Query::Strings(request(json!({"min_len":4,"cursor":-1,"limit":20}))),
        ),
        (
            "mem-dump",
            vec![
                "--addr",
                "2000",
                "--count",
                "8",
                "--at",
                "7",
                "--compare-at",
                "1",
            ],
            Query::MemDump(request(
                json!({"addr":"2000","count":8,"at":7,"compare_at":1}),
            )),
        ),
        (
            "mem-accesses",
            vec![
                "--addr", "2000", "--size", "8", "--start", "1", "--end", "9", "--limit", "5",
            ],
            Query::MemAccesses(request(
                json!({"addr":"2000","size":8,"start":1,"end":9,"limit":5,"cursor":0,"kind":"all"}),
            )),
        ),
        (
            "mem-provenance",
            vec!["--addr", "2000", "--count", "4", "--at", "7"],
            Query::MemProvenance(request(json!({"addr":"2000","count":4,"at":7}))),
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
            "resolve",
            vec!["--so", "libt.so", "--off", "0x0"],
            Query::Resolve(request(json!({"so":"libt.so","off":"0x0"}))),
        ),
        ("loops", vec![], Query::Loops),
        (
            "reg-timeline",
            vec!["--reg", "x0", "--start", "0", "--end", "9", "--equals", "0"],
            Query::RegInspect(request(
                json!({"reg":"x0","start":0,"end":9,"max_points":1000,"equals":"0"}),
            )),
        ),
        (
            "bfs-slice",
            vec!["--idx", "4", "--view", "graph", "--direction", "forward"],
            Query::Dependencies(request(
                json!({"seeds":{"idx":4,"mode":"union"},"view":"graph","direction":"forward","depth":null}),
            )),
        ),
        (
            "jni-calls",
            vec!["--strings", "--limit", "10"],
            Query::JniInspect(request(
                json!({"in_fn":null,"name":null,"jobject":null,"start":0,"end":null,"cursor":0,"limit":10,"strings":true,"max_len":256}),
            )),
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
        (
            vec!["records", cd.to_str().unwrap(), "--indices", "9999"],
            "not_found",
        ),
        (
            vec!["mem-dump", cd.to_str().unwrap(), "--addr", "not-an-address"],
            "invalid_argument",
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
    }
}

#[test]
fn writer_evidence_is_available_through_unified_provenance() {
    let (_tmp, cd) = synth_deep_dir();
    let out = entry(&[
        "mem-provenance",
        cd.to_str().unwrap(),
        "--addr",
        "2000",
        "--count",
        "4",
    ]);
    assert!(out.status.success());
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["bytes"][0]["last_writer"]["idx"], 7);
    assert_eq!(value["bytes"][0]["last_writer"]["source"], "trace");
    assert_eq!(value["bytes"][0]["byte"], 33);
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
        || Query::Records(request(json!({"indices":[1],"regs":"x1"}))),
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
