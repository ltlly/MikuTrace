//! 合并查询的跨能力边界：按需加载、时序来源、未知读、分页与双向依赖。
use serde_json::{json, Value};
use std::path::PathBuf;
use tracemiku_core::analysis::{self as a, AnalysisContext, Query};

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp.path().join("call_001_tid1_4r_1ms");
    std::fs::create_dir(&cd).unwrap();
    let insts = [0xd2800820u32, 0xf9000020, 0x91000402, 0xf9400023]; // mov x0,#65; str x0,[x1]; add x2,x0,#1; ldr x3,[x1]
    let mut bytes = vec![0; 4 * 272];
    for (i, inst) in insts.into_iter().enumerate() {
        let row = &mut bytes[i * 272..(i + 1) * 272];
        row[..8].copy_from_slice(&(0x1000u64 + i as u64 * 4).to_le_bytes());
        row[8..16].copy_from_slice(&65u64.to_le_bytes());
        row[16..24].copy_from_slice(&0x2000u64.to_le_bytes());
        row[268..].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), bytes).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":4,"module":{"name":"libtest.so","base":"0x1000","size":4096},"known_offsets":{"0":"root"}}"#).unwrap();
    let mut ext = Vec::new();
    for value in [66u8, 67] {
        ext.extend_from_slice(&2u64.to_le_bytes());
        ext.extend_from_slice(&0x2000u64.to_le_bytes());
        ext.push(value);
    }
    std::fs::write(cd.join("external_writes.bin"), ext).unwrap();
    (tmp, cd)
}
fn q<T: serde::de::DeserializeOwned>(v: Value) -> T {
    serde_json::from_value(v).unwrap()
}

#[test]
fn raw_record_selection_never_loads_indexes_or_memory_and_is_cache_independent() {
    let (_tmp, cd) = fixture();
    let context = AnalysisContext::load(cd.clone()).unwrap();
    assert_eq!(context.inner.loaded_components(), ["idle"; 4]);
    let make = || Query::Records(q(json!({"indices":[2,0],"regs":"x0,x1"})));
    let cold = a::execute(&context, make()).unwrap();
    assert_eq!(cold["records"][0]["regs"]["x0"], "0x41");
    assert_eq!(cold["start"], 0);
    assert_eq!(cold["end"], 3);
    assert_eq!(context.inner.loaded_components(), ["idle"; 4]);
    assert!(!cd.join("trace.bin.analysis-index.v2.bin").exists());
    a::execute(&context, Query::Record(0)).unwrap();
    assert_eq!(cold, a::execute(&context, make()).unwrap());
    assert!(a::execute(
        &context,
        Query::Records(q(json!({"regs":"x99","start":99})))
    )
    .is_err());
    assert!(a::execute(&context, Query::Records(q(json!({"indices":[0,99]})))).is_err());
}

#[test]
fn range_limit_does_not_claim_more_data_when_the_whole_trace_fits() {
    let (_tmp, cd) = fixture();
    let context = AnalysisContext::load(cd).unwrap();
    let out = a::execute(&context, Query::Records(q(json!({"count":1001})))).unwrap();
    assert_eq!(out["returned"], 4);
    assert_eq!(out["truncated"], false);
}

#[test]
fn access_pages_keep_duplicate_external_values_and_unknown_loads() {
    let (_tmp, cd) = fixture();
    let context = AnalysisContext::load(cd).unwrap();
    let query = |cursor, limit| {
        Query::MemAccesses(q(
            json!({"addr":"2000","size":1,"start":0,"end":null,"kind":"all","cursor":cursor,"limit":limit}),
        ))
    };
    let all = a::execute(&context, query(0, 100)).unwrap();
    assert_eq!(all["returned"], 4);
    assert_eq!(all["events"][0]["bytes"], json!([65]));
    assert_eq!(all["events"][1]["bytes"], json!([66]));
    assert_eq!(all["events"][2]["bytes"], json!([67]));
    assert_eq!(all["events"][1]["pc"], Value::Null);
    assert_eq!(all["events"][3]["kind"], "read");
    assert_eq!(all["events"][3]["bytes"], json!([null]));
    let first = a::execute(&context, query(0, 2)).unwrap();
    let second = a::execute(&context, query(first["next_cursor"].as_u64().unwrap(), 2)).unwrap();
    let joined = [
        first["events"].as_array().unwrap().as_slice(),
        second["events"].as_array().unwrap().as_slice(),
    ]
    .concat();
    assert_eq!(joined, all["events"].as_array().unwrap().to_vec());
    assert_eq!(second["truncated"], false);
}

#[test]
fn provenance_respects_time_and_never_fills_unknown_bytes() {
    let (_tmp, cd) = fixture();
    let context = AnalysisContext::load(cd).unwrap();
    let at = |at| Query::MemProvenance(q(json!({"addr":"2000","count":9,"at":at})));
    let before = a::execute(&context, at(1)).unwrap();
    let after = a::execute(&context, at(2)).unwrap();
    assert_eq!(before["bytes"][0]["byte"], 65);
    assert_eq!(before["bytes"][0]["last_writer"]["source"], "trace");
    assert_eq!(after["bytes"][0]["byte"], 67);
    assert_eq!(after["bytes"][0]["last_writer"]["source"], "external");
    assert_eq!(after["bytes"][0]["last_writer"]["pc"], Value::Null);
    assert_eq!(after["bytes"][8]["byte"], Value::Null);
    assert_eq!(after["bytes"][8]["last_writer"], Value::Null);
}

#[test]
fn dependency_views_share_direction_depth_and_seed_budgets() {
    let (_tmp, cd) = fixture();
    let context = AnalysisContext::load(cd).unwrap();
    let run = |seed, direction, view, depth, limit| {
        a::execute(&context,Query::Dependencies(q(json!({"seeds":{"idx":seed,"limit":limit},"direction":direction,"view":view,"depth":depth})))).unwrap()
    };
    let backward = run(2, "backward", "graph", None::<usize>, 100);
    assert!(backward["slice"].as_array().unwrap().contains(&json!(0)));
    let forward = run(0, "forward", "graph", None, 100);
    assert!(forward["slice"].as_array().unwrap().contains(&json!(2)));
    assert_eq!(
        forward["slice"],
        run(0, "forward", "slice", None, 100)["slice"]
    );
    let depth = run(0, "forward", "graph", Some(0), 100);
    assert_eq!(depth["slice"], json!([0]));
    assert_eq!(depth["truncated"], true);
    let limited = run(0, "forward", "graph", None, 1);
    assert_eq!(limited["slice_count"], 1);
    assert_eq!(limited["truncated"], true);
    let intersection=a::execute(&context,Query::Dependencies(q(json!({"seeds":{"idxs":"1,2","mode":"intersection"},"direction":"backward","view":"slice","depth":null})))).unwrap();
    assert_eq!(intersection["slice"], json!([0]));
}
