//! 寄存器查询的变化、等值、窗口及资源边界。
use serde_json::{json, Value};
use tracemiku_core::analysis::{self as a, Query};

fn synth_trace() -> tracemiku_core::analysis::AnalysisContext {
    let mut buf = vec![0u8; 272 * 4];
    // x0 changes 1->2->3->3; x1 constant 7.
    for i in 0..4 {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&(0x100000u64 + (i as u64 * 4)).to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&(1u64 + i as u64).min(3).to_le_bytes()); // x0
        buf[off + 16..off + 24].copy_from_slice(&7u64.to_le_bytes()); // x1
        buf[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("calls").join("call_001_tid1_4r_1ms");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("trace.bin"), &buf).unwrap();
    std::fs::write(dir.join("meta.json"), r#"{"records":4}"#).unwrap();
    std::fs::write(
        tmp.path().join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    tracemiku_core::analysis::AnalysisContext::load(dir).unwrap()
}

fn query(context: &a::AnalysisContext, value: Value) -> Result<Value, a::AnalysisError> {
    a::execute(
        context,
        Query::RegInspect(serde_json::from_value(value).unwrap()),
    )
}
#[test]
fn changes_and_equals_share_window_and_pagination_contract() {
    let context = synth_trace();
    let changes = query(&context, json!({"reg":"x0"})).unwrap();
    assert_eq!(
        changes["points"],
        json!([{"idx":0,"value":"0x1"},{"idx":1,"value":"0x2"},{"idx":2,"value":"0x3"}])
    );
    let late = query(&context, json!({"reg":"x0","start":2})).unwrap();
    assert_eq!(late["points"], json!([{"idx":2,"value":"0x3"}]));
    let equals = query(&context, json!({"reg":"x0","equals":"3"})).unwrap();
    assert_eq!(
        equals["points"],
        json!([{"idx":2,"value":"0x3"},{"idx":3,"value":"0x3"}])
    );
    let first = query(&context, json!({"reg":"x0","equals":"3","max_points":1})).unwrap();
    assert_eq!(first["truncated"], true);
    let second = query(
        &context,
        json!({"reg":"x0","equals":"3","start":first["next_cursor"]}),
    )
    .unwrap();
    assert_eq!(second["points"], json!([{"idx":3,"value":"0x3"}]));
    let empty = query(&context, json!({"reg":"x0","start":4})).unwrap();
    assert_eq!(empty["points"], json!([]));
}
#[test]
fn invalid_registers_windows_and_zero_limits_fail_even_for_empty_windows() {
    let context = synth_trace();
    for args in [
        json!({"reg":"zz","start":4}),
        json!({"reg":"x0","start":99}),
        json!({"reg":"x0","max_points":0}),
        json!({"reg":"x0","start":3,"end":2}),
        json!({"reg":"x0","equals":"bogus"}),
    ] {
        assert!(query(&context, args).is_err());
    }
}
