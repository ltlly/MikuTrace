//! sidecar 读取独立于 trace；游标必须在预算耗尽或坏行之后仍能推进。
use serde_json::{json, Value};
use tracemiku_core::analysis::events::{read_events, EventsQuery};

fn query(value: Value) -> EventsQuery {
    serde_json::from_value(value).unwrap()
}

#[test]
fn missing_sidecar_and_invalid_filters_are_distinct() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = read_events(tmp.path(), query(json!({"source":"jni"}))).unwrap();
    assert!(!missing.available);
    assert_eq!(missing.stop_reason, "missing");
    assert!(!missing.truncated);
    for value in [
        json!({"source":"unknown"}),
        json!({"source":"jni","status":"success"}),
        json!({"source":"fork","id":"name"}),
        json!({"source":"jni","start":2,"end":1}),
        json!({"source":"jni","limit":0}),
        json!({"source":"jni","cursor":"fork:0"}),
    ] {
        assert!(read_events(tmp.path(), query(value)).is_err());
    }
}

#[test]
fn jni_skips_bad_lines_and_keeps_matching_cursor_stable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut raw = b"broken\n[]\n".to_vec();
    raw.extend(vec![b'x'; 70_000]);
    raw.push(b'\n');
    for i in 0..3 {
        raw.extend(format!("{{\"id\":\"name\",\"trace_idx\":{i}}}\n").as_bytes());
    }
    std::fs::write(tmp.path().join("jni_hooks.jsonl"), raw).unwrap();
    let first = read_events(
        tmp.path(),
        query(json!({"source":"jni","start":1,"end":3,"limit":1})),
    )
    .unwrap();
    assert_eq!(first.invalid_lines, 2);
    assert_eq!(first.oversized_lines, 1);
    assert_eq!(first.events[0].event["trace_idx"], 1);
    assert!(first.truncated);
    let second = read_events(
        tmp.path(),
        query(json!({"source":"jni","start":1,"end":3,"cursor":first.next_cursor,"limit":1})),
    )
    .unwrap();
    assert_eq!(second.events[0].event["trace_idx"], 2);
    assert!(!second.truncated);
    for cursor in ["jni:1", "jni:999999", "fork:0", "jni:-1"] {
        assert!(read_events(tmp.path(), query(json!({"source":"jni","cursor":cursor}))).is_err());
    }
}

#[test]
fn jni_scan_budget_resumes_without_rescanning_or_losing_the_next_match() {
    let tmp = tempfile::tempdir().unwrap();
    let line = format!(
        "{{\"id\":\"skip\",\"payload\":\"{}\"}}\n",
        "a".repeat(60_000)
    );
    let mut raw = line.repeat(150);
    raw.push_str("{\"id\":\"target\",\"trace_idx\":9}");
    std::fs::write(tmp.path().join("jni_hooks.jsonl"), raw).unwrap();
    let first = read_events(tmp.path(), query(json!({"source":"jni","id":"target"}))).unwrap();
    assert_eq!(first.returned, 0);
    assert_eq!(first.stop_reason, "scan_budget");
    assert!(first.scanned_bytes <= first.budget_bytes);
    let offset: usize = first.next_cursor.as_ref().unwrap()[4..].parse().unwrap();
    assert_eq!(offset % line.len(), 0);
    let second = read_events(
        tmp.path(),
        query(json!({"source":"jni","id":"target","cursor":first.next_cursor})),
    )
    .unwrap();
    assert_eq!(second.events[0].event["id"], "target");
    assert!(!second.truncated);
    assert!(serde_json::to_vec(&second).unwrap().len() + 1 <= second.budget_bytes);
}

#[test]
fn a_single_unskippable_line_fails_with_a_resource_error() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("jni_hooks.jsonl"),
        vec![b'x'; 8 * 1024 * 1024 + 1],
    )
    .unwrap();
    let error = read_events(tmp.path(), query(json!({"source":"jni"}))).unwrap_err();
    assert_eq!(error.code, "limit_exceeded");
}

#[test]
fn fork_filters_pagination_and_metadata_errors_are_explicit() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("meta.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"fork_events":[
            {"child_pid":1,"is_fork_like":true,"attach_status":"success"},
            {"child_pid":2,"is_fork_like":false,"attach_status":"failed"},
            {"child_pid":3,"is_fork_like":true,"attach_status":"success","trace_idx":5}
        ]}))
        .unwrap(),
    )
    .unwrap();
    let first = read_events(
        tmp.path(),
        query(json!({"source":"fork","is_fork_like":true,"limit":1})),
    )
    .unwrap();
    assert_eq!(first.events[0].event["child_pid"], 1);
    assert_eq!(first.next_cursor.as_deref(), Some("fork:2"));
    let second = read_events(
        tmp.path(),
        query(json!({"source":"fork","status":"success","cursor":first.next_cursor})),
    )
    .unwrap();
    assert_eq!(second.events[0].event["child_pid"], 3);
    assert!(!second.truncated);
    let timed = read_events(
        tmp.path(),
        query(json!({"source":"fork","start":5,"end":6})),
    )
    .unwrap();
    assert_eq!(timed.returned, 1);
    assert!(read_events(
        tmp.path(),
        query(json!({"source":"fork","cursor":"fork:99"}))
    )
    .is_err());
    std::fs::write(&path, b"broken").unwrap();
    assert!(read_events(tmp.path(), query(json!({"source":"fork"}))).is_err());
    std::fs::write(&path, vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();
    assert_eq!(
        read_events(tmp.path(), query(json!({"source":"fork"})))
            .unwrap_err()
            .code,
        "limit_exceeded"
    );
}
