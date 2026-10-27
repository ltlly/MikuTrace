use super::analysis_support;
use std::fs;
use std::path::PathBuf;
use tracemiku_core::analysis::AnalysisContext;

fn synth_call_dir() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_3r_1ms");
    fs::create_dir_all(&cd).unwrap();
    let specs: [(u64, u32, u64); 3] = [
        (0x100000, 0xf9000020, 0x41), // str x0,[x1]
        (0x100004, 0xf9000020, 0x42), // str x0,[x1]
        (0x100008, 0xd65f03c0, 0x42),
    ];
    let mut buf = vec![0u8; 272 * specs.len()];
    for (i, (pc, inst, x0)) in specs.iter().enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&x0.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records":3}"#).unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn synth_many_write_call_dir(
    record_count: usize,
    addr_groups: usize,
) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join(format!("call_001_tid100_{record_count}r_1ms"));
    fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; 272 * record_count];
    for i in 0..record_count {
        let off = i * 272;
        let pc = 0x100000u64 + (i as u64 * 4);
        let x0 = (i & 0xff) as u64;
        let x1 = 0x7000u64 + ((i % addr_groups) as u64 * 8);
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&x0.to_le_bytes());
        buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x8000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0xf9000020u32.to_le_bytes());
    }
    fs::write(cd.join("trace.bin"), &buf).unwrap();
    fs::write(
        cd.join("meta.json"),
        format!(r#"{{"records":{record_count}}}"#),
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    (tmp, cd)
}

fn get(call_dir: PathBuf, uri: &str) -> (Option<&'static str>, serde_json::Value) {
    let app = AnalysisContext::load(call_dir).expect("load analysis context");
    let resp = analysis_support::query(&app, uri, None);
    let status = resp.error_code();
    let body = resp.bytes();
    (
        status,
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
    )
}

#[test]
fn memory_accesses_returns_observed_byte_events() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(cd, "memory-accesses?addr=0x7000&size=1");
    assert_eq!(status, None);
    assert_eq!(v["returned"], 2);
    assert_eq!(v["events"][0]["idx"], 0);
    assert_eq!(v["events"][0]["bytes"], serde_json::json!([65]));
    assert_eq!(v["events"][0]["kind"], "write");
    assert_eq!(v["events"][0]["pc"], "0x100000");
}

#[test]
fn memory_accesses_uses_trace_stream_and_memshadow_without_full_index() {
    let (_tmp, cd) = synth_call_dir();
    let app = AnalysisContext::load(cd).expect("load analysis context");
    let resp = analysis_support::query(&app, "memory-accesses?addr=0x7000&size=1", None);
    assert_eq!(resp.error_code(), None);
    let value: serde_json::Value = serde_json::from_slice(&resp.bytes()).unwrap();
    assert_eq!(value["returned"], 2);
    assert_eq!(value["events"][0]["bytes"], serde_json::json!([65]));
    let components = app.inner.loaded_components();
    assert_eq!(
        components[0], "idle",
        "memory accesses must not build Index"
    );
    assert_eq!(
        components[3], "ready",
        "memory accesses still use MemShadow"
    );
}

#[test]
fn memory_accesses_filters_time_and_write_kind() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(
        cd,
        "memory-accesses?addr=0x7000&size=1&start=1&end=2&kind=write&limit=1",
    );
    assert_eq!(status, None);
    assert_eq!(v["events"].as_array().unwrap().len(), 1);
    assert_eq!(v["events"][0]["idx"], 1);
    assert_eq!(v["events"][0]["bytes"], serde_json::json!([66]));
    assert_eq!(v["truncated"], false);
}

#[test]
fn memory_accesses_caps_total_returned_events() {
    let (_tmp, cd) = synth_many_write_call_dir(10_080, 21);
    let (status, v) = get(cd, "memory-accesses?addr=0x7000&size=168&limit=999999");
    assert_eq!(status, None);
    assert_eq!(v["returned"], 5000);
    assert_eq!(v["events"].as_array().unwrap().len(), 5000);
    assert_eq!(v["truncated"], true);
    assert_eq!(v["next_cursor"], 5000);
}

#[test]
fn mem_writes_in_range_filters_by_idx_addr_and_src_byte() {
    let (_tmp, cd) = synth_call_dir();
    let (status, v) = get(
        cd,
        "mem-writes-in-range?idx_lo=0&idx_hi=2&addr_lo=0x7000&addr_hi=0x7001&src_byte=0x42&max=10",
    );
    assert_eq!(status, None);
    assert_eq!(v["idx_range"][0], 0);
    assert_eq!(v["idx_range"][1], 2);
    assert_eq!(v["matched"], 1);
    assert_eq!(v["returned"], 1);
    assert_eq!(v["truncated"], false);
    assert_eq!(v["writes"][0]["idx"], 1);
    assert_eq!(v["writes"][0]["pc"], "0x100004");
    assert_eq!(v["writes"][0]["dst_addr"], "0x7000");
    assert_eq!(v["writes"][0]["src_reg"], "x0");
    assert_eq!(v["writes"][0]["src_value"], "0x42");
    assert_eq!(v["writes"][0]["byte0"], 66);
}

#[test]
fn mem_writes_in_range_bad_filter_is_invalid_argument() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _v) = get(cd, "mem-writes-in-range?idx_lo=0&src_byte=bogus");
    assert_eq!(status, Some("invalid_argument"));
}

#[test]
fn mem_flow_bad_addr_is_invalid_argument() {
    let (_tmp, cd) = synth_call_dir();
    let (status, _v) = get(cd, "memory-accesses?addr=bogus");
    assert_eq!(status, Some("invalid_argument"));
}
