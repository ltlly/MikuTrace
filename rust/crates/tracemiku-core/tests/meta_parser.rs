mod common;

use tracemiku_core::prelude::*;

#[test]
fn loads_synth_meta() {
    let fix = common::synth_meta_only_dir();
    let meta = TraceMeta::load(&fix.call_dir).expect("load synth meta");

    assert_eq!(meta.records, 9);
    assert_eq!(meta.format_version, FORMAT_VERSION);
    assert_eq!(meta.record_size, REC_SIZE);
    assert_eq!(meta.method, "f");
    assert_eq!(meta.cmd, Some(1));
    assert_eq!(meta.fn_addr, Some("0x100000".to_string()));

    let m = meta.module.as_ref().expect("primary module");
    assert_eq!(m.name, "libt.so");
    assert_eq!(m.base, "0x100000");
    assert_eq!(m.size, 0x10000);
    assert_eq!(m.end, "0x110000");

    assert_eq!(meta.modules.len(), 1);
    assert_eq!(meta.modules[0].name, "libt.so");

    // ARM64 register list — 33 names, in canonical order.
    assert_eq!(meta.regs.len(), 33);
    assert_eq!(meta.regs[0], "x0");
    assert_eq!(meta.regs[30], "lr");
    assert_eq!(meta.regs[32], "pc");
}

#[test]
fn loads_explicit_trace_format_contract() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    fs::create_dir(&run).unwrap();
    fs::create_dir(run.join("calls")).unwrap();
    let cd = run.join("calls").join("call_001_tid100_0r_1ms");
    fs::create_dir(&cd).unwrap();
    fs::write(cd.join("trace.bin"), []).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":0,"format_version":1,"record_size":272}"#,
    )
    .unwrap();
    fs::write(run.join("meta.json"), "{}").unwrap();

    let meta = TraceMeta::load(&cd).unwrap();
    assert_eq!(meta.format_version, FORMAT_VERSION);
    assert_eq!(meta.record_size, REC_SIZE);
}

#[test]
fn rejects_unknown_trace_format_contract() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    fs::create_dir(&run).unwrap();
    fs::create_dir(run.join("calls")).unwrap();
    let cd = run.join("calls").join("call_001_tid100_0r_1ms");
    fs::create_dir(&cd).unwrap();
    fs::write(cd.join("trace.bin"), []).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":0,"format_version":99,"record_size":272}"#,
    )
    .unwrap();
    fs::write(run.join("meta.json"), "{}").unwrap();

    let err = TraceMeta::load(&cd).unwrap_err().to_string();
    assert!(err.contains("unsupported trace format_version"), "{err}");
}

#[test]
fn rejects_unknown_record_size_contract() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    fs::create_dir(&run).unwrap();
    fs::create_dir(run.join("calls")).unwrap();
    let cd = run.join("calls").join("call_001_tid100_0r_1ms");
    fs::create_dir(&cd).unwrap();
    fs::write(cd.join("trace.bin"), []).unwrap();
    fs::write(
        cd.join("meta.json"),
        r#"{"records":0,"format_version":1,"record_size":520}"#,
    )
    .unwrap();
    fs::write(run.join("meta.json"), "{}").unwrap();

    let err = TraceMeta::load(&cd).unwrap_err().to_string();
    assert!(err.contains("unsupported trace record_size"), "{err}");
}

#[test]
fn missing_meta_yields_clear_error() {
    let tmp = tempfile::tempdir().unwrap();
    let result = TraceMeta::load(tmp.path());
    assert!(result.is_err(), "should fail when no meta.json present");
}

#[test]
fn module_end_computed_from_base_plus_size() {
    let fix = common::synth_meta_only_dir();
    let meta = TraceMeta::load(&fix.call_dir).unwrap();
    let m = meta.module.unwrap();
    // 0x100000 + 0x10000 = 0x110000
    assert_eq!(m.end, "0x110000");
}

#[test]
fn module_end_overflow_yields_error() {
    use std::fs;
    let tmp = tempfile::tempdir().unwrap();
    let run = tmp.path().join("run");
    fs::create_dir(&run).unwrap();
    fs::create_dir(run.join("calls")).unwrap();
    let cd = run.join("calls").join("call_001_tid100_9r_2ms");
    fs::create_dir(&cd).unwrap();
    fs::write(cd.join("trace.bin"), []).unwrap();
    fs::write(cd.join("meta.json"), r#"{"records": 9}"#).unwrap();
    fs::write(
        run.join("meta.json"),
        // Overflowing base+size: 0xFFFFFFFFFFFFFF00 + 256 → wrap.
        r#"{"module": {"name":"x","base":"0xFFFFFFFFFFFFFF00","size":256}}"#,
    )
    .unwrap();

    let result = TraceMeta::load(&cd);
    assert!(result.is_err(), "overflow must surface as Err, not panic");
}
