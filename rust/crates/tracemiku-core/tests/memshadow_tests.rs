//! TDD for tracemiku-core::memshadow. Builds a synth trace where x0 holds
//! the bytes "hello" packed into a u64 (LE, low 5 bytes), then
//! `str x0, [x1]` stores it. Trace has extra records after so `value_of_write`
//! has clean state.

use std::io::Write;

fn synth_string_trace_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_3r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs = [0x100000u64, 0x100004, 0x100008];
    let insts: [u32; 3] = [0xf9000020, 0xd503201f, 0xd65f03c0]; // str x0,[x1]; nop; ret
    let hello: u64 = u64::from_le_bytes([b'h', b'e', b'l', b'l', b'o', 0, 0, 0]);
    let x1: u64 = 0x7000;
    let mut buf = vec![0u8; 272 * 3];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * 272;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&hello.to_le_bytes()); // x0
        buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes()); // x1
        buf[off + 256..off + 264].copy_from_slice(&0u64.to_le_bytes()); // sp
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes()); // inst
    }
    std::fs::File::create(cd.join("trace.bin"))
        .unwrap()
        .write_all(&buf)
        .unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"records":3,"tid":100,"ms":1,"truncated":false}"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    let path = cd.clone();
    (tmp, path)
}

#[test]
fn memshadow_byte_at_returns_written_byte() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).expect("load trace");
    let mem = MemShadow::build_from_trace(&trace);
    let (b, kind, src) = mem.byte_at(0x7000, 1 << 60);
    assert_eq!(b, Some(b'h'));
    assert_eq!(kind, "w");
    assert_eq!(src, Some(0));
    let (b, _, _) = mem.byte_at(0x7004, 1 << 60);
    assert_eq!(b, Some(b'o'));
}

#[test]
fn memshadow_byte_at_unaccessed_addr_returns_none() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::build_from_trace(&trace);
    let (b, kind, src) = mem.byte_at(0xffff_0000, 1 << 60);
    assert_eq!(b, None);
    assert_eq!(kind, "??");
    assert_eq!(src, None);
}

#[test]
fn memshadow_find_strings_discovers_planted_run() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::build_from_trace(&trace);
    let strings = mem.find_strings(4);
    assert!(
        strings.iter().any(|(_a, s)| s.starts_with("hello")),
        "expected 'hello' run, got: {strings:?}"
    );
}

#[test]
fn memshadow_find_strings_respects_min_len() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::build_from_trace(&trace);
    let strs_4 = mem.find_strings(4);
    let strs_8 = mem.find_strings(8);
    assert!(!strs_4.is_empty());
    assert!(strs_8.iter().all(|(_a, s)| s != "hello"));
}

#[test]
fn memshadow_byte_at_t_zero_returns_event_at_idx_zero() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::build_from_trace(&trace);
    // The store happens at idx=0; byte_at returns the latest event with
    // idx <= t. At t=0 that event IS visible.
    let (b, _, src) = mem.byte_at(0x7000, 0);
    assert_eq!(b, Some(b'h'));
    assert_eq!(src, Some(0));
}
