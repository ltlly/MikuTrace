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

fn append_store_record(cd: &std::path::Path, pc: u64, addr: u64, value: u64) {
    let mut rec = vec![0u8; 272];
    rec[0..8].copy_from_slice(&pc.to_le_bytes());
    rec[8..16].copy_from_slice(&value.to_le_bytes()); // x0
    rec[16..24].copy_from_slice(&addr.to_le_bytes()); // x1
    rec[256..264].copy_from_slice(&0u64.to_le_bytes()); // sp
    rec[268..272].copy_from_slice(&0xf9000020u32.to_le_bytes()); // str x0,[x1]
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(cd.join("trace.bin"))
        .unwrap();
    f.write_all(&rec).unwrap();
}

fn append_external_write(cd: &std::path::Path, idx: u64, addr: u64, byte: u8) {
    let mut rec = Vec::with_capacity(17);
    rec.extend_from_slice(&idx.to_le_bytes());
    rec.extend_from_slice(&addr.to_le_bytes());
    rec.push(byte);
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(cd.join("external_writes.bin"))
        .unwrap();
    f.write_all(&rec).unwrap();
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

#[test]
fn memshadow_loads_external_writes_as_x_events() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    append_external_write(&cd, 1, 0x7002, b'X');
    append_external_write(&cd, 1, 0x7002, b'X');
    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::build_from_trace(&trace);

    let (before, before_kind, before_src) = mem.byte_at(0x7002, 0);
    assert_eq!(before, Some(b'l'));
    assert_eq!(before_kind, "w");
    assert_eq!(before_src, Some(0));

    let (after, after_kind, after_src) = mem.byte_at(0x7002, 1);
    assert_eq!(after, Some(b'X'));
    assert_eq!(after_kind, "x");
    assert_eq!(after_src, Some(1));
    assert_eq!(mem.latest_write_idx_strict_before(0x7002, 2), Some(1));
    assert!(mem
        .writes
        .iter()
        .any(|rec| rec.idx == 1 && rec.addr == 0x7002 && rec.value == b'X' as u64));
    assert_eq!(
        mem.bytes
            .get(&0x7002)
            .unwrap()
            .iter()
            .filter(|ev| ev.kind == "x")
            .count(),
        1
    );
}

#[test]
fn memshadow_v6_sidecar_roundtrip_preserves_shadow() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    append_external_write(&cd, 1, 0x7002, b'X');
    let trace = Trace::load(&cd).unwrap();
    let mem1 = MemShadow::load_or_build(&trace);
    let sidecar = MemShadow::sidecar_path(&trace);
    assert!(sidecar.exists(), "sidecar should be written at {sidecar:?}");

    let mem2 = MemShadow::try_load_sidecar(&trace).expect("sidecar loads");
    assert_eq!(mem1.writes, mem2.writes);
    assert_eq!(mem1.reads, mem2.reads);
    assert_eq!(mem1.bytes, mem2.bytes);
}

#[test]
fn memshadow_v6_sidecar_stale_trace_size_rebuilds() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).unwrap();
    let _ = MemShadow::load_or_build(&trace);
    assert!(MemShadow::sidecar_path(&trace).exists());

    let value = u64::from_le_bytes([b'b', b'y', b'e', 0, 0, 0, 0, 0]);
    append_store_record(&cd, 0x10000c, 0x8000, value);
    let trace2 = Trace::load(&cd).unwrap();
    assert_eq!(trace2.len(), 4);
    let mem2 = MemShadow::load_or_build(&trace2);
    let (b, kind, src) = mem2.byte_at(0x8000, 1 << 60);
    assert_eq!(b, Some(b'b'));
    assert_eq!(kind, "w");
    assert_eq!(src, Some(3));
}

#[test]
fn memshadow_v6_corrupt_sidecar_is_ignored() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;
    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).unwrap();
    let sidecar = MemShadow::sidecar_path(&trace);
    std::fs::write(&sidecar, b"not a valid sidecar").unwrap();

    let mem = MemShadow::load_or_build(&trace);
    let (b, kind, src) = mem.byte_at(0x7000, 1 << 60);
    assert_eq!(b, Some(b'h'));
    assert_eq!(kind, "w");
    assert_eq!(src, Some(0));
    assert!(sidecar.metadata().unwrap().len() > 32);
}

#[test]
fn memshadow_reconstructs_simd_loads_stores_and_worker_traces() {
    use tracemiku_core::analysis::{self as a, AnalysisContext, Query};
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;

    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_1ms");
    std::fs::create_dir_all(&cd).unwrap();

    // 0: str q0, [x0]          (0x3d800000) -> writes 16B at 0x9000
    // 1: st1 {v1.16b, v2.16b}, [x1] (0x4c00a021) -> writes 32B at 0x9100
    // 2: ldr q3, [x2]          (0x3dc00043) -> reads 16B at 0x9200 (post-state in idx 3)
    // 3: ret                   (0xd65f03c0)
    let pcs = [0x100000u64, 0x100004, 0x100008, 0x10000c];
    let insts: [u32; 4] = [0x3d800000, 0x4c00a021, 0x3dc00043, 0xd65f03c0];
    let mut trace_buf = vec![0u8; 272 * 4];
    let mut simd_buf = vec![0u8; 520 * 4];
    for i in 0..4 {
        let off = i * 272;
        trace_buf[off..off + 8].copy_from_slice(&pcs[i].to_le_bytes());
        trace_buf[off + 8..off + 16].copy_from_slice(&0x9000u64.to_le_bytes()); // x0
        trace_buf[off + 16..off + 24].copy_from_slice(&0x9100u64.to_le_bytes()); // x1
        trace_buf[off + 24..off + 32].copy_from_slice(&0x9200u64.to_le_bytes()); // x2
        trace_buf[off + 268..off + 272].copy_from_slice(&insts[i].to_le_bytes());

        let soff = i * 520;
        simd_buf[soff..soff + 8].copy_from_slice(&(i as u64).to_le_bytes());
        // q0 = "NEON_PAYLOAD_Q0!"
        simd_buf[soff + 8..soff + 24].copy_from_slice(b"NEON_PAYLOAD_Q0!");
        // q1 = "ST1_VECTOR_ONE!!"
        simd_buf[soff + 8 + 16..soff + 8 + 32].copy_from_slice(b"ST1_VECTOR_ONE!!");
        // q2 = "ST1_VECTOR_TWO!!"
        simd_buf[soff + 8 + 32..soff + 8 + 48].copy_from_slice(b"ST1_VECTOR_TWO!!");
        if i == 3 {
            // Post-state of ldr q3 at idx 2
            simd_buf[soff + 8 + 48..soff + 8 + 64].copy_from_slice(b"LOADED_Q3_BYTES!");
        }
    }

    // Add a worker trace file that writes 0xfeedface to 0x9300 via `str w0, [x1]` (0xb9000020)
    let mut worker_buf = vec![0u8; 272];
    worker_buf[0..8].copy_from_slice(&0x100100u64.to_le_bytes());
    worker_buf[8..16].copy_from_slice(&0xfeedfaceu64.to_le_bytes()); // x0
    worker_buf[16..24].copy_from_slice(&0x9300u64.to_le_bytes()); // x1
    worker_buf[268..272].copy_from_slice(&0xb9000020u32.to_le_bytes());

    std::fs::write(cd.join("trace.bin"), &trace_buf).unwrap();
    std::fs::write(cd.join("simd_trace.bin"), &simd_buf).unwrap();
    std::fs::write(cd.join("worker_trace_tid200.bin"), &worker_buf).unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"records":4,"tid":100,"ms":1,"truncated":false}"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::load_or_build(&trace);

    // Verify all 16 bytes of `str q0, [x0]`
    for (k, &expected) in b"NEON_PAYLOAD_Q0!".iter().enumerate() {
        assert_eq!(
            mem.byte_at(0x9000 + k as u64, 10),
            (Some(expected), "w", Some(0))
        );
    }
    // Verify all 32 bytes of `st1 {v1.16b, v2.16b}, [x1]`
    for (k, &expected) in b"ST1_VECTOR_ONE!!ST1_VECTOR_TWO!!".iter().enumerate() {
        assert_eq!(
            mem.byte_at(0x9100 + k as u64, 10),
            (Some(expected), "w", Some(1))
        );
    }
    // Verify all 16 bytes of `ldr q3, [x2]`
    for (k, &expected) in b"LOADED_Q3_BYTES!".iter().enumerate() {
        assert_eq!(
            mem.byte_at(0x9200 + k as u64, 10),
            (Some(expected), "r", Some(2))
        );
    }
    // Verify worker trace merged write at 0x9300
    assert_eq!(mem.byte_at(0x9300, 10), (Some(0xce), "x", Some(3)));
    assert_eq!(mem.byte_at(0x9303, 10), (Some(0xfe), "x", Some(3)));

    // Verify downstream analysis queries: mem-accesses, find-mem-pattern, records
    let ctx = AnalysisContext::load(cd).unwrap();
    let accesses = a::execute(
        &ctx,
        Query::MemAccesses(
            serde_json::from_value(serde_json::json!({"addr":"9000","size":16})).unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(
        accesses["events"][0]["bytes"],
        serde_json::json!(b"NEON_PAYLOAD_Q0!".to_vec())
    );

    let pattern = a::execute(
        &ctx,
        Query::FindMemPattern(
            serde_json::from_value(
                serde_json::json!({"bytes_hex":"5354315f564543544f525f54574f2121"}),
            )
            .unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(pattern["count"], 1);
    assert_eq!(pattern["hits"][0]["addr"], "0x9110");

    let recs = a::execute(
        &ctx,
        Query::Records(
            serde_json::from_value(serde_json::json!({"start":0,"count":1,"regs":"q0"})).unwrap(),
        ),
    )
    .unwrap();
    assert!(recs["records"][0]["regs"]["q0"].is_string());
    assert!(recs["records"][0]["mem_access"]["val"].is_string());
}
