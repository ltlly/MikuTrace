//! TDD for tracemiku-core::memshadow. Builds a synth trace where x0 holds
//! the bytes "hello" packed into a u64 (LE, low 5 bytes), then
//! `str x0, [x1]` stores it. Trace has extra records after so `value_of_write`
//! has clean state.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

static ALLOCATION_MEASUREMENT_LOCK: Mutex<()> = Mutex::new(());

struct AllocationTracker;

static MAX_TRACKED_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static TRACK_ALLOCATION: Cell<bool> = const { Cell::new(false) };
}

unsafe impl GlobalAlloc for AllocationTracker {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.track(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.track(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.track(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

impl AllocationTracker {
    fn track(&self, size: usize) {
        if TRACK_ALLOCATION
            .try_with(|active| active.get())
            .unwrap_or(false)
        {
            MAX_TRACKED_ALLOCATION.fetch_max(size, Ordering::Relaxed);
        }
    }
}

#[global_allocator]
static ALLOCATOR: AllocationTracker = AllocationTracker;

fn largest_allocation_during<T>(body: impl FnOnce() -> T) -> (T, usize) {
    let _guard = ALLOCATION_MEASUREMENT_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    TRACK_ALLOCATION.with(|active| {
        MAX_TRACKED_ALLOCATION.store(0, Ordering::Relaxed);
        active.set(true);
        let result = body();
        active.set(false);
        (result, MAX_TRACKED_ALLOCATION.load(Ordering::Relaxed))
    })
}

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
fn memshadow_v8_sidecar_roundtrip_preserves_shadow() {
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
fn memshadow_v8_sidecar_stale_trace_size_rebuilds() {
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
fn memshadow_v8_corrupt_sidecar_is_ignored() {
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

#[test]
fn memshadow_and_byte_lineage_bridge_uninstrumented_memcpy_and_memset() {
    use tracemiku_core::analysis::reports::{byte_lineage, VmProfile};
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;

    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_6r_1ms");
    std::fs::create_dir_all(&cd).unwrap();

    // 0: movz x4, #0x4443      (0xd2888864) -> defines x4
    // 1: str w4, [x1]          (0xb9000024) -> writes [0x43, 0x44, 0, 0] to src=0x7000
    // 2: bl #0x101000          (0x940003fe at pc=0x100008) -> uninstrumented memcpy(dst=0x8000, src=0x7000, len=4)
    // 3: ldrb w5, [x0, #1]     (0x39400405 at pc=0x10000c) -> reads dst+1 (0x8001) into w5 (post-state in idx 4)
    // 4: bl #0x102000          (0x940007fc at pc=0x100010) -> uninstrumented memset(dst=0x8100, c=0xaa, len=4)
    // 5: ldrb w6, [x0]         (0x39400006 at pc=0x100014) -> reads 0x8100 (post-state in idx 6)
    // 6: ret                   (0xd65f03c0 at pc=0x100018)
    let pcs = [
        0x100000u64,
        0x100004,
        0x100008,
        0x10000c,
        0x100010,
        0x100014,
        0x100018,
    ];
    let insts: [u32; 7] = [
        0xd2888864, 0xb9000024, 0x940003fe, 0x39400405, 0x940007fc, 0x39400006, 0xd65f03c0,
    ];
    let mut trace_buf = vec![0u8; 272 * 7];
    for i in 0..7 {
        let off = i * 272;
        trace_buf[off..off + 8].copy_from_slice(&pcs[i].to_le_bytes());
        let x0: u64 = if i >= 4 { 0x8100 } else { 0x8000 };
        let x1: u64 = if i == 4 { 0xaa } else { 0x7000 };
        let x2: u64 = 4;
        let x4: u64 = if i == 0 { 0 } else { 0x41424443 };
        let x5: u64 = if i >= 4 { 0x44 } else { 0 };
        let x6: u64 = if i >= 6 { 0xaa } else { 0 };
        trace_buf[off + 8..off + 16].copy_from_slice(&x0.to_le_bytes()); // x0
        trace_buf[off + 16..off + 24].copy_from_slice(&x1.to_le_bytes()); // x1
        trace_buf[off + 24..off + 32].copy_from_slice(&x2.to_le_bytes()); // x2
        trace_buf[off + 40..off + 48].copy_from_slice(&x4.to_le_bytes()); // x4
        trace_buf[off + 48..off + 56].copy_from_slice(&x5.to_le_bytes()); // x5
        trace_buf[off + 56..off + 64].copy_from_slice(&x6.to_le_bytes()); // x6
        trace_buf[off + 268..off + 272].copy_from_slice(&insts[i].to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &trace_buf).unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"records":7,"tid":100,"ms":1,"truncated":false}"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let trace = Trace::load(&cd).unwrap();
    let mem = MemShadow::load_or_build(&trace);

    // 1. MemShadow::byte_at propagates bytes across uninstrumented memcpy at idx=2
    assert_eq!(mem.byte_at(0x8000, 10), (Some(0x43), "x", Some(2)));
    assert_eq!(mem.byte_at(0x8001, 2), (Some(0x44), "x", Some(2)));
    assert_eq!(mem.byte_at(0x8002, 10), (Some(0x42), "x", Some(2)));
    assert_eq!(mem.byte_at(0x8003, 10), (Some(0x41), "x", Some(2)));
    assert_eq!(mem.copy_source_at(0x8001, 2), Some(0x7001));

    // Sidecar roundtrip preserves copy_sources
    let mem_reloaded = MemShadow::try_load_sidecar(&trace).expect("sidecar loads");
    assert!(mem_reloaded.copy_sources.is_mapped());
    assert_eq!(mem.copy_sources, mem_reloaded.copy_sources);
    assert_eq!(mem_reloaded.copy_source_at(0x8001, 2), Some(0x7001));

    // Uninstrumented memset at idx=4 is also synthesized
    assert_eq!(mem.byte_at(0x8100, 4), (Some(0xaa), "x", Some(4)));
    assert_eq!(mem.byte_at(0x8103, 10), (Some(0xaa), "x", Some(4)));

    // 2. byte-lineage on dst+1 (0x8001) hops across memcpy (idx=2) to src+1 (0x7001)
    // and reaches the original instruction that wrote src+1 (idx=1, str w4, [x1] -> idx=0, movz x4)!
    let profile = VmProfile::for_lineage(None, None, None, None).unwrap();
    let lineage = byte_lineage(
        cd.clone(),
        "0x8001".to_string(),
        6,
        1,
        4,
        16,
        64,
        64,
        String::new(),
        false,
        false,
        profile,
    )
    .unwrap();

    assert_eq!(lineage["status"], "ready");
    let steps = lineage["steps"].as_array().unwrap();
    assert!(
        steps.len() >= 3,
        "expected memcpy hop + src write + reg source, got: {lineage}"
    );
    // Step 0: last_write at 0x8001 (idx 2, memcpy_from 0x7001)
    assert_eq!(steps[0]["kind"], "last_write");
    assert_eq!(steps[0]["write"]["writer_idx"], 2);
    assert_eq!(steps[0]["memcpy_from"], "0x7001");
    assert_eq!(steps[0]["next"]["kind"], "addr_before");
    assert_eq!(steps[0]["next"]["addr"], "0x7001");
    assert_eq!(steps[0]["next"]["before_idx"], 2);

    // Step 1: last_write at 0x7001 (idx 1, str w4, [x1])
    assert_eq!(steps[1]["kind"], "last_write");
    assert_eq!(steps[1]["write"]["writer_idx"], 1);
    assert_eq!(steps[1]["write"]["src_reg"], "x4");
    assert_eq!(steps[1]["source_byte_offset"], 1);

    // Step 2: reg_source for x4 at idx 1 -> local_def at idx 0
    assert_eq!(steps[2]["kind"], "reg_source");
    assert_eq!(steps[2]["backstep"]["local_def"]["idx"], 0);

    // Origin resolves through the memcpy to the register writer at idx 1, not stopping at external_write
    assert_eq!(lineage["origin"]["register"]["reg"], "x4");
    assert_eq!(lineage["origin"]["register"]["idx"], 1);

    // 3. Also test when a register load at idx=3 (`ldrb w5, [x0, #1]`) is stored to 0x8200
    // and we trace byte-lineage on 0x8200: `reg_source` on `w5` loads from `0x8001` whose
    // upstream writer is the `memcpy` at idx=2, hopping to `0x7001` before idx=2!
    // Append `strb w5, [x3]` at idx=6 (replacing ret, followed by ret at idx=7)
    let mut trace2_buf = trace_buf.clone();
    // Modify record 6 to be `strb w5, [x3]` (0x39000065) with x3 = 0x8200, x5 = 0x44
    let off6 = 6 * 272;
    trace2_buf[off6 + 32..off6 + 40].copy_from_slice(&0x8200u64.to_le_bytes()); // x3
    trace2_buf[off6 + 48..off6 + 56].copy_from_slice(&0x44u64.to_le_bytes()); // x5
    trace2_buf[off6 + 268..off6 + 272].copy_from_slice(&0x39000065u32.to_le_bytes()); // strb w5, [x3]
    let mut rec7 = vec![0u8; 272];
    rec7[0..8].copy_from_slice(&0x10001cu64.to_le_bytes());
    rec7[268..272].copy_from_slice(&0xd65f03c0u32.to_le_bytes()); // ret
    trace2_buf.extend_from_slice(&rec7);
    std::fs::write(cd.join("trace.bin"), &trace2_buf).unwrap();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"records":8,"tid":100,"ms":1,"truncated":false}"#,
    )
    .unwrap();

    let profile2 = VmProfile::for_lineage(None, None, None, None).unwrap();
    let lineage2 = byte_lineage(
        cd,
        "0x8200".to_string(),
        7,
        1,
        5,
        16,
        64,
        64,
        "x0,x1,x2,x3,x4,x5,x6".to_string(),
        false,
        false,
        profile2,
    )
    .unwrap();
    assert_eq!(lineage2["status"], "ready");
    let steps2 = lineage2["steps"].as_array().unwrap();
    // Step 0: last_write at 0x8200 (idx 6, strb w5, [x3]) -> next reg_at(idx=6, reg=w5)
    // Step 1: reg_source at idx 6 (local_def at idx 3: ldrb w5, [x0, #1], mem_addr=0x8001)
    //         upstream writer is memcpy at idx 2 (copy_from=0x7001) -> next addr_before(addr=0x7001, before_idx=2)
    // Step 2: last_write at 0x7001 (idx 1, str w4, [x1]) -> next reg_at(idx=1, reg=x4, byte_lane=1)
    // Step 3: reg_source at idx 1 (local_def at idx 0: movz x4)
    assert!(
        steps2
            .iter()
            .any(|s| s["kind"] == "last_write" && s["write"]["writer_idx"] == 1),
        "expected reg_source load from memcpy dst to hop to src writer at idx=1, got: {lineage2}"
    );
}

#[test]
fn memshadow_rejects_unverified_call_returning_first_arg() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;

    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_4r_1ms");
    std::fs::create_dir_all(&cd).unwrap();

    // 0: movz x4, #0x4443
    // 1: str w4, [x1]          -> writes [0x43, 0x44, 0, 0] to src=0x7000
    // 2: bl #0x101000          -> arbitrary call with x0=0x8000, x1=0x7000, x2=4 returning x0=0x8000,
    //                             but NO subsequent read on 0x8000..0x8004!
    // 3: ret
    let pcs = [0x100000u64, 0x100004, 0x100008, 0x10000c];
    let insts: [u32; 4] = [0xd2888864, 0xb9000024, 0x940003fe, 0xd65f03c0];
    let mut trace_buf = vec![0u8; 272 * 4];
    for i in 0..4 {
        let off = i * 272;
        trace_buf[off..off + 8].copy_from_slice(&pcs[i].to_le_bytes());
        trace_buf[off + 8..off + 16].copy_from_slice(&0x8000u64.to_le_bytes()); // x0
        trace_buf[off + 16..off + 24].copy_from_slice(&0x7000u64.to_le_bytes()); // x1
        trace_buf[off + 24..off + 32].copy_from_slice(&4u64.to_le_bytes()); // x2
        trace_buf[off + 40..off + 48].copy_from_slice(&0x41424443u64.to_le_bytes()); // x4
        trace_buf[off + 268..off + 272].copy_from_slice(&insts[i].to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &trace_buf).unwrap();
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
    let mem = MemShadow::build_from_trace(&trace);
    assert_eq!(
        mem.byte_at(0x8000, 10),
        (None, "??", None),
        "must not synthesize memcpy without post-call read verification"
    );
    assert!(mem.copy_sources.is_empty());
}

#[test]
fn compact_byte_event_is_8_bytes_and_checks_record_index_boundaries() {
    use tracemiku_core::memshadow::{ByteEvent, ByteEventKind};

    assert_eq!(std::mem::size_of::<ByteEvent>(), 8);
    assert_eq!(std::mem::size_of::<ByteEventKind>(), 1);
    let last = ByteEvent::try_new(u32::MAX as usize, 0x5a, ByteEventKind::Write).unwrap();
    assert_eq!(last.idx(), u32::MAX as usize);
    assert_eq!(last.byte, 0x5a);
    assert_eq!(last.kind.as_str(), "w");
    if usize::BITS > 32 {
        assert!(ByteEvent::try_new(u32::MAX as usize + 1, 0, ByteEventKind::Read).is_none());
    }
}

#[test]
fn mmap_sidecar_matches_cold_build_without_file_sized_heap_allocation() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;

    let (_tmp, cd) = synth_string_trace_dir();
    for i in 0..96u64 {
        append_store_record(&cd, 0x10000c + i * 4, 0x8000 + i * 8, 0x414200 + i);
    }
    std::fs::write(cd.join("meta.json"), r#"{"records":99,"tid":100,"ms":1}"#).unwrap();
    let trace = Trace::load(&cd).unwrap();
    let cold = MemShadow::load_or_build(&trace);
    let sidecar = MemShadow::sidecar_path(&trace);
    let sidecar_len = sidecar.metadata().unwrap().len() as usize;
    assert!(sidecar_len > 4 * 1024);

    let (hot, largest_allocation) =
        largest_allocation_during(|| MemShadow::try_load_sidecar(&trace).expect("mmap sidecar"));
    assert!(
        largest_allocation < sidecar_len,
        "largest heap allocation {largest_allocation} approached sidecar size {sidecar_len}"
    );
    assert!(hot.bytes.is_mapped());
    assert!(hot.writes.is_mapped());
    assert!(hot.reads.is_mapped());
    assert!(hot.copy_sources.is_mapped());
    assert_eq!(hot.bytes.heap_event_bytes(), 0);
    assert_eq!(hot.bytes.mapped_bytes(), sidecar_len);
    assert_eq!(cold.writes, hot.writes);
    assert_eq!(cold.reads, hot.reads);
    assert_eq!(cold.bytes, hot.bytes);
    for i in 0..96u64 {
        let addr = 0x8000 + i * 8;
        assert_eq!(cold.byte_at(addr, 50), hot.byte_at(addr, 50));
        assert_eq!(cold.byte_at(addr, u64::MAX), hot.byte_at(addr, u64::MAX));
    }

    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..4 {
            handles.push(scope.spawn(|| {
                let trace = Trace::load(&cd).unwrap();
                let concurrent = MemShadow::try_load_sidecar(&trace).expect("concurrent mmap");
                assert_eq!(concurrent.bytes, cold.bytes);
                assert_eq!(concurrent.byte_at(0x8000, 50), cold.byte_at(0x8000, 50));
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
    });
}

#[test]
fn invalid_event_kind_is_rejected_and_rebuilt() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;

    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).unwrap();
    let _ = MemShadow::load_or_build(&trace);
    let sidecar = MemShadow::sidecar_path(&trace);
    let mut blob = std::fs::read(&sidecar).unwrap();
    let events_offset = u64::from_le_bytes(blob[120..128].try_into().unwrap()) as usize;
    blob[events_offset + 5] = 0xff;
    std::fs::write(&sidecar, blob).unwrap();
    assert!(MemShadow::try_load_sidecar(&trace).is_none());
    let rebuilt = MemShadow::load_or_build(&trace);
    assert_eq!(rebuilt.byte_at(0x7000, u64::MAX).0, Some(b'h'));
    assert!(MemShadow::try_load_sidecar(&trace).is_some());
}

#[test]
fn large_worker_mmap_preserves_boundary_tail_conditional_and_anchor_semantics() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;

    let (_tmp, cd) = synth_string_trace_dir();
    std::fs::write(
        cd.join("meta.json"),
        r#"{"records":3,"tid":100,"ms":1,"workerTraces":[{"file":"worker_trace_tid200.bin","spawnedAtIdx":0,"endedAtIdx":2}]}"#,
    )
    .unwrap();
    let records = 400usize;
    let mut worker = vec![0u8; records * 272];
    for i in 0..records {
        let off = i * 272;
        worker[off..off + 8].copy_from_slice(&(0x200000u64 + i as u64 * 4).to_le_bytes());
        worker[off + 268..off + 272].copy_from_slice(&0xd503201fu32.to_le_bytes());
    }
    let set_reg = |buf: &mut [u8], idx: usize, reg: usize, value: u64| {
        let off = idx * 272 + 8 + reg * 8;
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    };
    let set_inst = |buf: &mut [u8], idx: usize, inst: u32| {
        let off = idx * 272 + 268;
        buf[off..off + 4].copy_from_slice(&inst.to_le_bytes());
    };
    // Record 240 crosses a 64 KiB streaming-buffer boundary.
    assert!(240 * 272 < 64 * 1024 && 241 * 272 > 64 * 1024);
    set_inst(&mut worker, 240, 0xf9000020);
    set_reg(&mut worker, 240, 0, 0x1122334455667788);
    set_reg(&mut worker, 240, 1, 0x9300);
    // stxr w0,x2,[x1]: failed because the next pre-state has w0=1.
    set_inst(&mut worker, 241, 0xc8007c22);
    set_reg(&mut worker, 241, 1, 0x9400);
    set_reg(&mut worker, 241, 2, 0xdeadbeef);
    // A successful conditional write followed by w0=0 must remain visible.
    set_inst(&mut worker, 242, 0xc8007c22);
    set_reg(&mut worker, 242, 0, 1);
    set_reg(&mut worker, 242, 1, 0x9500);
    set_reg(&mut worker, 242, 2, 0xfeedface);
    set_reg(&mut worker, 243, 0, 0);
    worker.extend_from_slice(b"partial-worker-tail");
    let worker_path = cd.join("worker_trace_tid200.bin");
    std::fs::write(&worker_path, &worker).unwrap();

    // Initialize Capstone outside the measurement so the assertion targets
    // worker I/O rather than the process-wide disassembler's one-time tables.
    let _ = tracemiku_core::disasm::decode(0x100000, 0xd503201f);
    let (mem, largest_allocation) = largest_allocation_during(|| {
        let trace = Trace::load(&cd).unwrap();
        MemShadow::build_from_trace(&trace)
    });
    assert!(
        largest_allocation < worker.len(),
        "worker file was copied to the heap: allocation={largest_allocation}, file={}",
        worker.len()
    );
    let anchor = 240 * 2 / (records - 1);
    assert_eq!(anchor, 1);
    assert_eq!(mem.byte_at(0x9300, 0), (None, "??", None));
    assert_eq!(mem.byte_at(0x9300, 1), (Some(0x88), "x", Some(anchor)));
    assert_eq!(mem.byte_at(0x9307, 2), (Some(0x11), "x", Some(anchor)));
    assert_eq!(mem.byte_at(0x9400, u64::MAX), (None, "??", None));
    assert_eq!(mem.byte_at(0x9500, u64::MAX), (Some(0xce), "x", Some(1)));
    assert!(mem
        .writes
        .windows(2)
        .all(|pair| (pair[0].idx, pair[0].addr) <= (pair[1].idx, pair[1].addr)));
}

#[test]
fn same_length_worker_rewrite_invalidates_sidecar() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;

    let (_tmp, cd) = synth_string_trace_dir();
    let mut worker = vec![0u8; 272];
    worker[0..8].copy_from_slice(&0x100100u64.to_le_bytes());
    worker[8..16].copy_from_slice(&0x11223344u64.to_le_bytes());
    worker[16..24].copy_from_slice(&0x9300u64.to_le_bytes());
    worker[268..272].copy_from_slice(&0xb9000020u32.to_le_bytes());
    let worker_path = cd.join("worker_trace_tid200.bin");
    std::fs::write(&worker_path, &worker).unwrap();
    let trace = Trace::load(&cd).unwrap();
    let cold = MemShadow::load_or_build(&trace);
    assert_eq!(cold.byte_at(0x9300, 10).0, Some(0x44));

    worker[8..16].copy_from_slice(&0x55667788u64.to_le_bytes());
    std::fs::write(&worker_path, &worker).unwrap();
    let rebuilt = MemShadow::load_or_build(&trace);
    assert_eq!(rebuilt.byte_at(0x9300, 10).0, Some(0x88));
    let hot = MemShadow::try_load_sidecar(&trace).expect("rebuilt sidecar");
    assert_eq!(hot.byte_at(0x9300, 10).0, Some(0x88));
}

#[test]
fn old_version_sidecar_is_rebuilt_instead_of_deserialized() {
    use tracemiku_core::memshadow::MemShadow;
    use tracemiku_core::prelude::Trace;

    let (_tmp, cd) = synth_string_trace_dir();
    let trace = Trace::load(&cd).unwrap();
    let _ = MemShadow::load_or_build(&trace);
    let sidecar = MemShadow::sidecar_path(&trace);
    let mut blob = std::fs::read(&sidecar).unwrap();
    blob[..8].copy_from_slice(b"TMMSV7\0\0");
    blob[8..12].copy_from_slice(&7u32.to_le_bytes());
    std::fs::write(&sidecar, blob).unwrap();
    assert!(MemShadow::try_load_sidecar(&trace).is_none());
    let rebuilt = MemShadow::load_or_build(&trace);
    assert_eq!(rebuilt.byte_at(0x7000, u64::MAX).0, Some(b'h'));
    assert!(MemShadow::try_load_sidecar(&trace).is_some());
}
