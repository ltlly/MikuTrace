//! TDD for tracemiku-core::index.

#[path = "common/mod.rs"]
mod common;

use tracemiku_core::prelude::*;

/// Build a synth per-call trace dir from a list of (pc, inst, gprs) specs.
/// Each spec sets PC + inst + a list of (reg_idx, value) GPR overrides.
/// `reg_idx` 0..=28 = x0..x28, 29 = fp, 30 = lr. Out-of-range silently ignored.
/// SP defaults to 0x7000.
#[allow(clippy::type_complexity)]
fn write_synth_trace(cd: &std::path::Path, specs: &[(u64, u32, &[(usize, u64)])]) {
    use std::fs;
    use std::io::Write;
    let mut bf = fs::File::create(cd.join("trace.bin")).unwrap();
    for (pc, inst, gprs) in specs {
        let mut buf = [0u8; 272];
        buf[0..8].copy_from_slice(&pc.to_le_bytes());
        for (gi, gv) in *gprs {
            if *gi < 31 {
                let go = 8 + gi * 8;
                buf[go..go + 8].copy_from_slice(&gv.to_le_bytes());
            }
        }
        let sp: u64 = 0x7000;
        buf[256..264].copy_from_slice(&sp.to_le_bytes());
        buf[268..272].copy_from_slice(&inst.to_le_bytes());
        bf.write_all(&buf).unwrap();
    }
    fs::write(
        cd.join("meta.json"),
        format!(
            r#"{{"records":{},"tid":100,"ms":2,"truncated":false}}"#,
            specs.len()
        ),
    )
    .unwrap();
    let run = cd.parent().unwrap().parent().unwrap();
    fs::write(
        run.join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
}

/// Make a per-call dir with the given `<n>r` records suffix and return (tmp_guard, call_dir).
fn make_call_dir(n_records: usize) -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join(format!("call_001_tid100_{}r_2ms", n_records));
    std::fs::create_dir_all(&cd).unwrap();
    (tmp, cd)
}

#[test]
fn index_records_reg_def_for_mov_record() {
    use std::fs;
    use std::io::Write;

    let tmp = tempfile::tempdir().unwrap();
    let cd = tmp
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid100_1r_2ms");
    fs::create_dir_all(&cd).unwrap();

    let mut buf = vec![0u8; 272];
    buf[0..8].copy_from_slice(&0x100000u64.to_le_bytes());
    buf[256..264].copy_from_slice(&0x7000u64.to_le_bytes());
    buf[268..272].copy_from_slice(&0xaa0103e0u32.to_le_bytes()); // mov x0, x1
    let mut f = fs::File::create(cd.join("trace.bin")).unwrap();
    f.write_all(&buf).unwrap();

    fs::write(
        cd.join("meta.json"),
        r#"{"records":1,"tid":100,"ms":2,"truncated":false}"#,
    )
    .unwrap();
    fs::write(
        tmp.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();

    let t = Trace::load(&cd).unwrap();
    let idx = Index::build(&t);

    let x0_defs = idx.reg_defs.get("x0").expect("x0 must have defs");
    assert_eq!(x0_defs, &vec![0usize]);

    let x1_uses = idx.reg_uses.get("x1").expect("x1 must have uses");
    assert_eq!(x1_uses, &vec![0usize]);

    assert!(idx.reg_uses.get("x0").map(|v| v.is_empty()).unwrap_or(true));
}

#[test]
fn index_empty_trace_yields_empty_index() {
    let fix = common::synth_trace_dir(0);
    let t = Trace::load(&fix.call_dir).unwrap();
    let idx = Index::build(&t);
    assert!(idx.reg_defs.is_empty());
    assert!(idx.reg_uses.is_empty());
}

#[test]
fn index_synth_trace_has_consistent_counts() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    let idx = Index::build(&t);
    let total_def_entries: usize = idx.reg_defs.values().map(|v| v.len()).sum();
    let total_use_entries: usize = idx.reg_uses.values().map(|v| v.len()).sum();
    assert_eq!(
        total_def_entries, 0,
        "nop-only synth trace should have no defs, got: {:?}",
        idx.reg_defs
    );
    assert_eq!(total_use_entries, 0);
}

#[test]
fn index_records_mem_writes_with_idx_and_addr() {
    // str x0, [x1, #0x10] with x1=0x7000 → write at 0x7010, size=8.
    let (_tmp, cd) = make_call_dir(1);
    write_synth_trace(
        &cd,
        &[
            // x1 (reg slot 1) = 0x7000
            (0x100000u64, 0xf9000820u32, &[(1usize, 0x7000u64)]),
        ],
    );
    let t = Trace::load(&cd).unwrap();
    let idx = Index::build(&t);

    assert_eq!(idx.mem_writes.len(), 1, "expected 1 mem_write");
    assert!(idx.mem_reads.is_empty(), "expected 0 mem_reads");
    let mw = &idx.mem_writes[0];
    assert_eq!(mw.idx, 0);
    assert_eq!(mw.addr, 0x7010);
    assert_eq!(mw.size, 8);
    assert_eq!(mw.value, None);
    assert_eq!(idx.mem_addr_to_writes.get(&0x7010).cloned(), Some(vec![0]));
}

#[test]
fn index_records_mem_reads_separate_from_writes() {
    // record 0: str x0, [x1] with x1=0x7000 → write at 0x7000
    // record 1: ldr x2, [x1] with x1=0x7000 → read at 0x7000
    let (_tmp, cd) = make_call_dir(2);
    write_synth_trace(
        &cd,
        &[
            (0x100000u64, 0xf9000020u32, &[(1usize, 0x7000u64)]),
            (0x100004u64, 0xf9400022u32, &[(1usize, 0x7000u64)]),
        ],
    );
    let t = Trace::load(&cd).unwrap();
    let idx = Index::build(&t);

    assert_eq!(idx.mem_writes.len(), 1, "expected 1 mem_write");
    assert_eq!(idx.mem_reads.len(), 1, "expected 1 mem_read");
    assert_eq!(idx.mem_writes[0].idx, 0);
    assert_eq!(idx.mem_writes[0].addr, 0x7000);
    assert_eq!(idx.mem_writes[0].size, 8);
    assert_eq!(idx.mem_reads[0].idx, 1);
    assert_eq!(idx.mem_reads[0].addr, 0x7000);
    assert_eq!(idx.mem_reads[0].size, 8);
    // Reads must NOT appear in mem_addr_to_writes.
    assert_eq!(idx.mem_addr_to_writes.get(&0x7000).cloned(), Some(vec![0]));
}

#[test]
fn index_addr_to_writes_lookup_returns_idxs_in_order() {
    // 3 records, two writes to 0x7000 (idx 0,1) and one to 0x7010 (idx 2).
    let (_tmp, cd) = make_call_dir(3);
    write_synth_trace(
        &cd,
        &[
            // str x0, [x1] with x1=0x7000 → addr 0x7000
            (0x100000u64, 0xf9000020u32, &[(1usize, 0x7000u64)]),
            // str x0, [x1] with x1=0x7000 → addr 0x7000 again
            (0x100004u64, 0xf9000020u32, &[(1usize, 0x7000u64)]),
            // str x0, [x1, #0x10] with x1=0x7000 → addr 0x7010
            (0x100008u64, 0xf9000820u32, &[(1usize, 0x7000u64)]),
        ],
    );
    let t = Trace::load(&cd).unwrap();
    let idx = Index::build(&t);

    assert_eq!(idx.mem_writes.len(), 3, "expected 3 mem_writes");
    assert_eq!(
        idx.mem_addr_to_writes.get(&0x7000).cloned(),
        Some(vec![0, 1])
    );
    assert_eq!(idx.mem_addr_to_writes.get(&0x7010).cloned(), Some(vec![2]));
}

#[test]
fn index_no_mem_op_does_not_add_records() {
    let fix = common::synth_trace_dir(5);
    let t = Trace::load(&fix.call_dir).unwrap();
    let idx = Index::build(&t);
    assert!(idx.mem_writes.is_empty(), "nop trace must have no writes");
    assert!(idx.mem_reads.is_empty(), "nop trace must have no reads");
    assert!(idx.mem_addr_to_writes.is_empty());
}

#[test]
fn index_addr_to_writes_holds_trace_indices_not_vec_indices() {
    // Regression: previously the impl stored mem_writes.len() (vec position)
    // instead of `i` (trace record idx). Both consumers (taint backward,
    // last-write-of-addr) bisect against trace-record-idx cursors, so a read
    // record between two writes must NOT shift the second write's reported
    // index.
    //
    // 3 records:
    //   idx 0: str x0, [x1]  with x1=0x7000  → write to 0x7000
    //   idx 1: ldr x2, [x1]  with x1=0x7000  → read of 0x7000 (NOT a write)
    //   idx 2: str x0, [x1]  with x1=0x7000  → write to 0x7000
    //
    // Correct: mem_addr_to_writes[0x7000] = vec![0, 2]   (trace indices)
    // Bug:     mem_addr_to_writes[0x7000] = vec![0, 1]   (vec indices, since
    //                                                     mem_writes had len 1
    //                                                     when idx=2 was pushed)
    let (_tmp, cd) = make_call_dir(3);
    write_synth_trace(
        &cd,
        &[
            (0x100000u64, 0xf9000020u32, &[(1usize, 0x7000u64)]),
            (0x100004u64, 0xf9400022u32, &[(1usize, 0x7000u64)]),
            (0x100008u64, 0xf9000020u32, &[(1usize, 0x7000u64)]),
        ],
    );
    let t = Trace::load(&cd).unwrap();
    let idx = Index::build(&t);

    assert_eq!(idx.mem_writes.len(), 2, "expected 2 mem_writes (idx 0 + 2)");
    assert_eq!(idx.mem_reads.len(), 1, "expected 1 mem_read (idx 1)");
    assert_eq!(
        idx.mem_addr_to_writes.get(&0x7000).cloned(),
        Some(vec![0usize, 2]),
        "addr_to_writes must hold trace record indices, not mem_writes vec indices"
    );
}
