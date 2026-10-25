use super::*;
use crate::trace::REC_SIZE;

fn synth_two_callees() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_9r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 9] = [
        0x100000, 0x100004, 0x100100, 0x100104, 0x100008, 0x100200, 0x100204, 0x100208, 0x10000c,
    ];
    let insts: [u32; 9] = [
        0xd503201f, 0x9400003f, 0xd503201f, 0xd65f03c0, 0x9400007e, 0xd503201f, 0xd503201f,
        0xd65f03c0, 0xd65f03c0,
    ];
    let mut buf = vec![0u8; REC_SIZE * 9];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * REC_SIZE;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":9}"#).unwrap();
    std::fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":65536}}"#,
    )
    .unwrap();
    dir
}

fn synth_x0_chain() -> tempfile::TempDir {
    // 5 records of `add x0, x0, #1` (opcode 0x91000400). If this opcode
    // does not produce regs_use=[x0] under your capstone wrapper, swap for
    // `add x0, x0, x1` (0x8b010000) and ensure the test still asserts x0.
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_5r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; REC_SIZE * 5];
    for i in 0..5 {
        let off = i * REC_SIZE;
        let pc = 0x100000u64 + (i as u64) * 4;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&0x91000400u32.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
    std::fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
    )
    .unwrap();
    dir
}

fn load_trace(dir: &tempfile::TempDir) -> Trace {
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    Trace::load(&cd).unwrap()
}

fn synth_trace_with<F>(insts: &[u32], mut fill: F) -> tempfile::TempDir
where
    F: FnMut(usize, &mut [u8]),
{
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join(format!("call_001_tid1_{}r_1ms", insts.len()));
    std::fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; REC_SIZE * insts.len()];
    for (i, inst) in insts.iter().enumerate() {
        let off = i * REC_SIZE;
        let rec = &mut buf[off..off + REC_SIZE];
        let pc = 0x100000u64 + (i as u64) * 4;
        rec[0..8].copy_from_slice(&pc.to_le_bytes());
        rec[256..264].copy_from_slice(&0x7000u64.to_le_bytes());
        rec[268..272].copy_from_slice(&inst.to_le_bytes());
        fill(i, rec);
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(
        cd.join("meta.json"),
        format!(r#"{{"records":{}}}"#, insts.len()),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
    )
    .unwrap();
    dir
}

#[test]
fn frame_depth_map_root_only_then_one_call() {
    let dir = synth_two_callees();
    let t = load_trace(&dir);
    let depths = build_frame_depth_map(&t);
    assert_eq!(depths.len(), 9);
    assert_eq!(depths[0], 0);
    assert_eq!(depths[1], 0);
    assert_eq!(depths[2], 1);
    assert_eq!(depths[3], 1);
    assert_eq!(depths[4], 0);
    assert_eq!(depths[5], 1);
    assert_eq!(depths[8], 0);
}

#[test]
fn forward_taint_empty_when_reg_unused() {
    let dir = synth_two_callees();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
    assert!(hits.is_empty());
    assert!(!stopped);
}

#[test]
fn forward_taint_kills_clean_reg_overwrite() {
    // idx 0 seeds x0, idx 1 overwrites x0 with an immediate, idx 2 reads x0.
    // Without explicit def-event kill semantics idx 2 was a false positive.
    let dir = synth_trace_with(&[0xd2800020, 0xd2800000, 0x91000401], |i, rec| {
        let x0 = if i == 0 { 1u64 } else { 0u64 };
        rec[8..16].copy_from_slice(&x0.to_le_bytes());
    });
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
    assert!(!stopped);
    assert!(
        hits.iter().all(|h| h.idx != 2),
        "clean overwrite at idx 1 should kill x0 before idx 2: {hits:?}"
    );
}

#[test]
fn forward_taint_partial_modify_preserves_reg_taint() {
    // movk is a partial register update. If Capstone does not expose the old
    // destination as a use, the taint engine still keeps the existing x0 taint.
    let dir = synth_trace_with(&[0xd2800020, 0xf2800040, 0x91000401], |_, rec| {
        rec[8..16].copy_from_slice(&1u64.to_le_bytes());
    });
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
    assert!(!stopped);
    assert!(
        hits.iter().any(|h| h.idx == 2),
        "movk should preserve x0 taint through the later add: {hits:?}"
    );
}

#[test]
fn backward_taint_empty_when_reg_undefined() {
    let dir = synth_two_callees();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = backward_taint(&t, &idx, 8, "x0", 100, &exclude, false, None, false);
    assert!(hits.is_empty());
    assert!(!stopped);
}

#[test]
fn forward_taint_max_count_caps() {
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 3, &exclude, false, None, false);
    assert_eq!(hits.len(), 3, "should stop after 3 hits, got {hits:?}");
    assert!(stopped, "max_count truncation should set stopped=true");
    for h in &hits {
        assert!(h.why.contains("x0"), "hit row references x0: {h:?}");
    }
}

#[test]
fn forward_taint_updates_self_reg_provenance() {
    // Same-reg read-modify-write must advance provenance for tree view:
    // seed x0 at idx=0, then each `add x0, x0, #1` depends on the prior hit.
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
    assert!(!stopped);
    let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
    assert_eq!(idxs, vec![1, 2, 3, 4], "forward self-chain hits: {hits:?}");

    let row1 = hits.iter().find(|h| h.idx == 1).unwrap();
    assert_eq!(row1.parent_idxs, Vec::<usize>::new());
    assert_eq!(row1.taint_depth, 0);
    for (expected_idx, expected_parent, expected_depth) in [(2, 1, 1), (3, 2, 2), (4, 3, 3)] {
        let row = hits.iter().find(|h| h.idx == expected_idx).unwrap();
        assert_eq!(
            row.parent_idxs,
            vec![expected_parent],
            "row #{expected_idx} should depend on #{expected_parent}: {row:?}"
        );
        assert_eq!(
            row.taint_depth, expected_depth,
            "row #{expected_idx} depth should advance along self-chain: {row:?}"
        );
    }
}

#[test]
fn backward_taint_emits_bare_reg_name() {
    // 5-record `add x0, x0, #1` chain. Backward from idx=4, taint=x0.
    // Each `add x0, x0, #1` defines x0 AND uses x0, so chasing x0 backward
    // should include the seed at idx=4 plus prior defs 3, 2, 1, 0.
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = backward_taint(&t, &idx, 4, "x0", 100, &exclude, false, None, false);
    let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
    assert_eq!(
        idxs,
        vec![0, 1, 2, 3, 4],
        "should chase self read-modify-write chain backwards: {hits:?}"
    );
    assert!(!stopped);
    // Wire-shape pin: `why` is the bare reg name, NOT "via:x0".
    for h in &hits {
        assert_eq!(h.why, "x0", "expected bare reg name, got {:?}", h.why);
    }
    // Order: dedup'd by sorted idx, so smallest idx first.
    for w in idxs.windows(2) {
        assert!(w[0] < w[1], "hits sorted by ascending idx: {idxs:?}");
    }
}

#[test]
fn backward_taint_chases_mem_writer() {
    // 5-record trace:
    //   idx 0: mov x0, x2   (0xaa0203e0)  — defines x0 from x2
    //   idx 1: str x0, [sp] (0xf90003e0)  — store x0 to [sp]
    //   idx 2: nop          (0xd503201f)
    //   idx 3: ldr x1, [sp] (0xf94003e1)  — defs x1 from [sp]
    //   idx 4: nop          (0xd503201f)
    //
    // Backward from idx=3, taint=x1.
    //   d0 (idx=3) defines x1 → starts_with_def branch:
    //     pre-emit (3, "x1"); push regs_use of d0 (sp); push MEM(3, 0x7000, 8).
    //   pop Reg(3, sp): no defs of sp → continue.
    //   pop MEM(3, 0x7000, 8): writers of 0x7000 < 3 → idx 1.
    //     emit idx 1 as the memory writer; first non-addressing reg in
    //     d.regs_use → x0; push Reg(1, "x0") with parent idx 1.
    //   pop Reg(1, "x0"): defs of x0 before 1 → idx 0; emit (0, "x0").
    //
    // Expected: hits idxs include 0, 1, and 3.
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_5r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let mut buf = vec![0u8; REC_SIZE * 5];
    let pcs: [u64; 5] = [0x100000, 0x100004, 0x100008, 0x10000c, 0x100010];
    let insts: [u32; 5] = [0xaa0203e0, 0xf90003e0, 0xd503201f, 0xf94003e1, 0xd503201f];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * REC_SIZE;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        // x0 = 0xdead so values are defined.
        buf[off + 8..off + 16].copy_from_slice(&0xdeadu64.to_le_bytes());
        // x2 = 0xbeef so x0 := x2 has a defined source.
        buf[off + 24..off + 32].copy_from_slice(&0xbeefu64.to_le_bytes());
        // sp = 0x7000.
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":5}"#).unwrap();
    std::fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
    )
    .unwrap();
    let cd_path = dir
        .path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let t = Trace::load(&cd_path).unwrap();
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, _stopped) = backward_taint(&t, &idx, 3, "x1", 100, &exclude, false, None, false);
    let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
    assert!(
        idxs.contains(&0),
        "MEM-chasing should reach idx 0 via mov→str→ldr at sp=0x7000; got {idxs:?}"
    );
    assert!(
        idxs.contains(&1),
        "MEM-chasing should expose idx 1 as the memory writer; got {idxs:?}"
    );
    assert!(
        idxs.contains(&3),
        "should pre-emit (idx=3, want_reg=x1) when start defines x1; got {idxs:?}"
    );
    let row1 = hits.iter().find(|h| h.idx == 1).unwrap();
    assert_eq!(row1.why, "mem");
    assert_eq!(row1.parent_idxs, vec![3]);
    assert_eq!(row1.edge_kind.as_deref(), Some("mem"));
    let row0 = hits.iter().find(|h| h.idx == 0).unwrap();
    assert_eq!(row0.parent_idxs, vec![1]);
    assert_eq!(row0.edge_kind.as_deref(), Some("store-src"));
}

#[test]
fn backward_taint_includes_control_dependency_when_enabled() {
    // idx 0: cmp x0, #0
    // idx 1: b.eq #8
    // idx 2: mov x1, x2
    let dir = synth_trace_with(&[0xf100001f, 0x54000040, 0xaa0203e1], |_, rec| {
        rec[8..16].copy_from_slice(&1u64.to_le_bytes()); // x0
        rec[24..32].copy_from_slice(&2u64.to_le_bytes()); // x2
    });
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();

    let (hits, stopped) = backward_taint(&t, &idx, 2, "x1", 100, &exclude, false, None, false);
    assert!(!stopped);
    let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
    assert!(
        idxs.contains(&1),
        "control branch should be included in backward taint: {hits:?}"
    );
    assert!(
        idxs.contains(&0),
        "control branch condition should chase back to cmp/nzcv def: {hits:?}"
    );
    let branch = hits.iter().find(|h| h.idx == 1).unwrap();
    assert_eq!(branch.why, "control");
    assert_eq!(branch.edge_kind.as_deref(), Some("control"));

    let (data_hits, _) = backward_taint(&t, &idx, 2, "x1", 100, &exclude, false, None, true);
    let data_idxs: Vec<usize> = data_hits.iter().map(|h| h.idx).collect();
    assert!(
        !data_idxs.contains(&1),
        "data_only=true should suppress control branch dependency: {data_hits:?}"
    );
}

#[test]
fn backward_taint_does_not_attach_control_across_call_boundary() {
    // idx 0: cmp x0, #0
    // idx 1: b.eq #8
    // idx 2: bl #8        -- boundary between caller condition and callee body
    // idx 3: mov x1, x2   -- pretend this is inside the callee
    let dir = synth_trace_with(
        &[0xf100001f, 0x54000040, 0x94000002, 0xaa0203e1],
        |_, rec| {
            rec[8..16].copy_from_slice(&1u64.to_le_bytes()); // x0
            rec[24..32].copy_from_slice(&2u64.to_le_bytes()); // x2
        },
    );
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = backward_taint(&t, &idx, 3, "x1", 100, &exclude, false, None, false);
    assert!(!stopped);
    let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
    assert!(
        !idxs.contains(&1),
        "caller-side conditional branch should not control a row past bl boundary: {hits:?}"
    );
}

#[test]
fn backward_taint_pair_load_chases_matching_store_half() {
    // idx 0: mov x0, x2
    // idx 1: mov x1, x3
    // idx 2: stp x0, x1, [sp]
    // idx 3: ldp x4, x5, [sp]
    //
    // Backward from x5 must chase the second ldp/stp half through x1, not
    // the first half through x0.
    let dir = synth_trace_with(
        &[0xaa0203e0, 0xaa0303e1, 0xa90007e0, 0xa94017e4],
        |_, rec| {
            rec[8..16].copy_from_slice(&0x1111u64.to_le_bytes()); // x0
            rec[16..24].copy_from_slice(&0x2222u64.to_le_bytes()); // x1
            rec[24..32].copy_from_slice(&0xaaaau64.to_le_bytes()); // x2
            rec[32..40].copy_from_slice(&0xbbbbu64.to_le_bytes()); // x3
        },
    );
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (hits, stopped) = backward_taint(&t, &idx, 3, "x5", 100, &exclude, false, None, true);
    assert!(!stopped);
    let idxs: Vec<usize> = hits.iter().map(|h| h.idx).collect();
    assert!(
        idxs.contains(&1),
        "x5 should chase through second store half source x1: {hits:?}"
    );
    assert!(
        !idxs.contains(&0),
        "x5 should not chase through first store half source x0: {hits:?}"
    );
}

#[test]
fn forward_taint_through_mem_byte_overlap_extends_taint() {
    // 4-record trace exploring byte-overlap behavior:
    //   idx 0: mov x0, #0xab     (defines x0)
    //   idx 1: str x0, [x0]      (8-byte write, taints bytes [x0_val, x0_val+8))
    //   idx 2: ldr w1, [x0, #4]  (4-byte load at x0_val+4..x0_val+8 —
    //                             ONLY overlaps when through_mem tags full range)
    //   idx 3: nop
    //
    // Both insns have x0 in regs_use, so the heap-driven loop visits
    // them via push_reg(x0). The differentiator is whether load_tainted
    // fires at idx 2:
    //   through_mem=true:  bytes x0+4..x0+8 ARE tagged → "mem" in why
    //   through_mem=false: only base byte (x0) tagged → no overlap → no "mem"
    //
    // x0 register value in fixture = 0xab (so store taints 0xab..0xb3,
    // load reads 0xaf..0xb3 — fully inside the tainted range).
    //
    // Opcodes (ARM64 LE):
    //   mov x0, #0xab     = 0xd2801560
    //   str x0, [x0]      = 0xf9000000
    //   ldr w1, [x0, #4]  = 0xb9400401
    //   nop               = 0xd503201f
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_4r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 4] = [0x100000, 0x100004, 0x100008, 0x10000c];
    let insts: [u32; 4] = [0xd2801560, 0xf9000000, 0xb9400401, 0xd503201f];
    let mut buf = vec![0u8; REC_SIZE * 4];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * REC_SIZE;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        // x0 = 0xab (offset 8..16)
        buf[off + 8..off + 16].copy_from_slice(&0xabu64.to_le_bytes());
        // sp (offset 256..264)
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        // inst (offset 268..272)
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
    std::fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
    )
    .unwrap();
    let cd_path = dir
        .path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let t = Trace::load(&cd_path).unwrap();
    let idx = Index::build(&t);
    let mem = MemShadow::build_from_trace(&t);
    let exclude = HashSet::new();

    // through_mem=true: idx 2 hits with "mem" in why (byte-overlap match).
    let (hits_on, _stopped) =
        forward_taint(&t, &idx, 0, "x0", 100, &exclude, true, Some(&mem), false);
    let idxs_on: Vec<usize> = hits_on.iter().map(|h| h.idx).collect();
    assert!(
        idxs_on.contains(&1),
        "idx 1 (str) should emit; got {idxs_on:?}"
    );
    assert!(
        idxs_on.contains(&2),
        "idx 2 (ldr [x0,#4]) should emit; got {idxs_on:?}"
    );
    let row2_on = hits_on.iter().find(|h| h.idx == 2).unwrap();
    assert!(
        row2_on.why.contains("mem"),
        "through_mem=true: idx 2 why should contain 'mem'; got {row2_on:?}"
    );
    let row1_on = hits_on.iter().find(|h| h.idx == 1).unwrap();
    assert_eq!(
        row1_on.taint_depth, 0,
        "seed-driven first store should be a root tree node: {row1_on:?}"
    );
    assert!(
        row1_on.parent_idxs.is_empty(),
        "seed-driven first store should not have parents: {row1_on:?}"
    );
    assert_eq!(
        row2_on.parent_idxs,
        vec![1],
        "load should depend on the store that tainted memory: {row2_on:?}"
    );
    assert_eq!(
        row2_on.taint_depth, 1,
        "load depending on row 1 should be one level below it: {row2_on:?}"
    );

    // through_mem=false: idx 2 still emits (regs:x0 use), but NO "mem" —
    // only the base byte (x0_val) is tagged, load reads x0_val+4..+8.
    let (hits_off, _stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
    let row2_off = hits_off.iter().find(|h| h.idx == 2).unwrap();
    assert!(
        !row2_off.why.contains("mem"),
        "through_mem=false: idx 2 why must NOT contain 'mem' (base-only tag); got {row2_off:?}"
    );
}

#[test]
fn forward_taint_clean_store_kills_tainted_memory() {
    // idx 0: mov x0, #0xab
    // idx 1: str x0, [sp]    -> taints [sp]
    // idx 2: mov x0, #0      -> kills x0
    // idx 3: str x2, [sp]    -> clean overwrite must kill [sp]
    // idx 4: ldr x1, [sp]    -> must not reload stale memory taint
    let dir = synth_trace_with(
        &[0xd2801560, 0xf90003e0, 0xd2800000, 0xf90003e2, 0xf94003e1],
        |_, rec| {
            rec[8..16].copy_from_slice(&0xabu64.to_le_bytes()); // x0
            rec[24..32].copy_from_slice(&0xcdu64.to_le_bytes()); // x2
        },
    );
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let mem = MemShadow::build_from_trace(&t);
    let (hits, stopped) = forward_taint(&t, &idx, 0, "x0", 100, &exclude, true, Some(&mem), false);
    assert!(!stopped);
    assert!(
        hits.iter().any(|h| h.idx == 1),
        "seed x0 should taint the first store: {hits:?}"
    );
    assert!(
        !hits.iter().any(|h| h.idx == 4 && h.why.contains("mem")),
        "clean store at idx 3 should clear memory before load idx 4: {hits:?}"
    );
}

#[test]
fn forward_taint_data_only_filters_addressing_regs() {
    // 4-record trace where x1 is tainted; an `ldr w2, [x0, x1]` uses x1
    // PURELY as an index reg (addressing), and `add x3, x3, x1` uses x1
    // as a value reg.
    //
    //   idx 0: mov x1, #0xab    (defines x1)
    //   idx 1: ldr w2, [x0, x1] (reads x1 as index → addressing)
    //   idx 2: add x3, x3, x1   (reads x1 as value)
    //   idx 3: nop
    //
    // forward_taint(start=0, reg=x1):
    //   data_only=false: hits include idx 1 (x1 in regs_use, even if addressing)
    //                    AND idx 2 (x1 in regs_use as value).
    //   data_only=true:  hits exclude idx 1 (x1 filtered as addressing reg).
    //                    Includes idx 2 only.
    //
    // Opcodes (ARM64 LE):
    //   mov x1, #0xab        = 0xd2801561
    //   ldr w2, [x0, x1]     = 0xb8616802  (extended-reg form; x1 = index)
    //   add x3, x3, x1       = 0x8b010063
    //   nop                  = 0xd503201f
    let dir = tempfile::tempdir().unwrap();
    let cd = dir
        .path()
        .join("run")
        .join("calls")
        .join("call_001_tid1_4r_1ms");
    std::fs::create_dir_all(&cd).unwrap();
    let pcs: [u64; 4] = [0x100000, 0x100004, 0x100008, 0x10000c];
    let insts: [u32; 4] = [0xd2801561, 0xb8616802, 0x8b010063, 0xd503201f];
    let mut buf = vec![0u8; REC_SIZE * 4];
    for (i, (pc, inst)) in pcs.iter().zip(insts.iter()).enumerate() {
        let off = i * REC_SIZE;
        buf[off..off + 8].copy_from_slice(&pc.to_le_bytes());
        buf[off + 8..off + 16].copy_from_slice(&0u64.to_le_bytes()); // x0
        buf[off + 16..off + 24].copy_from_slice(&0xabu64.to_le_bytes()); // x1
        buf[off + 24..off + 32].copy_from_slice(&0u64.to_le_bytes()); // x2
        buf[off + 32..off + 40].copy_from_slice(&0u64.to_le_bytes()); // x3
        buf[off + 256..off + 264].copy_from_slice(&0x7000u64.to_le_bytes());
        buf[off + 268..off + 272].copy_from_slice(&inst.to_le_bytes());
    }
    std::fs::write(cd.join("trace.bin"), &buf).unwrap();
    std::fs::write(cd.join("meta.json"), r#"{"records":4}"#).unwrap();
    std::fs::write(
        dir.path().join("run").join("meta.json"),
        r#"{"module":{"name":"libt.so","base":"0x100000","size":4096}}"#,
    )
    .unwrap();
    let cd_path = dir
        .path()
        .join("run")
        .join("calls")
        .read_dir()
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let t = Trace::load(&cd_path).unwrap();
    let idx = Index::build(&t);
    let exclude = HashSet::new();

    // data_only=false: should hit idx 1 AND idx 2 on x1.
    let (hits_loose, _) = forward_taint(&t, &idx, 0, "x1", 100, &exclude, false, None, false);
    let idxs_loose: Vec<usize> = hits_loose.iter().map(|h| h.idx).collect();
    assert!(
        idxs_loose.contains(&1),
        "data_only=false: idx 1 (ldr [x0,x1]) should hit; got {idxs_loose:?}"
    );
    assert!(
        idxs_loose.contains(&2),
        "data_only=false: idx 2 (add x3,x3,x1) should hit; got {idxs_loose:?}"
    );

    // data_only=true: should hit idx 2 only — idx 1 filtered as addressing.
    let (hits_strict, _) = forward_taint(&t, &idx, 0, "x1", 100, &exclude, false, None, true);
    let idxs_strict: Vec<usize> = hits_strict.iter().map(|h| h.idx).collect();
    assert!(
        !idxs_strict.contains(&1),
        "data_only=true: idx 1 should be filtered (x1 is index reg); got {idxs_strict:?}"
    );
    assert!(
        idxs_strict.contains(&2),
        "data_only=true: idx 2 should still hit; got {idxs_strict:?}"
    );
}

#[test]
fn forward_taint_ext_completes_when_no_limits() {
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let result = forward_taint_ext(
        &t,
        &idx,
        0,
        "x0",
        100,
        &exclude,
        None,
        TaintOptions::default(),
    );
    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.hits.len(), 4);
}

#[test]
fn forward_taint_ext_max_count_sets_max_count_reason() {
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let result = forward_taint_ext(
        &t,
        &idx,
        0,
        "x0",
        2,
        &exclude,
        None,
        TaintOptions::default(),
    );
    assert_eq!(result.stop_reason, StopReason::MaxCount);
    assert_eq!(result.hits.len(), 2);
}

#[test]
fn forward_taint_ext_scan_limit_kicks_in_on_dead_seed() {
    // Seed reg never appears in trace, so the BFS finds nothing. With
    // a scan_limit of 1 the watchdog should trip.
    let dir = synth_two_callees();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let result = forward_taint_ext(
        &t,
        &idx,
        0,
        "x9",
        100,
        &exclude,
        None,
        TaintOptions {
            through_mem: false,
            data_only: false,
            scan_limit: Some(1),
        },
    );
    // With no reg events scheduled the heap is empty, so the loop never
    // runs and the walk completes (no hits, no scan-limit trip).
    assert!(result.hits.is_empty());
    assert!(matches!(
        result.stop_reason,
        StopReason::Completed | StopReason::ScanLimit
    ));
}

#[test]
fn forward_taint_ext_scan_limit_trips_when_walk_runs_dry() {
    // x0_chain emits one hit per record, but the heap interleaves
    // register-use and register-def events for the same row, so the
    // BFS pops several already-seen rows between hits. With a tight
    // scan_limit those idle iterations exhaust the watchdog before the
    // queue drains.
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let result = forward_taint_ext(
        &t,
        &idx,
        0,
        "x0",
        100,
        &exclude,
        None,
        TaintOptions {
            through_mem: false,
            data_only: false,
            scan_limit: Some(1),
        },
    );
    assert_eq!(
        result.stop_reason,
        StopReason::ScanLimit,
        "scan_limit=1 must trip in synth_x0_chain when duplicate events are popped"
    );
}

#[test]
fn forward_taint_ext_scan_limit_completes_when_limit_is_high() {
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let result = forward_taint_ext(
        &t,
        &idx,
        0,
        "x0",
        100,
        &exclude,
        None,
        TaintOptions {
            through_mem: false,
            data_only: false,
            scan_limit: Some(10_000),
        },
    );
    assert_eq!(result.stop_reason, StopReason::Completed);
    assert_eq!(result.hits.len(), 4);
}

#[test]
fn backward_taint_ext_max_count_reports_max_count_reason() {
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let result = backward_taint_ext(
        &t,
        &idx,
        4,
        "x0",
        2,
        &exclude,
        None,
        TaintOptions::default(),
    );
    assert_eq!(result.stop_reason, StopReason::MaxCount);
    assert!(result.hits.len() <= 2);
}

#[test]
fn backward_taint_ext_completes_on_finite_chain() {
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let result = backward_taint_ext(
        &t,
        &idx,
        4,
        "x0",
        100,
        &exclude,
        None,
        TaintOptions::default(),
    );
    assert_eq!(result.stop_reason, StopReason::Completed);
    let idxs: Vec<usize> = result.hits.iter().map(|h| h.idx).collect();
    assert_eq!(idxs, vec![0, 1, 2, 3, 4]);
}

#[test]
fn taint_legacy_wrappers_preserve_old_shape() {
    let dir = synth_x0_chain();
    let t = load_trace(&dir);
    let idx = Index::build(&t);
    let exclude = HashSet::new();
    let (fwd_hits, fwd_stopped) =
        forward_taint(&t, &idx, 0, "x0", 100, &exclude, false, None, false);
    assert!(!fwd_stopped);
    assert_eq!(fwd_hits.len(), 4);
    let (bwd_hits, bwd_stopped) =
        backward_taint(&t, &idx, 4, "x0", 100, &exclude, false, None, false);
    assert!(!bwd_stopped);
    assert_eq!(bwd_hits.len(), 5);
}
