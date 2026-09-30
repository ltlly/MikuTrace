use tracemiku_core::trace::{evidence::branch_taken, Record, Trace};
use tracemiku_core::{cfg::resolve_indirect_branch_targets, memshadow::MemShadow};

fn fixture(records: &[Record], meta: &str) -> (tempfile::TempDir, Trace) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("trace.bin"), bytemuck::cast_slice(records)).unwrap();
    std::fs::write(tmp.path().join("meta.json"), meta).unwrap();
    let trace = Trace::load(tmp.path()).unwrap();
    (tmp, trace)
}
fn rec(pc: u64, inst: u32, x0: u64, x1: u64) -> Record {
    let mut r = Record::zero(pc);
    r.inst = inst;
    r.regs[0] = x0;
    r.regs[1] = x1;
    r
}
fn external(path: &std::path::Path, idx: u64, addr: u64, value: u8) {
    let mut data = Vec::new();
    data.extend(idx.to_le_bytes());
    data.extend(addr.to_le_bytes());
    data.push(value);
    std::fs::write(path.join("external_writes.bin"), data).unwrap();
}
#[test]
fn cache_tracks_external_creation_replacement_and_removal() {
    let (tmp, trace) = fixture(
        &[
            rec(0x1000, 0xf9000020, 65, 0x7000),
            rec(0x1004, 0xd503201f, 65, 0x7000),
        ],
        "{}",
    );
    assert_eq!(
        MemShadow::load_or_build(&trace).byte_at(0x7000, 1).0,
        Some(65)
    );
    external(tmp.path(), 1, 0x7000, 66);
    assert_eq!(
        MemShadow::load_or_build(&trace).byte_at(0x7000, 1),
        (Some(66), "x", Some(1))
    );
    external(tmp.path(), 1, 0x7000, 67);
    assert_eq!(
        MemShadow::load_or_build(&trace).byte_at(0x7000, 1).0,
        Some(67)
    );
    std::fs::remove_file(tmp.path().join("external_writes.bin")).unwrap();
    assert_eq!(
        MemShadow::load_or_build(&trace).byte_at(0x7000, 1).0,
        Some(65)
    );
}
#[test]
fn cache_tracks_same_size_trace_replacement() {
    let (tmp, trace) = fixture(&[rec(0x1000, 0xf9000020, 65, 0x7000)], "{}");
    MemShadow::load_or_build(&trace);
    drop(trace);
    std::fs::write(
        tmp.path().join("trace.bin"),
        bytemuck::bytes_of(&rec(0x1000, 0xf9000020, 66, 0x7000)),
    )
    .unwrap();
    assert_eq!(
        MemShadow::load_or_build(&Trace::load(tmp.path()).unwrap())
            .byte_at(0x7000, 0)
            .0,
        Some(66)
    );
}
#[test]
fn load_gap_and_metadata_loss_never_become_memory_facts() {
    for (next_pc, meta) in [
        (0x1010, "{}"),
        (0x1004, r#"{"dropped":1}"#),
        (0x1004, "broken metadata"),
    ] {
        let (_tmp, trace) = fixture(
            &[
                rec(0x1000, 0xf9400020, 0, 0x7000),
                rec(next_pc, 0xd503201f, 99, 0x7000),
            ],
            meta,
        );
        assert!(MemShadow::build_from_trace(&trace).reads.is_empty());
    }
}
#[test]
fn cache_invalidates_when_capture_loss_metadata_changes() {
    let (tmp, trace) = fixture(
        &[
            rec(0x1000, 0xf9400020, 0, 0x7000),
            rec(0x1004, 0xd503201f, 99, 0x7000),
        ],
        "{}",
    );
    assert_eq!(MemShadow::load_or_build(&trace).reads.len(), 1);
    std::fs::write(tmp.path().join("meta.json"), r#"{"dropped":1}"#).unwrap();
    let reloaded = Trace::load(tmp.path()).unwrap();
    assert!(MemShadow::load_or_build(&reloaded).reads.is_empty());
}
#[test]
fn indirect_call_uses_operand_even_if_callee_is_excluded_or_at_tail() {
    let mut call = rec(0x1000, 0xd63f0100, 0, 0);
    call.regs[8] = 0x5000;
    for records in [vec![call, rec(0x1004, 0xd503201f, 0, 0)], vec![call]] {
        let (_tmp, trace) = fixture(&records, "{}");
        assert_eq!(
            resolve_indirect_branch_targets(&trace)[&0x1000],
            vec![(0x5000, 1)]
        );
    }
}
#[test]
fn branch_outcome_comes_from_flags_including_zero_distance_branch() {
    let mut r = rec(0x1000, 0x54000020, 0, 0); // b.eq to PC+4
    r.nzcv = 1 << 30;
    assert_eq!(branch_taken(&r), Some(true));
    r.nzcv = 0;
    assert_eq!(branch_taken(&r), Some(false));
    r.inst = 0x36000000;
    assert_eq!(branch_taken(&r), Some(true)); // tbz x0,#0
}
#[test]
fn failed_or_unobservable_exclusive_store_does_not_invent_a_write() {
    let mut store = rec(0x1000, 0xc8007c22, 0, 0x7000); // stxr w0,x2,[x1]
    store.regs[2] = 65;
    for (pc, status, expected_writes) in [(0x1004, 1, 0), (0x1010, 0, 0), (0x1004, 0, 1)] {
        let mut post = store;
        post.pc = pc;
        post.inst = 0xd503201f;
        post.regs[0] = status;
        let (_tmp, trace) = fixture(&[store, post], "{}");
        assert_eq!(
            MemShadow::build_from_trace(&trace).writes.len(),
            expected_writes
        );
    }
}
