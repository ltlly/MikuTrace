use tracemiku_core::memshadow::{MemShadow, MemSnapshot, SnapRegion};
use tracemiku_core::replay::{replay_trace, ReplayReason, MAX_REPLAY_RECORDS};
use tracemiku_core::trace::{Record, Trace};
fn record(pc: u64, inst: u32, x0: u64, x1: u64) -> Record {
    let mut r = Record::zero(pc);
    r.inst = inst;
    r.regs[0] = x0;
    r.regs[1] = x1;
    r
}
fn fixture(records: &[Record], meta: &str) -> (tempfile::TempDir, Trace, MemShadow) {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("trace.bin"), bytemuck::cast_slice(records)).unwrap();
    std::fs::write(tmp.path().join("meta.json"), meta).unwrap();
    let trace = Trace::load(tmp.path()).unwrap();
    let mem = MemShadow::build_from_trace(&trace);
    (tmp, trace, mem)
}
#[test]
fn integer_arithmetic_matches_independent_architectural_states() {
    // Includes modular overflow; expectations come from architectural states.
    for x in [0, 1, 0x7fff_ffff_ffff_ffff, u64::MAX] {
        let states = [
            record(0x1000, 0x91000400, x, 0),
            record(0x1004, 0xcb000001, x.wrapping_add(1), 0),
            record(0x1008, 0xd503201f, x.wrapping_add(1), 0),
        ]; // add x0,x0,#1; sub x1,x0,x0
        let (_tmp, trace, mem) = fixture(&states, "{}");
        let out = replay_trace(&trace, &mem, 0, 2).unwrap();
        assert_eq!(out.status, "matched", "{:?}", out.stop);
        assert_eq!(out.checked, 2);
        assert_eq!(out.register_comparisons, 66);
    }
}
#[test]
fn stops_at_first_incorrect_result_without_using_it_as_new_evidence() {
    let (_tmp, trace, mem) = fixture(
        &[
            record(0x1000, 0xd2800020, 0, 0),
            record(0x1004, 0x91000400, 1, 0),
            record(0x1008, 0xd503201f, 99, 0),
        ],
        "{}",
    );
    let out = replay_trace(&trace, &mem, 0, 3).unwrap();
    assert_eq!(out.status, "diverged");
    assert_eq!(out.checked, 1);
    let stop = out.stop.unwrap();
    assert_eq!(stop.idx, 1);
    assert_eq!(stop.reason, ReplayReason::RegisterMismatch);
    assert_eq!(stop.expected, Some(2));
    assert_eq!(stop.observed, Some(99));
}
#[test]
fn a_load_cannot_validate_itself_from_its_post_state() {
    let (_tmp, trace, mut mem) = fixture(
        &[
            record(0x1000, 0xf9400020, 0, 0x7000),
            record(0x1004, 0xd503201f, 65, 0x7000),
        ],
        "{}",
    );
    assert_eq!(mem.reads.len(), 1); // shadow inferred from the captured x0
    let out = replay_trace(&trace, &mem, 0, 1).unwrap();
    assert_eq!(out.checked, 0);
    let stop = out.stop.unwrap();
    assert_eq!(stop.reason, ReplayReason::UnknownMemory);
    assert_eq!(stop.next_capture.addr, Some(0x7000));
    assert_eq!(stop.next_capture.size, Some(8));
    mem.snapshot = Some(MemSnapshot {
        regions: vec![SnapRegion {
            base: 0x7000,
            perms: 1,
            data: 65u64.to_le_bytes().to_vec(),
        }],
    });
    let out = replay_trace(&trace, &mem, 0, 1).unwrap();
    assert_eq!(out.status, "matched");
    assert_eq!(out.independent_memory_bytes, 8);
}
#[test]
fn preceding_store_can_supply_independent_load_input() {
    let states = [
        record(0x1000, 0xf9000020, 65, 0x7000),
        record(0x1004, 0xf9400020, 65, 0x7000),
        record(0x1008, 0xd503201f, 65, 0x7000),
    ];
    let (_tmp, trace, mem) = fixture(&states, "{}");
    let out = replay_trace(&trace, &mem, 0, 2).unwrap();
    assert_eq!(out.status, "matched");
    assert_eq!(out.independent_memory_bytes, 8);
}
#[test]
fn incomplete_evidence_has_explicit_stop_reasons() {
    for (inst, next_pc, meta, reason) in [
        (0xd4000001, 0x1004, "{}", ReplayReason::SyscallBoundary),
        (0x4e228420, 0x1004, "{}", ReplayReason::SimdStateUnavailable),
        (0xd503201f, 0x1010, "{}", ReplayReason::TraceGap),
        (
            0xd503201f,
            0x1004,
            r#"{"dropped":1}"#,
            ReplayReason::TraceGap,
        ),
        (0xd63f0100, 0x1004, "{}", ReplayReason::ExcludedCall),
        (
            0x00000000,
            0x1004,
            "{}",
            ReplayReason::UnsupportedInstruction,
        ),
    ] {
        let (_tmp, trace, mem) = fixture(
            &[
                record(0x1000, inst, 0, 0),
                record(next_pc, 0xd503201f, 0, 0),
            ],
            meta,
        );
        let out = replay_trace(&trace, &mem, 0, 1).unwrap();
        assert_eq!(out.status, "stopped");
        assert_eq!(out.checked, 0);
        assert_eq!(out.stop.unwrap().reason, reason, "inst={inst:x}");
    }
}
#[test]
fn branch_and_flag_oracles_check_control_flow_and_unmodified_registers() {
    let mut before = record(0x1000, 0x54000040, 0, 0);
    before.nzcv = 1 << 30;
    let mut after = record(0x1008, 0xd503201f, 0, 0);
    after.nzcv = before.nzcv;
    let (_tmp, trace, mem) = fixture(&[before, after], "{}");
    assert_eq!(replay_trace(&trace, &mem, 0, 1).unwrap().status, "matched");
}
#[test]
fn range_limits_and_missing_post_state_are_not_success() {
    let mut records: Vec<_> = (0..MAX_REPLAY_RECORDS + 2)
        .map(|i| record(0x1000 + i as u64 * 4, 0xd503201f, 0, 0))
        .collect();
    let (_tmp, trace, mem) = fixture(&records, "{}");
    let out = replay_trace(&trace, &mem, 0, usize::MAX).unwrap();
    assert_eq!(out.effective_count, MAX_REPLAY_RECORDS);
    assert!(out.truncated);
    assert_eq!(out.stop.unwrap().reason, ReplayReason::LimitReached);
    records.truncate(1);
    let (_tmp, trace, mem) = fixture(&records, "{}");
    assert_eq!(
        replay_trace(&trace, &mem, 0, 1)
            .unwrap()
            .stop
            .unwrap()
            .reason,
        ReplayReason::MissingPostState
    );
    assert!(replay_trace(&trace, &mem, 1, 1).is_err());
    assert!(replay_trace(&trace, &mem, 0, 0).is_err());
}

#[test]
fn arithmetic_width_and_nzcv_are_checked_against_architectural_examples() {
    // adds/subs x0/w0,x0,#1: zero, carry/borrow and signed overflow boundaries.
    for (inst, before_x0, after_x0, nzcv) in [
        (0xb1000400, u64::MAX, 0, 0x60000000),
        (
            0xb1000400,
            0x7fff_ffff_ffff_ffff,
            0x8000_0000_0000_0000,
            0x90000000,
        ),
        (0xf1000400, 0, u64::MAX, 0x80000000),
        (
            0xf1000400,
            0x8000_0000_0000_0000,
            0x7fff_ffff_ffff_ffff,
            0x30000000,
        ),
        (0x31000400, u64::MAX, 0, 0x60000000),
        (0x31000400, 0x7fff_ffff, 0x8000_0000, 0x90000000),
        (0x51000400, 0, 0xffff_ffff, 0), // sub w0,w0,#1 preserves flags
    ] {
        let before = record(0x1000, inst, before_x0, 0);
        let mut after = record(0x1004, 0xd503201f, after_x0, 0);
        after.nzcv = nzcv;
        let (_tmp, trace, mem) = fixture(&[before, after], "{}");
        let out = replay_trace(&trace, &mem, 0, 1).unwrap();
        assert_eq!(out.status, "matched", "inst={inst:x}: {:?}", out.stop);
        // A wrong flag alone must also cause divergence.
        after.nzcv ^= 1 << 30;
        let (_tmp, trace, mem) = fixture(&[before, after], "{}");
        let stop = replay_trace(&trace, &mem, 0, 1).unwrap().stop.unwrap();
        assert_eq!(stop.reason, ReplayReason::RegisterMismatch);
        assert_eq!(stop.register.as_deref(), Some("nzcv"));
    }
}

#[test]
fn register_aliases_width_and_stack_pointer_are_architectural() {
    for (inst, x0, x1, expected_x0) in [
        (0x2a0103e0, u64::MAX, 0x1234_5678_abcd_ef01, 0xabcd_ef01), // mov w0,w1
        (0x12800000, 0, 0, 0xffff_ffff),                            // movn w0,#0
        (0xf2a24680, 0xffff_ffff_ffff_ffff, 0, 0xffff_ffff_1234_ffff), // movk x0,#0x1234,lsl#16
        (0xaa0107e0, 0, 3, 6),                                      // orr x0,xzr,x1,lsl#1
    ] {
        let (_tmp, trace, mem) = fixture(
            &[
                record(0x1000, inst, x0, x1),
                record(0x1004, 0xd503201f, expected_x0, x1),
            ],
            "{}",
        );
        let out = replay_trace(&trace, &mem, 0, 1).unwrap();
        assert_eq!(out.status, "matched", "inst={inst:x}: {:?}", out.stop);
    }
    let mut before = record(0x1000, 0xd10043ff, 7, 0); // sub sp,sp,#16
    before.sp = 0x8000;
    let mut after = before;
    after.pc += 4;
    after.sp = 0x7ff0;
    let (_tmp, trace, mem) = fixture(&[before, after], "{}");
    assert_eq!(replay_trace(&trace, &mem, 0, 1).unwrap().status, "matched");
}

#[test]
fn unmodelled_control_flow_requests_semantics_instead_of_more_capture() {
    for inst in [0xd65f0bff, 0xd69f03e0, 0xd4200000] {
        // retaa, eret, brk
        let (_tmp, trace, mem) = fixture(
            &[record(0x1000, inst, 0, 0), record(0x1004, 0xd503201f, 0, 0)],
            "{}",
        );
        let stop = replay_trace(&trace, &mem, 0, 1).unwrap().stop.unwrap();
        assert_eq!(stop.reason, ReplayReason::UnsupportedInstruction);
        assert_eq!(stop.next_capture.action, "inspect_instruction_semantics");
    }
}
