//! Integration tests for the full LLIL → MLIL → HLIL decompiler pipeline.
//!
//! Tests the complete path from ARM64 instructions to C-like HLIL output,
//! including the trace-enhanced decompiler.

use tracemiku_core::decompiler::il_pipeline::{decompile_static, decompile_trace, TraceContext};
use tracemiku_core::hlil::lower::lower_mlil_to_hlil;
use tracemiku_core::llil::lift::lift_arm64;
use tracemiku_core::llil::pass_flag_elim::flag_elim_block;
use tracemiku_core::llil::pass_var_unify::unify_vars;
use tracemiku_core::llil::ssa::ssa_block;
use tracemiku_core::mlil::lower::lower_llil_to_mlil;

/// Helper: lift a single instruction and return LLIL expressions.
fn lift(pc: u64, inst: u32) -> Vec<tracemiku_core::llil::expr::LlilExpr> {
    lift_arm64(pc, inst)
}

// ============================================================================
// LLIL lifter tests — regression for arm64 instruction coverage
// ============================================================================

#[test]
fn llil_lifts_mov_add_sub_ret() {
    let mov = lift(0x1000, 0xd2800020); // mov x0, #1
    assert!(!mov.is_empty());
    assert_eq!(mov[0].short(), "x0 = 1");

    let add = lift(0x1004, 0x8b010000); // add x0, x0, x1
    assert!(!add.is_empty());
    assert!(add[0].short().contains("+"));

    let sub = lift(0x1008, 0xcb010000); // sub x0, x0, x1
    assert!(!sub.is_empty());

    let ret = lift(0x100c, 0xd65f03c0); // ret
    assert_eq!(ret[0].short(), "ret");
}

#[test]
fn llil_lifts_memory_ops() {
    let ldr = lift(0x1000, 0xf9400020); // ldr x0, [x1]
    assert!(!ldr.is_empty());
    assert!(ldr[0].short().contains("load"));

    let str_ = lift(0x1004, 0xf9000020); // str x0, [x1]
    assert!(!str_.is_empty());
    assert_eq!(str_[0].op, tracemiku_core::llil::expr::LlilOp::Store);
}

#[test]
fn llil_lifts_branches() {
    let b = lift(0x1000, 0x14000002); // b 0x100c
    assert_eq!(b[0].op, tracemiku_core::llil::expr::LlilOp::Goto);

    let beq = lift(0x1004, 0x54000040); // b.eq 0x100c
    assert_eq!(beq[0].op, tracemiku_core::llil::expr::LlilOp::If);

    let bl = lift(0x1008, 0x94000002); // bl ...
    assert_eq!(bl[0].op, tracemiku_core::llil::expr::LlilOp::Call);
}

#[test]
fn llil_lifts_bitwise_ops() {
    let and_ = lift(0x1000, 0x8a010000); // and x0, x0, x1
    assert!(and_[0].short().contains("&"));

    let orr = lift(0x1004, 0xaa010000); // orr x0, x0, x1
    assert!(orr[0].short().contains("|"));

    let eor = lift(0x1008, 0xca010000); // eor x0, x0, x1
    assert!(eor[0].short().contains("^"));
}

#[test]
fn llil_lifts_nzcv_flags_from_cmp() {
    let cmp = lift(0x1000, 0xeb01001f); // cmp x0, x1
    assert_eq!(cmp.len(), 4); // n, z, c, v flags
    for e in &cmp {
        assert_eq!(e.op, tracemiku_core::llil::expr::LlilOp::SetFlag);
    }
}

#[test]
fn llil_lifts_csel() {
    let csel = lift(0x1000, 0x9a821020); // csel x0, x1, x2, eq
    assert!(csel[0].short().contains("csel"));
}

// ============================================================================
// Flag elimination tests
// ============================================================================

#[test]
fn flag_elim_folds_cmp_into_if_eq() {
    let cmp = lift(0x1000, 0xeb01001f); // cmp x0, x1 -> n, z, c, v
                                        // b.eq 0x2000
    let beq = tracemiku_core::llil::expr::LlilExpr::new(
        tracemiku_core::llil::expr::LlilOp::If,
        1,
        vec![
            tracemiku_core::llil::expr::expr(tracemiku_core::llil::expr::flag_cond("eq")),
            tracemiku_core::llil::expr::LlilOperand::U64(0x2000),
            tracemiku_core::llil::expr::LlilOperand::U64(0x1008),
        ],
        0x1004,
    );
    let mut exprs = cmp;
    exprs.push(beq);
    let result = flag_elim_block(&exprs);
    assert!(!result.folded_pairs.is_empty());
    assert!(
        result.exprs[0]
            .extra
            .get("flag_elim")
            .map_or(false, |v| v.contains("nzcv")),
        "expected flag_elim nzcv annotation"
    );
}

// ============================================================================
// SSA tests
// ============================================================================

#[test]
fn ssa_tracks_versions_across_redefinitions() {
    let exprs = vec![
        lift(0x1000, 0xd2800020)[0].clone(), // mov x0, #1 (x0#1 = 1)
        lift(0x1004, 0x8b010000)[0].clone(), // add x0, x0, x1 (x0#2 = x0#1 + x1#0)
    ];
    let ssa = ssa_block(&exprs);
    assert!(ssa.exprs[0].short().contains("x0#1"));
    assert!(ssa.exprs[1].short().contains("x0#2"));
}

#[test]
fn ssa_call_kills_caller_saved_regs() {
    let bl = lift(0x1000, 0x94000002)[0].clone(); // bl ...
    let ssa = ssa_block(&[bl]);
    assert!(ssa.exit_versions.get("x0").is_some());
    assert!(ssa.exit_versions.get("lr").is_some());
}

// ============================================================================
// Variable naming tests
// ============================================================================

#[test]
fn var_unify_names_args() {
    let exprs = vec![
        lift(0x1000, 0xd2800020)[0].clone(), // mov x0, #1
    ];
    let ssa = ssa_block(&exprs);
    let names = unify_vars(&ssa.exprs);
    // x0#0 should be arg_0
    assert_eq!(names.get("x0#0").map(String::as_str), Some("arg_0"));
}

// ============================================================================
// LLIL → MLIL lowering tests
// ============================================================================

#[test]
fn llil_to_mlil_eliminates_flags() {
    // SetFlag ops should be filtered out by the MLIL lowering
    use tracemiku_core::llil::expr::*;
    let exprs = vec![
        set_flag("z", binary(LlilOp::CmpE, reg("x0#1"), konst(0)), 0x1000),
        set_reg("x1#1", konst(42), 0x1004),
    ];
    let ssa = ssa_block(&exprs);
    let names = unify_vars(&ssa.exprs);
    let (mlil, stats) = lower_llil_to_mlil(&ssa.exprs, &names);
    assert_eq!(stats.skipped_flags, 1);
    assert_eq!(stats.mlil_count, 1);
    assert_eq!(mlil[0].op, tracemiku_core::mlil::expr::MlilOp::SetVar);
}

#[test]
fn llil_to_mlil_converts_regs_to_vars() {
    let exprs = vec![
        lift(0x1000, 0xd28002a0)[0].clone(), // mov x0, #0x15
        lift(0x1004, 0xd65f03c0)[0].clone(), // ret
    ];
    let ssa = ssa_block(&exprs);
    let names = unify_vars(&ssa.exprs);
    let (mlil, stats) = lower_llil_to_mlil(&ssa.exprs, &names);
    assert!(stats.mlil_count >= 1);
    // MLIL should have SetVar (not SetReg)
    assert_eq!(mlil[0].op, tracemiku_core::mlil::expr::MlilOp::SetVar);
    // The return should be preserved
    assert!(mlil
        .iter()
        .any(|e| e.op == tracemiku_core::mlil::expr::MlilOp::Ret));
}

#[test]
fn llil_to_mlil_detects_struct_access() {
    use tracemiku_core::llil::expr::*;
    // Load from x1 + 0x10 (struct-like access)
    let addr = binary(LlilOp::Add, reg("x1#0"), konst(0x10));
    let load = LlilExpr::new(LlilOp::Load, 8, vec![expr(addr)], 0x1000);
    let set = set_reg("x0#1", load, 0x1000);
    let ssa = ssa_block(&[set]);
    let names = unify_vars(&ssa.exprs);
    let (mlil, _) = lower_llil_to_mlil(&ssa.exprs, &names);
    // LoadStruct is nested inside SetVar — check the rendered output
    let rendered = tracemiku_core::mlil::render::render_mlil_block(&mlil);
    // LoadStruct renders as *(type *)((base) + offset) — clean C dereference
    assert!(rendered.contains("*"), "expected deref in: {rendered}");
    assert!(
        rendered.contains("0x10"),
        "expected 0x10 offset in: {rendered}"
    );
}

// ============================================================================
// MLIL → HLIL lowering tests
// ============================================================================

#[test]
fn mlil_to_hlil_converts_setvar_to_assign() {
    use tracemiku_core::llil::pass_var_unify::VarNameMap;
    use tracemiku_core::mlil::expr::*;
    let mlil = vec![
        set_var("v0", konst(42), 0x1000),
        MlilExpr::new(MlilOp::Ret, 8, vec![], 0x1004),
    ];
    let names = VarNameMap::new();
    let (hlil, stats) = lower_mlil_to_hlil(&mlil, &names);
    assert!(stats.hlil_count >= 1);
    assert_eq!(hlil[0].op, tracemiku_core::hlil::expr::HlilOp::Assign);
}

#[test]
fn mlil_to_hlil_converts_load_to_deref() {
    use tracemiku_core::llil::pass_var_unify::VarNameMap;
    use tracemiku_core::mlil::expr::*;
    let mlil = vec![load(8, var("ptr"), 0x1000)];
    let names = VarNameMap::new();
    let (hlil, _) = lower_mlil_to_hlil(&mlil, &names);
    assert_eq!(hlil[0].op, tracemiku_core::hlil::expr::HlilOp::Deref);
}

#[test]
fn mlil_to_hlil_converts_store_to_assign_deref() {
    use tracemiku_core::llil::pass_var_unify::VarNameMap;
    use tracemiku_core::mlil::expr::*;
    let mlil = vec![store(4, var("ptr"), var("val"), 0x1000)];
    let names = VarNameMap::new();
    let (hlil, _) = lower_mlil_to_hlil(&mlil, &names);
    assert_eq!(hlil[0].op, tracemiku_core::hlil::expr::HlilOp::Assign);
}

// ============================================================================
// Full pipeline (LLIL → MLIL → HLIL) tests
// ============================================================================

#[test]
fn full_pipeline_simple_function() {
    // x0 = 1; x1 = 2; x0 = x0 + x1; ret
    // This is a minimal function: mov x0,#1; mov x1,#2; add x0,x0,x1; ret
    let output = decompile_static(&[
        (0x1000, 0xd2800020), // mov x0, #1
        (0x1004, 0xd2800041), // mov x1, #2
        (0x1008, 0x8b010000), // add x0, x0, x1
        (0x100c, 0xd65f03c0), // ret
    ]);
    assert!(output.llil_count >= 3);
    assert!(output.mlil_count >= 1);
    assert!(!output.hlil_text.is_empty());
    assert!(output.hlil_text.contains("return;"));
}

#[test]
fn full_pipeline_branch_and_flag_folding() {
    // cmp x0, #0; b.ne 0x1014; mov x0, #1; ret; (0x1014:) mov x0, #2; ret
    let output = decompile_static(&[
        (0x1000, 0xf100001f), // cmp x0, #0
        (0x1004, 0x54000081), // b.ne 0x1014
        (0x1008, 0xd2800020), // mov x0, #1
        (0x100c, 0xd65f03c0), // ret
        (0x1014, 0xd2800040), // mov x0, #2
        (0x1018, 0xd65f03c0), // ret
    ]);
    // Should produce LLIL with flag folding
    assert!(!output.llil_ssa_text.is_empty());
    // MLIL should have if-like output
    assert!(!output.mlil_text.is_empty());
    // HLIL should have coverage
    assert!(output.hlil_count > 0);
}

#[test]
fn full_pipeline_load_store() {
    // ldr x0, [x1]; add x0, x0, #1; str x0, [x1]; ret
    let output = decompile_static(&[
        (0x1000, 0xf9400020), // ldr x0, [x1]
        (0x1004, 0x91000400), // add x0, x0, #1
        (0x1008, 0xf9000020), // str x0, [x1]
        (0x100c, 0xd65f03c0), // ret
    ]);
    assert!(output.llil_count >= 3);
    // MLIL should have non-trivial output
    assert!(!output.mlil_text.is_empty());
    // HLIL should convert load to deref
    assert!(!output.hlil_text.is_empty());
    assert!(output.hlil_count > 0);
}

#[test]
fn full_pipeline_multi_instruction_block() {
    // A realistic basic block with 10+ instructions
    let output = decompile_static(&[
        (0x1000, 0xd2800000), // mov x0, #0
        (0x1004, 0xd2800021), // mov x1, #1
        (0x1008, 0xd2800042), // mov x2, #2
        (0x100c, 0x8b010042), // add x2, x2, x1
        (0x1010, 0x8b020000), // add x0, x0, x2
        (0x1014, 0xd1000401), // sub x1, x0, #1
        (0x1018, 0x8b010042), // add x2, x2, x1
        (0x101c, 0xf9000002), // str x2, [x0]
        (0x1020, 0x8b010000), // add x0, x0, x1
        (0x1024, 0xd65f03c0), // ret
    ]);
    // Every instruction in this set is supported
    assert!(
        output.llil_coverage > 0.9,
        "low coverage: {:.2}",
        output.llil_coverage
    );
    assert!(output.mlil_count > 0);
    assert!(output.hlil_count > 0);
}

#[test]
fn full_pipeline_with_trace_context() {
    let insns = vec![
        (0x1000u64, 0xd2800020u32), // mov x0, #1
        (0x1004u64, 0xd65f03c0u32), // ret
    ];
    let ctx = TraceContext {
        regs_before: [("x0".to_string(), 0i64)].into_iter().collect(),
        regs_after: [("x0".to_string(), 1i64)].into_iter().collect(),
        exec_count: 1,
        ..Default::default()
    };
    let output = decompile_trace(&insns, &[ctx], "traced_fn");
    assert_eq!(output.function_name, "traced_fn");
    assert_eq!(output.total_exec_count, 1);
    assert_eq!(output.unique_pcs, 2);
    // Trace contexts should be preserved
    assert_eq!(output.trace_contexts.len(), 1);
    assert_eq!(output.trace_contexts[0].exec_count, 1);
}

#[test]
fn decompile_trace_surfaces_observed_runtime_values() {
    // ldr x0, [x1]; str x0, [x1]; ret
    // The ldr survives DCE because str consumes x0, so its rendered LLIL line
    // is a stable target for the observed-value annotation.
    let insns = vec![
        (0x1000u64, 0xf9400020u32), // ldr x0, [x1]
        (0x1004u64, 0xf9000020u32), // str x0, [x1]
        (0x1008u64, 0xd65f03c0u32), // ret
    ];

    // Context positionally aligned to insns: the ldr loaded 0x2a into x0.
    let mut ldr_ctx = TraceContext {
        exec_count: 1,
        ..Default::default()
    };
    ldr_ctx.regs_before.insert("x0".to_string(), 0);
    ldr_ctx.regs_before.insert("x1".to_string(), 0x4000);
    ldr_ctx.regs_after.insert("x0".to_string(), 0x2a); // loaded value
    ldr_ctx.regs_after.insert("x1".to_string(), 0x4000); // unchanged
    let contexts = vec![
        ldr_ctx,
        TraceContext {
            exec_count: 1,
            ..Default::default()
        },
        TraceContext {
            exec_count: 1,
            ..Default::default()
        },
    ];

    let output = decompile_trace(&insns, &contexts, "f");

    // Structured: the value the ldr produced (x0 changed 0 -> 0x2a) is surfaced,
    // and the unchanged x1 is NOT reported.
    assert!(
        output
            .observed_annotations
            .iter()
            .any(|a| a.pc == 0x1000 && a.text.contains("x0=0x2a")),
        "missing structured observed annotation; got {:?}",
        output.observed_annotations
    );
    assert!(
        !output
            .observed_annotations
            .iter()
            .any(|a| a.pc == 0x1000 && a.text.contains("x1")),
        "unchanged register x1 should not be reported as observed: {:?}",
        output.observed_annotations
    );

    // Rendered into the LLIL text the user/UI sees.
    assert!(
        output.llil_ssa_text.contains("observed: x0=0x2a"),
        "observed value not injected into LLIL text:\n{}",
        output.llil_ssa_text
    );
}

#[test]
fn decompile_trace_prunes_untaken_branch_from_context() {
    let insns = vec![
        (0x1000u64, 0x34000040u32), // cbz w0, 0x1008
        (0x1004u64, 0xd2800021u32), // mov x1, #1 (fallthrough path)
        (0x1008u64, 0xd2800042u32), // mov x2, #2 (branch target)
        (0x100cu64, 0xd65f03c0u32), // ret
    ];
    let contexts = vec![
        TraceContext {
            exec_count: 1,
            branch_taken: Some(false),
            ..Default::default()
        },
        TraceContext {
            exec_count: 1,
            ..Default::default()
        },
        TraceContext {
            exec_count: 0,
            ..Default::default()
        },
        TraceContext {
            exec_count: 1,
            ..Default::default()
        },
    ];

    let output = decompile_trace(&insns, &contexts, "path_specialized");

    assert!(
        output.llil_ssa_text.contains("trace_pruned_branch"),
        "expected pruning annotation in LLIL:\n{}",
        output.llil_ssa_text
    );
    assert!(
        output.llil_ssa_text.contains("goto loc_1004"),
        "expected fallthrough target to be kept:\n{}",
        output.llil_ssa_text
    );
    assert!(
        !output.llil_ssa_text.contains("else goto loc_1004"),
        "conditional branch should be specialized:\n{}",
        output.llil_ssa_text
    );
}

#[test]
fn decompile_trace_resolves_observed_indirect_jump() {
    let insns = vec![
        (0x1000u64, 0xd61f0100u32), // br x8
        (0x2000u64, 0xd65f03c0u32), // ret
    ];
    let contexts = vec![
        TraceContext {
            exec_count: 1,
            next_pc: Some(0x2000),
            ..Default::default()
        },
        TraceContext {
            exec_count: 1,
            ..Default::default()
        },
    ];

    let output = decompile_trace(&insns, &contexts, "resolved_br");
    assert!(
        output.llil_ssa_text.contains("trace_resolved_jump"),
        "expected resolved jump annotation:\n{}",
        output.llil_ssa_text
    );
    assert!(
        output.llil_ssa_text.contains("goto loc_2000"),
        "expected br to become observed goto:\n{}",
        output.llil_ssa_text
    );
}

#[test]
fn trace_decompile_preserves_all_layers() {
    let insns = vec![
        (0x1000, 0xd2800020), // mov x0, #1
        (0x1004, 0xd65f03c0), // ret
    ];
    let output = decompile_static(&insns);
    // All three layers should have non-empty text
    assert!(!output.llil_ssa_text.is_empty(), "LLIL SSA text is empty");
    assert!(!output.mlil_text.is_empty(), "MLIL text is empty");
    assert!(!output.hlil_text.is_empty(), "HLIL text is empty");
    // Layer counts should be non-zero
    assert!(output.llil_count > 0);
    assert!(output.mlil_count > 0);
    assert!(output.hlil_count > 0);
}

#[test]
fn coverage_high_for_common_instructions() {
    // A representative set of commonly-used ARM64 instructions
    let common_insns = vec![
        (0x1000, 0xd2800020), // mov x0, #1
        (0x1004, 0x8b010000), // add x0, x0, x1
        (0x1008, 0xcb010000), // sub x0, x0, x1
        (0x100c, 0x8a010000), // and x0, x0, x1
        (0x1010, 0xaa010000), // orr x0, x0, x1
        (0x1014, 0xca010000), // eor x0, x0, x1
        (0x1018, 0xeb01001f), // cmp x0, x1
        (0x101c, 0xf9400020), // ldr x0, [x1]
        (0x1020, 0xf9000020), // str x0, [x1]
        (0x1024, 0xd65f03c0), // ret
    ];
    let output = decompile_static(&common_insns);
    assert!(
        output.llil_coverage > 0.8,
        "coverage too low: {:.2}",
        output.llil_coverage
    );
}

#[test]
fn empty_input_handled_gracefully() {
    let output = decompile_static(&[]);
    assert_eq!(output.insn_count, 0);
    assert_eq!(output.llil_count, 0);
    assert_eq!(output.mlil_count, 0);
    assert_eq!(output.hlil_count, 0);
    assert!(output.llil_ssa_text.is_empty());
    assert!(output.mlil_text.is_empty());
    assert!(output.hlil_text.is_empty());
}

#[test]
fn struct_access_lowers_through_all_layers() {
    use tracemiku_core::llil::expr::*;
    // Simulate a struct field access: load from x0 + 0x20
    let addr = binary(LlilOp::Add, reg("x0#0"), konst(0x20));
    let load = LlilExpr::new(LlilOp::Load, 4, vec![expr(addr)], 0x1000);
    let set = set_reg("x1#1", load, 0x1000);
    let ssa = ssa_block(&[set]);
    let names = unify_vars(&ssa.exprs);
    // LLIL → MLIL should create LoadStruct (nested inside SetVar)
    let (mlil, _) = lower_llil_to_mlil(&ssa.exprs, &names);
    let mlil_text = tracemiku_core::mlil::render::render_mlil_block(&mlil);
    assert!(
        mlil_text.contains("*"),
        "expected deref in MLIL text: {mlil_text}"
    );
    // MLIL → HLIL should create DerefField
    let (hlil, _) = lower_mlil_to_hlil(&mlil, &names);
    let hlil_text = tracemiku_core::hlil::render::render_hlil(&hlil);
    assert!(
        hlil_text.contains("0x20"),
        "expected 0x20 offset in HLIL text: {hlil_text}"
    );
    // HLIL should have either DerefField or Deref
    assert!(
        hlil_text.contains("*"),
        "expected deref * in HLIL text: {hlil_text}"
    );
}
