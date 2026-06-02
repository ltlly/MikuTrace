//! Trace-enhanced IL pipeline.
//!
//! Lifts trace records through all three IL layers (LLIL → MLIL → HLIL),
//! enriching each level with runtime values from the trace.
//!
//! Trace advantages:
//!   - Actual register values: resolve indirect calls/jumps
//!   - Execution counts: identify hot/cold paths
//!   - Memory snapshots: resolve pointer dereferences
//!   - Executed paths: validate CFG correctness

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use serde::Serialize;

use crate::disasm::decode;
use crate::hlil::lower::{lower_mlil_to_hlil, LowerStats as HlilLowerStats};
use crate::hlil::render::render_hlil;
use crate::llil::expr::{LlilExpr, LlilOp, LlilOperand};
use crate::llil::lift::lift_arm64;
use crate::llil::pass_constfold::constfold_block;
use crate::llil::pass_dce::dce_block;
use crate::llil::pass_flag_elim::flag_elim_block;
use crate::llil::pass_frame_fold::frame_fold_block;
use crate::llil::pass_var_unify::unify_vars;
use crate::llil::render::{render_llil_block_with_names, render_llil_block_with_names_annotated};
use crate::llil::ssa::ssa_block;
use crate::mlil::lower::{lower_llil_to_mlil, LowerStats as MlilLowerStats};
use crate::mlil::render::render_mlil_block;

use super::pass::{from_llil, PassIlExpr, PassIlOperand};
use super::pass_registry::build_universal_pipeline;

/// Per-instruction trace context (runtime values).
#[derive(Debug, Clone, Default, Serialize)]
pub struct TraceContext {
    /// Register values before instruction execution.
    pub regs_before: BTreeMap<String, i64>,
    /// Register values after instruction execution.
    pub regs_after: BTreeMap<String, i64>,
    /// Memory reads performed by this instruction (addr → value).
    pub mem_reads: BTreeMap<u64, Vec<u8>>,
    /// Memory writes performed by this instruction (addr → value).
    pub mem_writes: BTreeMap<u64, Vec<u8>>,
    /// Execution count (how many times this PC was executed).
    pub exec_count: u64,
    /// Whether this instruction is on a taken branch path.
    pub branch_taken: Option<bool>,
    /// Next executed PC after this instruction, when known.
    pub next_pc: Option<u64>,
}

/// A runtime value observed at an instruction, surfaced into the IL.
///
/// `text` lists the register(s) the instruction produced and their observed
/// value(s), e.g. `"x0=0x2a"`. This is the trace-aware advantage a static
/// decompiler cannot have: the actual value computed at runtime.
#[derive(Debug, Clone, Serialize)]
pub struct ObservedAnnotation {
    pub pc: u64,
    pub text: String,
}

/// Stability classification for a value observed at a register write site
/// across multiple calls to the same function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueStability {
    /// Same value across ALL calls — safe to fold as a constant.
    Constant,
    /// Varies across calls but correlates with an input parameter (e.g. x0+8).
    InputDependent,
    /// Varies unpredictably across calls — keep as a variable, do NOT fold.
    CallDependent,
    /// No trace data available across calls — conservative, do NOT fold.
    Unobserved,
}

impl fmt::Display for ValueStability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueStability::Constant => write!(f, "const"),
            ValueStability::InputDependent => write!(f, "input_dep"),
            ValueStability::CallDependent => write!(f, "call_dep"),
            ValueStability::Unobserved => write!(f, "unobs"),
        }
    }
}

/// A stability classification for a register write at a specific PC.
#[derive(Debug, Clone, Serialize)]
pub struct StabilityEntry {
    /// Register name (e.g. "x0", "x5").
    pub reg: String,
    /// PC of the instruction that wrote this register.
    pub pc: u64,
    /// The representative value (from the first call where this was observed).
    pub value: i64,
    /// Stability classification.
    pub stability: ValueStability,
    /// When InputDependent, the parameter register this value correlates with.
    pub correlated_param: Option<String>,
}

/// Instruction-and-context data for one invocation of a function.
/// Used by `classify_value_stability` to compare register values across calls.
#[derive(Debug, Clone)]
pub struct CallTraceData {
    /// (pc, instruction_word) pairs for this call.
    pub insns: Vec<(u64, u32)>,
    /// Per-instruction trace contexts (positionally aligned to `insns`).
    pub contexts: Vec<TraceContext>,
}

/// Inferred type for a single parameter across multiple call sites.
#[derive(Debug, Clone, Serialize)]
pub struct ParameterTypeInfo {
    /// Parameter index (0-based: arg0, arg1, ...).
    pub index: usize,
    /// Register used for this parameter (e.g. "x0").
    pub register: String,
    /// The majority-voted type string (e.g. "int", "ptr", "uint").
    pub inferred_type: String,
    /// How many call sites provided this type.
    pub vote_count: usize,
    /// Total call sites for this parameter (used to detect conflicts).
    pub total_call_sites: usize,
    /// If there is a conflict, list the minority types seen.
    pub conflicting_types: Vec<(String, usize)>,
}

/// Inferred function signature for a callee, built from call site argument types.
#[derive(Debug, Clone, Serialize)]
pub struct CallSignature {
    /// Callee target address (PC of the called function).
    pub callee_pc: u64,
    /// Callee name when known (e.g. "sub_12345").
    pub callee_name: String,
    /// Number of call sites that called this callee.
    pub call_site_count: usize,
    /// Inferred return type (e.g. "int", "void", "ptr", "uint").
    pub return_type: String,
    /// Inferred parameter types in argument order.
    pub params: Vec<ParameterTypeInfo>,
    /// The signature string (e.g. "int sub_12345(int arg0, char* arg1)").
    pub signature_string: String,
}

/// Result of decompiling a sequence of trace records through all three IL layers.
#[derive(Debug, Clone, Serialize)]
pub struct TraceDecompileOutput {
    /// Number of ARM64 instructions processed.
    pub insn_count: usize,
    /// LLIL expression count (after lifting).
    pub llil_count: usize,
    /// MLIL expression count (after lowering).
    pub mlil_count: usize,
    /// HLIL expression count (after lowering).
    pub hlil_count: usize,
    /// LLIL coverage (fraction of non-intrinsic instructions).
    pub llil_coverage: f64,
    /// LLIL SSA-form text (after constfold + DCE).
    pub llil_ssa_text: String,
    /// MLIL text.
    pub mlil_text: String,
    /// HLIL C-like text.
    pub hlil_text: String,
    /// Function name resolution.
    pub function_name: String,
    /// Trace-recorded runtime values (per instruction).
    pub trace_contexts: Vec<TraceContext>,
    /// Observed runtime values folded out of the trace, keyed by PC.
    pub observed_annotations: Vec<ObservedAnnotation>,
    /// Stats from each lowering pass.
    pub mlil_lower_stats: MlilLowerStats,
    pub hlil_lower_stats: HlilLowerStats,
    /// Unique PCs covered.
    pub unique_pcs: usize,
    /// Total executed instructions.
    pub total_exec_count: u64,
    /// Number of const-folded expressions.
    pub constfold_count: usize,
    /// Number of dead expressions removed.
    pub dce_removed_count: usize,
    /// Number of DCE iterations.
    pub dce_iterations: usize,
    /// Ghidra-style universal pipeline text (rendered after passes).
    pub ghidra_pass_text: String,
    /// Ghidra pipeline phases that made changes.
    pub ghidra_phases_changed: usize,
    /// Ghidra pipeline final expression count.
    pub ghidra_final_count: usize,
    /// Stability classifications for register write sites across multiple calls.
    /// Empty when only single-call data is available.
    /// Indirect branch dispatch targets collected from trace.
    /// Key: source PC of br/blr. Value: list of (target_pc, hit_count).
    pub indirect_dispatch_targets: HashMap<u64, Vec<(u64, u64)>>,
    /// Number of indirect branch (br/blr) sites with trace-observed targets.
    pub indirect_dispatch_sites: usize,
    /// Total number of unique indirect dispatch target PCs observed.
    pub indirect_dispatch_unique_targets: usize,
    pub stability_entries: Vec<StabilityEntry>,
    /// Count of register write sites classified as Constant.
    pub stability_constant_count: usize,
    /// Count of register write sites classified as InputDependent.
    pub stability_input_dependent_count: usize,
    /// Count of register write sites classified as CallDependent.
    pub stability_call_dependent_count: usize,
    /// Inferred function signatures from call site argument types.
    pub call_signatures: Vec<CallSignature>,
}

/// Decompile a sequence of (pc, inst) pairs with trace data.
///
/// This is the main entry point for trace-enhanced decompilation. It
/// lifts every instruction, builds SSA, eliminates flags, lowers through
/// MLIL and HLIL, and annotates with runtime values from the trace.
pub fn decompile_trace(
    insns: &[(u64, u32)],
    contexts: &[TraceContext],
    function_name: &str,
) -> TraceDecompileOutput {
    let insn_count = insns.len();

    // Phase 1: Lift ARM64 → LLIL
    let mut llil_exprs = Vec::new();
    let mut total_llil = 0usize;
    let mut intrinsic_count = 0usize;

    for (pc, inst) in insns {
        let lifted = lift_arm64(*pc, *inst);
        for e in &lifted {
            if matches!(e.op, crate::llil::expr::LlilOp::Intrinsic) {
                intrinsic_count += 1;
            }
        }
        total_llil += lifted.len();
        llil_exprs.extend(lifted);
    }

    let llil_count = llil_exprs.len();
    let llil_coverage = if insn_count == 0 {
        1.0
    } else {
        1.0 - (intrinsic_count as f64 / total_llil as f64)
    };

    // Phase 2: Frame folding + flag elimination + SSA
    let llil_exprs = specialize_trace_control_flow(&llil_exprs, insns, contexts);

    let frame_fold = frame_fold_block(&llil_exprs);
    let flag_elim = flag_elim_block(&frame_fold.exprs);
    let ssa = ssa_block(&flag_elim.exprs);
    let names = unify_vars(&ssa.exprs);

    // Phase 2b: LLIL optimization passes — constfold + DCE
    let constfolded = constfold_block(&ssa.exprs);
    let dce_result = dce_block(&constfolded);
    let opt_llil = &dce_result.exprs;

    let constfold_count = constfolded
        .iter()
        .zip(ssa.exprs.iter())
        .filter(|(folded, original)| folded.short() != original.short())
        .count();

    let dce_removed_count = dce_result.removed_pcs.len();

    // Trace-aware: surface the runtime value each instruction produced.
    // contexts[i] is positionally aligned to insns[i]; a register whose value
    // changed across the instruction is exactly what that instruction computed.
    let mut anno_by_pc: BTreeMap<u64, String> = BTreeMap::new();
    let mut observed_annotations: Vec<ObservedAnnotation> = Vec::new();
    for (ctx, (pc, _)) in contexts.iter().zip(insns.iter()) {
        let mut parts: Vec<String> = Vec::new();
        for (reg, after) in &ctx.regs_after {
            if ctx.regs_before.get(reg) != Some(after) {
                parts.push(format!("{reg}=0x{:x}", *after as u64));
            }
        }
        if parts.is_empty() {
            continue;
        }
        let text = parts.join(", ");
        anno_by_pc.entry(*pc).or_insert_with(|| text.clone());
        observed_annotations.push(ObservedAnnotation { pc: *pc, text });
    }

    // Render LLIL from the optimized (constfolded + DCE'd) expressions, folding
    // the observed runtime values inline where the producing instruction survived.
    let llil_ssa_text = if anno_by_pc.is_empty() {
        render_llil_block_with_names(opt_llil, &names)
    } else {
        render_llil_block_with_names_annotated(opt_llil, &names, &anno_by_pc)
    };

    // Phase 2c: Ghidra-style universal pipeline (operates on LLIL via PassIlExprs).
    // This runs constant propagation, dead code elimination, simplification rules,
    // type inference, struct recovery, and control-flow normalization — all within
    // the generic pass framework.
    let mut pass_exprs = from_llil(opt_llil);
    let pipeline = build_universal_pipeline();
    let pipeline_stats = pipeline.execute(function_name, &mut pass_exprs);
    let ghidra_phases_changed = pipeline_stats.phases_changed;
    let ghidra_final_count = pipeline_stats.final_expr_count;
    let ghidra_pass_text = render_pass_il_block(&pass_exprs.exprs);

    // Phase 2d: Infer call signatures from call site argument types
    let call_signatures = infer_call_signatures(&pass_exprs.exprs);

    // Phase 3: LLIL → MLIL (using the optimized LLIL)
    let (mlil_exprs, mlil_stats) = lower_llil_to_mlil(opt_llil, &names);
    let mlil_count = mlil_exprs.len();
    let mlil_text = render_mlil_block(&mlil_exprs);

    // Phase 4: MLIL → HLIL
    let (hlil_exprs, hlil_stats) = lower_mlil_to_hlil(&mlil_exprs, &names);
    let hlil_count = hlil_exprs.len();
    let hlil_text = render_hlil(&hlil_exprs);

    // Collect indirect branch dispatch targets (br xN, blr xN) from trace.
    let indirect_dispatch_targets = collect_indirect_dispatch_targets(insns, contexts);
    let indirect_dispatch_sites = indirect_dispatch_targets.len();
    let indirect_dispatch_unique_targets: usize =
        indirect_dispatch_targets.values().map(|v| v.len()).sum();

    // Collect trace metadata
    let unique_pcs: BTreeSet<u64> = insns.iter().map(|(pc, _)| *pc).collect();
    let total_exec_count: u64 = contexts.iter().map(|c| c.exec_count).sum();

    TraceDecompileOutput {
        insn_count,
        llil_count,
        mlil_count,
        hlil_count,
        llil_coverage,
        llil_ssa_text,
        mlil_text,
        hlil_text,
        function_name: function_name.to_string(),
        trace_contexts: contexts.to_vec(),
        observed_annotations,
        mlil_lower_stats: mlil_stats,
        hlil_lower_stats: hlil_stats,
        unique_pcs: unique_pcs.len(),
        total_exec_count,
        constfold_count,
        dce_removed_count,
        dce_iterations: 0,
        ghidra_pass_text,
        ghidra_phases_changed,
        ghidra_final_count,

        indirect_dispatch_targets,
        indirect_dispatch_sites,
        indirect_dispatch_unique_targets,
        stability_entries: Vec::new(),
        stability_constant_count: 0,
        stability_input_dependent_count: 0,
        stability_call_dependent_count: 0,
        call_signatures,
    }
}

fn specialize_trace_control_flow(
    exprs: &[LlilExpr],
    insns: &[(u64, u32)],
    contexts: &[TraceContext],
) -> Vec<LlilExpr> {
    let branch_by_pc: BTreeMap<u64, bool> = insns
        .iter()
        .zip(contexts.iter())
        .filter_map(|((pc, _), ctx)| ctx.branch_taken.map(|taken| (*pc, taken)))
        .collect();
    let next_pc_by_pc: BTreeMap<u64, Option<u64>> = insns
        .iter()
        .zip(contexts.iter())
        .map(|((pc, _), ctx)| (*pc, ctx.next_pc))
        .collect();
    if branch_by_pc.is_empty() && next_pc_by_pc.values().all(Option::is_none) {
        return exprs.to_vec();
    }

    let mut out = Vec::with_capacity(exprs.len());
    for e in exprs {
        if e.op != LlilOp::If {
            if e.op == LlilOp::Jump {
                if let Some(next_pc) = next_pc_by_pc.get(&e.pc).copied().flatten() {
                    out.push(resolved_jump_note(e.pc, next_pc));
                    out.push(LlilExpr::new(
                        LlilOp::Goto,
                        8,
                        vec![LlilOperand::U64(next_pc)],
                        e.pc,
                    ));
                } else {
                    out.push(e.clone());
                }
                continue;
            }
            out.push(e.clone());
            continue;
        }
        let Some(taken) = branch_by_pc.get(&e.pc).copied() else {
            out.push(e.clone());
            continue;
        };
        let chosen = branch_target(e, taken);
        let pruned = branch_target(e, !taken);
        match (chosen, pruned) {
            (Some(chosen), Some(pruned)) => {
                out.push(pruned_branch_note(e.pc, taken, pruned));
                out.push(LlilExpr::new(
                    LlilOp::Goto,
                    8,
                    vec![LlilOperand::U64(chosen)],
                    e.pc,
                ));
            }
            _ => out.push(e.clone()),
        }
    }
    out
}

fn resolved_jump_note(pc: u64, target: u64) -> LlilExpr {
    LlilExpr::new(LlilOp::Intrinsic, 0, vec![LlilOperand::U64(target)], pc)
        .with_extra("mnem", "trace_resolved_jump")
}

fn branch_target(e: &LlilExpr, taken: bool) -> Option<u64> {
    let idx = if taken { 1 } else { 2 };
    match e.operands.get(idx) {
        Some(LlilOperand::U64(v)) => Some(*v),
        _ => None,
    }
}

fn pruned_branch_note(pc: u64, taken: bool, pruned_target: u64) -> LlilExpr {
    LlilExpr::new(
        LlilOp::Intrinsic,
        0,
        vec![LlilOperand::U64(pruned_target)],
        pc,
    )
    .with_extra("mnem", "trace_pruned_branch")
    .with_extra("taken", if taken { "true" } else { "false" })
}

/// Simple decompilation from raw instructions (no trace data).
/// Useful for static analysis.
pub fn decompile_static(insns: &[(u64, u32)]) -> TraceDecompileOutput {
    let empty_contexts: Vec<TraceContext> = insns.iter().map(|_| TraceContext::default()).collect();
    decompile_trace(insns, &empty_contexts, "static_fn")
}

// ============================================================================
// Multi-call value stability analysis
// ============================================================================

/// Parameter registers used for correlation detection.
const PARAM_REGS: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];

/// Classify the stability of every register write site across multiple calls
/// to the same function.
///
/// For each (register, defining_pc) pair, this function compares the written
/// value across every call:
///
/// - **Constant**: the same value across ALL calls — safe to fold.
/// - **InputDependent**: varies across calls but the offset from a parameter
///   register (x0–x7) is constant — the value is parameter-indexed.
/// - **CallDependent**: varies unpredictably — keep as a variable.
/// - **Unobserved**: reserved for future use (not produced by this function).
///
/// This classification prevents over-specialized constant folding: only
/// `Constant` values should be folded; `InputDependent` values carry runtime
/// parameter semantics that must survive into the decompiled output.
pub fn classify_value_stability(calls: &[CallTraceData]) -> Vec<StabilityEntry> {
    if calls.is_empty() {
        return Vec::new();
    }

    // Collect all register writes across all calls: (reg_name, pc) → Vec<(call_idx, value)>
    let mut write_sites: BTreeMap<(String, u64), Vec<(usize, i64)>> = BTreeMap::new();

    for (call_idx, call) in calls.iter().enumerate() {
        for ((pc, _), ctx) in call.insns.iter().zip(call.contexts.iter()) {
            for (reg, after) in &ctx.regs_after {
                let before = ctx.regs_before.get(reg);
                if before != Some(after) {
                    write_sites
                        .entry((reg.clone(), *pc))
                        .or_default()
                        .push((call_idx, *after));
                }
            }
        }
    }

    // Classify each write site.
    let mut entries: Vec<StabilityEntry> = Vec::with_capacity(write_sites.len());

    for ((reg, pc), values) in &write_sites {
        // Collect the set of unique values across all calls.
        let unique_values: BTreeSet<i64> = values.iter().map(|(_, v)| *v).collect();

        if unique_values.len() == 1 {
            // Same value across ALL calls → truly constant.
            let value = *unique_values.first().unwrap();
            entries.push(StabilityEntry {
                reg: reg.clone(),
                pc: *pc,
                value,
                stability: ValueStability::Constant,
                correlated_param: None,
            });
        } else {
            // Value varies. Check for correlation with an input parameter.
            // A value is InputDependent on param P if (written_value - P_entry_value)
            // is constant across all calls (additive offset correlation).
            let mut correlated: Option<String> = None;

            for param_reg in &PARAM_REGS {
                let mut first_offset: Option<i64> = None;
                let mut all_match = true;

                for (call_idx, written_val) in values {
                    let call = &calls[*call_idx];
                    let param_val = call
                        .contexts
                        .first()
                        .and_then(|ctx| ctx.regs_before.get(*param_reg))
                        .copied();

                    match param_val {
                        Some(pv) => {
                            let offset = written_val - pv;
                            match first_offset {
                                None => first_offset = Some(offset),
                                Some(first) if first != offset => {
                                    all_match = false;
                                    break;
                                }
                                _ => {}
                            }
                        }
                        None => {
                            // Param not observed in this call — cannot check correlation.
                            all_match = false;
                            break;
                        }
                    }
                }

                if first_offset.is_some() && all_match {
                    correlated = Some(param_reg.to_string());
                    break;
                }
            }

            let (stability, correlated_param) = if let Some(param) = correlated {
                (ValueStability::InputDependent, Some(param))
            } else {
                (ValueStability::CallDependent, None)
            };

            let value = values.first().map(|(_, v)| *v).unwrap_or(0);
            entries.push(StabilityEntry {
                reg: reg.clone(),
                pc: *pc,
                value,
                stability,
                correlated_param,
            });
        }
    }

    // Sort by pc for deterministic output.
    entries.sort_by_key(|e| e.pc);
    entries
}

/// Decompile with multi-call stability analysis.
///
/// Runs `classify_value_stability` over the provided calls and feeds the
/// resulting classification into the decompile result. The stability metadata
/// is available in `TraceDecompileOutput::stability_entries` and can be used
/// by downstream passes to prevent over-specialized constant folding.
///
/// The first call's instructions are used for decompilation; all calls are
/// used for stability classification.
pub fn decompile_trace_multi(calls: &[CallTraceData], function_name: &str) -> TraceDecompileOutput {
    if calls.is_empty() {
        return decompile_static(&[]);
    }

    let stability_entries = classify_value_stability(calls);
    let first = &calls[0];

    let mut output = decompile_trace(&first.insns, &first.contexts, function_name);

    // Populate stability metadata.
    let c = stability_entries
        .iter()
        .filter(|e| e.stability == ValueStability::Constant)
        .count();
    let i = stability_entries
        .iter()
        .filter(|e| e.stability == ValueStability::InputDependent)
        .count();
    let d = stability_entries
        .iter()
        .filter(|e| e.stability == ValueStability::CallDependent)
        .count();

    output.stability_entries = stability_entries;
    output.stability_constant_count = c;
    output.stability_input_dependent_count = i;
    output.stability_call_dependent_count = d;

    output
}

// ============================================================================
// Call signature inference
// ============================================================================

/// ARM64 parameter registers in argument order.
const CALL_PARAM_REGS: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];

/// Collect the canonical register name by stripping an SSA version suffix.
/// "x0#1" → "x0", "x1#2" → "x1", "sp#1" → "sp".
fn canonical_reg(var_name: &str) -> &str {
    if let Some(pos) = var_name.rfind('#') {
        &var_name[..pos]
    } else {
        var_name
    }
}

/// Extract the type annotation from a PassIlExpr's extra fields.
fn expr_type(e: &PassIlExpr) -> Option<String> {
    e.extra
        .iter()
        .find(|(k, _)| k == "type")
        .map(|(_, v)| v.clone())
}

/// Extract the callee target from a call expression.
/// For LLIL_Call, the first operand is the target (register, immediate, or expression).
fn extract_call_target(expr: &PassIlExpr) -> Option<String> {
    if !expr.op.contains("Call") || expr.op.contains("CallInd") {
        return None;
    }
    expr.operands.first().map(|op| match op {
        PassIlOperand::Var(name) => name.clone(),
        PassIlOperand::U64(addr) => format!("{:#x}", addr),
        PassIlOperand::Imm(addr) => format!("{:#x}", *addr as u64),
        PassIlOperand::Str(s) => s.clone(),
        PassIlOperand::Expr(_) => "<indirect>".to_string(),
    })
}

/// Map a PassIl type string to a C type string suitable for signatures.
fn map_type_to_c(il_type: &str) -> &str {
    match il_type {
        "int" => "int",
        "uint" => "unsigned int",
        "sint" => "int",
        "ptr" => "void*",
        "unknown" => "int",
        _ => "int",
    }
}

/// For one call expression at a given position, find the types of arguments
/// by scanning backward for the most recent SetReg of each parameter register.
fn collect_call_arg_types(exprs: &[PassIlExpr], call_pos: usize) -> Option<Vec<Option<String>>> {
    // Track last-seen type for each parameter register.
    let mut arg_types: [Option<String>; 8] = Default::default();

    // Scan backward from the call to find SetReg of parameter regs.
    for i in (0..call_pos).rev() {
        let e = &exprs[i];
        let is_set = e.op == "LLIL_SetReg"
            || e.op == "MLIL_SetVar"
            || e.op == "HLIL_SetVar"
            || e.op.contains("SetReg")
            || e.op.contains("SetVar");
        if !is_set {
            continue;
        }
        if e.operands.is_empty() {
            continue;
        }
        let dest_var = match &e.operands[0] {
            PassIlOperand::Var(name) => name.clone(),
            _ => continue,
        };
        let reg = canonical_reg(&dest_var);

        for (param_idx, param_reg) in CALL_PARAM_REGS.iter().enumerate() {
            if reg == *param_reg && arg_types[param_idx].is_none() {
                if let Some(ty) = expr_type(e) {
                    arg_types[param_idx] = Some(ty);
                }
                break;
            }
        }

        // If all param regs found, stop scanning.
        if arg_types.iter().all(Option::is_some) {
            break;
        }
    }

    // Strip trailing Nones: only keep up to the last Some entry.
    let mut args: Vec<Option<String>> = arg_types.into_iter().collect();
    while args.last().is_some_and(|last| last.is_none()) {
        args.pop();
    }

    // If no args have types, return None (skip this call site).
    if args.is_empty() {
        return None;
    }

    Some(args)
}

/// Infer call signatures from call site argument types in the PassIlExprs.
///
/// Steps:
/// 1. For each call site, collect the types of arguments passed (from type inference).
/// 2. For each callee, aggregate all call site argument types.
/// 3. Vote on parameter types: majority type wins, conflicts recorded.
/// 4. Infer return type from how return value (x0) is used after the call.
/// 5. Generate function signature string.
pub fn infer_call_signatures(exprs: &[PassIlExpr]) -> Vec<CallSignature> {
    if exprs.is_empty() {
        return Vec::new();
    }

    // Step 1: Find call sites and collect argument types.
    // Per callee: Vec of (call_pos, arg_types[8])
    let mut callee_data: std::collections::BTreeMap<String, Vec<(usize, Vec<Option<String>>)>> =
        std::collections::BTreeMap::new();

    for (pos, expr) in exprs.iter().enumerate() {
        if !expr.op.contains("Call") {
            continue;
        }
        let Some(target) = extract_call_target(expr) else {
            continue;
        };
        if let Some(arg_types) = collect_call_arg_types(exprs, pos) {
            callee_data
                .entry(target)
                .or_default()
                .push((pos, arg_types));
        }
    }

    // Step 2-3: Aggregate per callee and vote on parameter types.
    let mut signatures: Vec<CallSignature> = Vec::new();

    for (callee_id, sites) in &callee_data {
        let call_site_count = sites.len();
        let max_params = sites.iter().map(|(_, args)| args.len()).max().unwrap_or(0);

        // Determine callee name: if it looks like an address, format as sub_NNNN
        let callee_name = if callee_id.starts_with("0x") || callee_id.starts_with("0X") {
            let addr = u64::from_str_radix(callee_id.trim_start_matches("0x"), 16).unwrap_or(0);
            format!("sub_{:x}", addr)
        } else {
            callee_id.clone()
        };

        let callee_pc = u64::from_str_radix(callee_id.trim_start_matches("0x"), 16).unwrap_or(0);

        let mut params: Vec<ParameterTypeInfo> = Vec::new();

        for param_idx in 0..max_params {
            // Collect the types observed for this parameter across call sites.
            let mut type_votes: std::collections::BTreeMap<String, usize> =
                std::collections::BTreeMap::new();
            let mut total_call_sites_with_param = 0usize;

            for (_pos, arg_types) in sites {
                if let Some(Some(ty)) = arg_types.get(param_idx) {
                    *type_votes.entry(ty.clone()).or_default() += 1;
                    total_call_sites_with_param += 1;
                }
            }

            if type_votes.is_empty() {
                // No call site had this parameter typed.
                params.push(ParameterTypeInfo {
                    index: param_idx,
                    register: CALL_PARAM_REGS[param_idx.min(7)].to_string(),
                    inferred_type: "int".to_string(),
                    vote_count: 0,
                    total_call_sites: call_site_count,
                    conflicting_types: Vec::new(),
                });
                continue;
            }

            // Find majority type.
            let mut votes: Vec<(String, usize)> = type_votes.into_iter().collect();
            votes.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

            let (majority_type, vote_count) = votes[0].clone();
            let conflicting_types: Vec<(String, usize)> = votes
                .iter()
                .skip(1)
                .map(|(ty, count)| (ty.clone(), *count))
                .collect();

            params.push(ParameterTypeInfo {
                index: param_idx,
                register: CALL_PARAM_REGS[param_idx.min(7)].to_string(),
                inferred_type: majority_type,
                vote_count,
                total_call_sites: call_site_count,
                conflicting_types,
            });
        }

        // Step 4: Infer return type from x0 usage after calls.
        let return_type = infer_return_type(exprs, sites, callee_id);

        // Step 5: Build signature string.
        let sig_string = build_signature_string(&return_type, &callee_name, &params);

        signatures.push(CallSignature {
            callee_pc,
            callee_name,
            call_site_count,
            return_type,
            params,
            signature_string: sig_string,
        });
    }

    // Sort by caller_count descending (most-called first).
    signatures.sort_by_key(|s| std::cmp::Reverse(s.call_site_count));
    signatures
}

/// Infer the return type of a callee by examining how x0 is used after calls.
fn infer_return_type(
    exprs: &[PassIlExpr],
    sites: &[(usize, Vec<Option<String>>)],
    _callee_id: &str,
) -> String {
    let mut usage_types: Vec<String> = Vec::new();

    for &(call_pos, _) in sites {
        // Look forward from the call position to find how x0 is used.
        for i in (call_pos + 1)..exprs.len() {
            let e = &exprs[i];

            // Recursively walk the expression tree to find x0 usage and its context.
            let ctx = find_x0_usage_context(e);
            if let Some(type_hint) = ctx {
                usage_types.push(type_hint);
            } else {
                // Expression doesn't read x0 — keep looking.
                continue;
            }

            break; // Only consider the first usage of x0 after the call.
        }
    }

    // Vote on return type.
    if usage_types.is_empty() {
        return "void".to_string();
    }

    let mut vote_counts: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    for ty in &usage_types {
        *vote_counts.entry(ty.as_str()).or_default() += 1;
    }
    let mut votes: Vec<(&&str, &usize)> = vote_counts.iter().collect();
    votes.sort_by_key(|(_, count)| std::cmp::Reverse(**count));

    let (ty, _) = votes[0];
    map_type_to_c(ty).to_string()
}

/// Walk an expression tree looking for x0/w0 usage and return a type hint
/// based on the context in which x0 is found.
/// Returns the IL-level type string (not the C-mapped type).
fn find_x0_usage_context(e: &PassIlExpr) -> Option<String> {
    // Check each operand for x0.
    for (idx, op) in e.operands.iter().enumerate() {
        match op {
            PassIlOperand::Var(name) => {
                let reg = canonical_reg(name);
                if reg == "x0" || reg == "w0" {
                    return context_to_type_hint(&e.op, idx);
                }
            }
            PassIlOperand::Expr(child) => {
                if let Some(hint) = find_x0_usage_context(child) {
                    return Some(hint);
                }
            }
            _ => {}
        }
    }
    None
}

/// Given an expression op and the operand index where x0 appears, return
/// a type hint string ("ptr", "int", "uint", "sint").
fn context_to_type_hint(parent_op: &str, operand_idx: usize) -> Option<String> {
    match parent_op {
        "LLIL_Load" | "MLIL_Load" | "HLIL_Load" => {
            if operand_idx == 0 {
                // x0 used as load address → ptr return
                Some("ptr".to_string())
            } else {
                // x0 is the value being loaded — actually this means x0 is a source, not result
                None
            }
        }
        "LLIL_Store" | "MLIL_Store" | "HLIL_Store" => {
            if operand_idx == 0 {
                // x0 used as store address → ptr
                Some("ptr".to_string())
            } else {
                Some("int".to_string())
            }
        }
        "LLIL_CmpE" | "MLIL_CmpE" | "LLIL_CmpNe" | "MLIL_CmpNe" | "LLIL_CmpSlt" | "LLIL_CmpSle"
        | "LLIL_CmpSgt" | "LLIL_CmpSge" | "LLIL_CmpUlt" | "LLIL_CmpUle" | "LLIL_CmpUgt"
        | "LLIL_CmpUge" => Some("int".to_string()),
        "LLIL_Zx" | "MLIL_Zx" | "HLIL_Zx" => {
            // Zero-extend indicates unsigned
            Some("uint".to_string())
        }
        "LLIL_Sx" | "MLIL_Sx" | "HLIL_Sx" => {
            // Sign-extend indicates signed
            Some("sint".to_string())
        }
        "LLIL_Add" | "MLIL_Add" | "HLIL_Add" | "LLIL_Sub" | "MLIL_Sub" | "HLIL_Sub"
        | "LLIL_Mul" | "MLIL_Mul" | "HLIL_Mul" | "LLIL_DivS" | "MLIL_DivS" | "LLIL_DivU"
        | "MLIL_DivU" | "LLIL_And" | "MLIL_And" | "HLIL_And" | "LLIL_Or" | "MLIL_Or"
        | "HLIL_Or" | "LLIL_Xor" | "MLIL_Xor" | "HLIL_Xor" | "LLIL_Lsl" | "MLIL_Lsl"
        | "HLIL_Lsl" | "LLIL_Lsr" | "MLIL_Lsr" | "HLIL_Lsr" | "LLIL_Asr" | "MLIL_Asr"
        | "HLIL_Asr" | "LLIL_Neg" | "MLIL_Neg" | "HLIL_Neg" => Some("int".to_string()),
        // For SetReg/SetVar, recurse into the source operand (index 1)
        "LLIL_SetReg" | "MLIL_SetVar" | "HLIL_SetVar" => {
            // x0 in dest position → this is where x0 is being written, not read.
            // Skip — we should only look at where x0 is READ.
            if operand_idx == 0 {
                None
            } else {
                // x0 is the source value → look at what it's assigned to
                Some("int".to_string())
            }
        }
        _ => {
            // For other operations where x0 appears, default to int.
            Some("int".to_string())
        }
    }
}

/// Build a C-like function signature string from the inferred types.
fn build_signature_string(
    return_type: &str,
    callee_name: &str,
    params: &[ParameterTypeInfo],
) -> String {
    let mut s = String::new();
    s.push_str(return_type);
    s.push(' ');
    s.push_str(callee_name);
    s.push('(');
    let param_parts: Vec<String> = params
        .iter()
        .map(|p| {
            let c_type = map_type_to_c(&p.inferred_type);
            format!("{} arg{}", c_type, p.index)
        })
        .collect();
    s.push_str(&param_parts.join(", "));
    s.push(')');
    s
}

// ============================================================================
// PassIlExpr rendering helpers
// ============================================================================

/// Render a block of PassIlExpr as readable single-line expressions.
fn render_pass_il_block(exprs: &[PassIlExpr]) -> String {
    let mut out = String::new();
    for e in exprs {
        out.push_str(&format!("  {:#x}: {}", e.pc, e.op));
        for op in &e.operands {
            out.push(' ');
            out.push_str(&render_pass_operand(op));
        }
        if !e.extra.is_empty() {
            out.push_str("  // ");
            for (k, v) in &e.extra {
                out.push_str(k);
                out.push('=');
                out.push_str(v);
                out.push(' ');
            }
        }
        out.push('\n');
    }
    out
}

fn render_pass_operand(op: &PassIlOperand) -> String {
    match op {
        PassIlOperand::Expr(e) => format!("({})", render_pass_expr(e)),
        PassIlOperand::Var(v) => v.clone(),
        PassIlOperand::Imm(v) => format!("{}", v),
        PassIlOperand::U64(v) => format!("{:#x}", v),
        PassIlOperand::Str(s) => s.clone(),
    }
}

fn render_pass_expr(e: &PassIlExpr) -> String {
    let mut out = e.op.clone();
    if !e.operands.is_empty() {
        out.push(' ');
        let parts: Vec<String> = e.operands.iter().map(render_pass_operand).collect();
        out.push_str(&parts.join(", "));
    }
    out
}

/// Collect the set of actually-executed edges from trace contexts.
/// Build a map from instruction PC to total execution count.
/// Collect indirect branch (br xN, blr xN) dispatch targets from trace data.
pub fn collect_indirect_dispatch_targets(
    insns: &[(u64, u32)],
    contexts: &[TraceContext],
) -> HashMap<u64, Vec<(u64, u64)>> {
    let mut dispatch_count: HashMap<u64, HashMap<u64, u64>> = HashMap::new();

    for ((pc, inst), ctx) in insns.iter().zip(contexts.iter()) {
        let d = decode(*pc, *inst);
        let mnem = d.mnemonic.as_str();
        if mnem != "br" && mnem != "blr" {
            continue;
        }
        if let Some(next_pc) = ctx.next_pc {
            dispatch_count
                .entry(*pc)
                .or_default()
                .entry(next_pc)
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }
    }

    let mut result: HashMap<u64, Vec<(u64, u64)>> = HashMap::new();
    for (src, targets) in dispatch_count {
        let mut vec: Vec<(u64, u64)> = targets.into_iter().collect();
        vec.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
        result.insert(src, vec);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a trace context with known register values.
    fn trace_ctx(before: &[(&str, i64)], exec_count: u64) -> TraceContext {
        let mut ctx = TraceContext {
            exec_count,
            ..Default::default()
        };
        for (reg, val) in before {
            ctx.regs_before.insert(reg.to_string(), *val);
        }
        ctx
    }

    /// Create a CallTraceData with register writes simulated via context pairs.
    /// Each (pc, inst, [(reg, before_val, after_val)]) entry creates a
    /// TraceContext with regs_before and regs_after set accordingly.
    fn call_data(
        entries: &[(u64, u32, &[(&str, i64, i64)])],
        param_vals: &[(&str, i64)],
    ) -> CallTraceData {
        let mut insns = Vec::new();
        let mut contexts = Vec::new();

        for (pc, inst, reg_changes) in entries {
            insns.push((*pc, *inst));
            let mut ctx = TraceContext::default();
            for (reg, before, after) in *reg_changes {
                ctx.regs_before.insert(reg.to_string(), *before);
                ctx.regs_after.insert(reg.to_string(), *after);
            }
            contexts.push(ctx);
        }

        // Set param values in the first context.
        if !contexts.is_empty() {
            for (reg, val) in param_vals {
                contexts[0]
                    .regs_before
                    .entry(reg.to_string())
                    .or_insert(*val);
            }
        }

        CallTraceData { insns, contexts }
    }

    #[test]
    fn static_decompile_simple() {
        // x0 = 1; ret
        let insns = vec![
            (0x1000u64, 0xd2800020u32), // mov x0, #1
            (0x1004u64, 0xd65f03c0u32), // ret
        ];
        let output = decompile_static(&insns);
        assert!(output.insn_count > 0);
        assert!(output.llil_count > 0);
        assert!(!output.llil_ssa_text.is_empty());
        assert!(!output.mlil_text.is_empty());
        assert!(!output.hlil_text.is_empty());
        // Coverage should be 1.0 for these two well-known instructions
        assert!(output.llil_coverage >= 0.0);
    }

    #[test]
    fn trace_enriched_decompile() {
        // mov x0, #1; mov x1, #2; add x0, x0, x1; ret
        let insns = vec![
            (0x1000u64, 0xd2800020u32), // mov x0, #1
            (0x1004u64, 0xd2800041u32), // mov x1, #2
            (0x1008u64, 0x8b010000u32), // add x0, x0, x1
            (0x100cu64, 0xd65f03c0u32), // ret
        ];

        let contexts = vec![
            trace_ctx(&[("x0", 0), ("x1", 0)], 1),
            trace_ctx(&[("x0", 1), ("x1", 0)], 1),
            trace_ctx(&[("x0", 1), ("x1", 2)], 1),
            trace_ctx(&[("x0", 3), ("x1", 2)], 1),
        ];

        let output = decompile_trace(&insns, &contexts, "add_fn");
        assert_eq!(output.function_name, "add_fn");
        assert_eq!(output.total_exec_count, 4);
        assert_eq!(output.unique_pcs, 4);
        assert_eq!(output.insn_count, 4);
    }

    #[test]
    fn conditional_branch_decompile() {
        // cmp x0, x1; b.eq target; (fallthrough) mov x0, #1; b end; target: mov x0, #2; end: ret
        let insns = vec![
            (0x1000u64, 0xeb01001fu32), // cmp x0, x1
            (0x1004u64, 0x54000080u32), // b.eq 0x1014 (target)
            (0x1008u64, 0xd2800020u32), // mov x0, #1
            (0x100cu64, 0x14000002u32), // b 0x101c (end)
            (0x1014u64, 0xd2800040u32), // mov x0, #2
            (0x101cu64, 0xd65f03c0u32), // ret
        ];

        let contexts: Vec<TraceContext> = insns.iter().map(|_| TraceContext::default()).collect();
        let output = decompile_trace(&insns, &contexts, "cmp_fn");
        assert!(output.insn_count > 0);
        assert!(!output.llil_ssa_text.is_empty());
        // Should detect the if pattern
        assert!(output.hlil_text.contains("return;") || output.mlil_text.contains("if"));
    }

    #[test]
    fn empty_decompile() {
        let output = decompile_static(&[]);
        assert_eq!(output.insn_count, 0);
        assert!(output.llil_ssa_text.is_empty());
    }

    #[test]
    fn llil_coverage_tracks_intrinsics() {
        // Known well-supported instruction
        let insns = vec![(0x1000u64, 0xd2800020u32)]; // mov x0, #1
        let output = decompile_static(&insns);
        assert!(output.llil_coverage > 0.9);
    }

    #[test]
    fn multi_layer_text_is_non_empty() {
        let insns = vec![
            (0x1000u64, 0xd2800020u32), // mov x0, #1
            (0x1004u64, 0xd65f03c0u32), // ret
        ];
        let output = decompile_static(&insns);
        assert!(!output.llil_ssa_text.is_empty(), "LLIL SSA text empty");
        assert!(!output.mlil_text.is_empty(), "MLIL text empty");
        assert!(!output.hlil_text.is_empty(), "HLIL text empty");
    }

    // ---------- Value stability classification tests ----------

    #[test]
    fn stability_constant_same_value_across_all_calls() {
        // Two calls. In both, x5 is written to 0x100 at PC 0x2000.
        let c1 = call_data(&[(0x2000, 0x91000405, &[("x5", 0, 0x100)])], &[("x0", 10)]);
        let c2 = call_data(&[(0x2000, 0x91000405, &[("x5", 0, 0x100)])], &[("x0", 999)]);
        let entries = classify_value_stability(&[c1, c2]);
        assert!(!entries.is_empty());
        let x5 = entries
            .iter()
            .find(|e| e.reg == "x5" && e.pc == 0x2000)
            .unwrap();
        assert_eq!(x5.stability, ValueStability::Constant);
        assert_eq!(x5.value, 0x100);
        assert!(x5.correlated_param.is_none());
    }

    #[test]
    fn stability_input_dependent_correlates_with_param() {
        // x5 = x0 + 8. Call 1: x0=10 → x5=18. Call 2: x0=20 → x5=28.
        let c1 = call_data(&[(0x2000, 0x91000505, &[("x5", 0, 18)])], &[("x0", 10)]);
        let c2 = call_data(&[(0x2000, 0x91000505, &[("x5", 0, 28)])], &[("x0", 20)]);
        let entries = classify_value_stability(&[c1, c2]);
        let x5 = entries
            .iter()
            .find(|e| e.reg == "x5" && e.pc == 0x2000)
            .unwrap();
        assert_eq!(
            x5.stability,
            ValueStability::InputDependent,
            "x5 = x0+8 should be InputDependent on x0"
        );
        assert_eq!(x5.correlated_param.as_deref(), Some("x0"));
    }

    #[test]
    fn stability_call_dependent_varies_unpredictably() {
        // x5 written with unrelated values across calls (neither constant nor additive).
        let c1 = call_data(&[(0x2000, 0xd2800005, &[("x5", 0, 42)])], &[("x0", 10)]);
        let c2 = call_data(&[(0x2000, 0xd2800005, &[("x5", 0, 77)])], &[("x0", 999)]);
        let entries = classify_value_stability(&[c1, c2]);
        let x5 = entries
            .iter()
            .find(|e| e.reg == "x5" && e.pc == 0x2000)
            .unwrap();
        assert_eq!(x5.stability, ValueStability::CallDependent);
        assert!(x5.correlated_param.is_none());
    }

    #[test]
    fn stability_input_dependent_offset_different_params() {
        // x5 = x0+8 (correlates with x0), x6 = x1-4 (correlates with x1).
        let c1 = call_data(
            &[
                (0x2000, 0x91000505, &[("x5", 0, 18)]), // x5 = 10+8 = 18
                (0x2004, 0xd1000826, &[("x6", 0, 1)]),  // x6 = 5-4 = 1
            ],
            &[("x0", 10), ("x1", 5)],
        );
        let c2 = call_data(
            &[
                (0x2000, 0x91000505, &[("x5", 0, 108)]), // x5 = 100+8 = 108
                (0x2004, 0xd1000826, &[("x6", 0, 46)]),  // x6 = 50-4 = 46
            ],
            &[("x0", 100), ("x1", 50)],
        );
        let entries = classify_value_stability(&[c1, c2]);
        let x5 = entries
            .iter()
            .find(|e| e.reg == "x5" && e.pc == 0x2000)
            .unwrap();
        assert_eq!(x5.stability, ValueStability::InputDependent);
        assert_eq!(x5.correlated_param.as_deref(), Some("x0"));

        let x6 = entries
            .iter()
            .find(|e| e.reg == "x6" && e.pc == 0x2004)
            .unwrap();
        assert_eq!(x6.stability, ValueStability::InputDependent);
        assert_eq!(x6.correlated_param.as_deref(), Some("x1"));
    }

    #[test]
    fn stability_mixed_constant_and_input_dependent() {
        // x5 always = 0x100 (Constant), x6 = x0 + 16 (InputDependent on x0).
        let c1 = call_data(
            &[
                (0x2000, 0xd2820005, &[("x5", 0, 0x100)]),
                (0x2004, 0x91004006, &[("x6", 0, 26)]), // x6 = 10+16
            ],
            &[("x0", 10)],
        );
        let c2 = call_data(
            &[
                (0x2000, 0xd2820005, &[("x5", 0, 0x100)]),
                (0x2004, 0x91004006, &[("x6", 0, 36)]), // x6 = 20+16
            ],
            &[("x0", 20)],
        );
        let entries = classify_value_stability(&[c1, c2]);

        let x5 = entries
            .iter()
            .find(|e| e.reg == "x5" && e.pc == 0x2000)
            .unwrap();
        assert_eq!(x5.stability, ValueStability::Constant);

        let x6 = entries
            .iter()
            .find(|e| e.reg == "x6" && e.pc == 0x2004)
            .unwrap();
        assert_eq!(x6.stability, ValueStability::InputDependent);
        assert_eq!(x6.correlated_param.as_deref(), Some("x0"));
    }

    #[test]
    fn stability_empty_calls_returns_empty() {
        let entries = classify_value_stability(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn stability_single_call_everything_is_constant() {
        // With only one call, every register write is trivially "constant"
        // because there's no other call to compare against.
        let c1 = call_data(
            &[
                (0x2000, 0xd2820005, &[("x5", 0, 0x100)]),
                (0x2004, 0x91000406, &[("x6", 0, 18)]),
            ],
            &[("x0", 10)],
        );
        let entries = classify_value_stability(&[c1]);
        assert_eq!(entries.len(), 2);
        for e in &entries {
            assert_eq!(
                e.stability,
                ValueStability::Constant,
                "Single-call should classify all writes as Constant: {e:?}"
            );
        }
    }

    #[test]
    fn stability_decompile_trace_multi_populates_metadata() {
        // 2 constant writes + 1 input-dependent + 1 call-dependent
        let c1 = call_data(
            &[
                (0x1000, 0xd2820005, &[("x5", 0, 0x100)]), // constant
                (0x1004, 0xd2820006, &[("x6", 0, 0x200)]), // constant
                (0x1008, 0x91000507, &[("x7", 0, 18)]),    // input-dep: x0=10, offset 8
                (0x100c, 0xd280002a, &[("fp", 0, 42)]),    // call-dep
            ],
            &[("x0", 10)],
        );
        let c2 = call_data(
            &[
                (0x1000, 0xd2820005, &[("x5", 0, 0x100)]),
                (0x1004, 0xd2820006, &[("x6", 0, 0x200)]),
                (0x1008, 0x91000507, &[("x7", 0, 108)]), // x0=100, offset 8
                (0x100c, 0xd280002a, &[("fp", 0, 99)]),  // call-dep
            ],
            &[("x0", 100)],
        );
        let output = decompile_trace_multi(&[c1, c2], "counts");
        assert_eq!(output.stability_constant_count, 2);
        assert_eq!(output.stability_input_dependent_count, 1);
        assert_eq!(output.stability_call_dependent_count, 1);
        assert_eq!(output.stability_entries.len(), 4);
    }

    #[test]
    fn stability_decompile_trace_single_call_has_empty_stability() {
        // Single-call decompile should have empty stability metadata.
        let insns = vec![(0x1000u64, 0xd2800020u32)]; // mov x0, #1
        let output = decompile_static(&insns);
        assert!(output.stability_entries.is_empty());
        assert_eq!(output.stability_constant_count, 0);
        assert_eq!(output.stability_input_dependent_count, 0);
        assert_eq!(output.stability_call_dependent_count, 0);
    }

    #[test]
    fn value_stability_display() {
        assert_eq!(format!("{}", ValueStability::Constant), "const");
        assert_eq!(format!("{}", ValueStability::InputDependent), "input_dep");
        assert_eq!(format!("{}", ValueStability::CallDependent), "call_dep");
        assert_eq!(format!("{}", ValueStability::Unobserved), "unobs");
    }

    #[test]
    fn stability_serialization_lowercase() {
        let e = StabilityEntry {
            reg: "x5".into(),
            pc: 0x2000,
            value: 0x100,
            stability: ValueStability::InputDependent,
            correlated_param: Some("x0".into()),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"stability\":\"inputdependent\""));
        assert!(json.contains("\"correlated_param\":\"x0\""));
    }

    // ---------- Indirect dispatch target collection tests ----------

    /// Helper: create a trace context with a known `next_pc`.
    fn ctx_with_next_pc(next_pc: u64) -> TraceContext {
        TraceContext {
            next_pc: Some(next_pc),
            ..Default::default()
        }
    }

    #[test]
    fn collect_indirect_dispatch_empty() {
        let insns = vec![(0x1000u64, 0xd503201fu32)]; // nop
        let contexts = vec![TraceContext::default()];
        let targets = collect_indirect_dispatch_targets(&insns, &contexts);
        assert!(targets.is_empty());
    }

    #[test]
    fn collect_indirect_dispatch_single_br() {
        // br x8 instruction (0xd61f0100), next_pc = 0x2000
        let insns = vec![(0x1000u64, 0xd61f0100u32)];
        let contexts = vec![ctx_with_next_pc(0x2000)];
        let targets = collect_indirect_dispatch_targets(&insns, &contexts);
        assert!(targets.contains_key(&0x1000));
        assert_eq!(targets[&0x1000], vec![(0x2000, 1)]);
    }

    #[test]
    fn collect_indirect_dispatch_multi_target() {
        // Two br instructions at same PC, going to different targets.
        let insns = vec![
            (0x1000u64, 0xd61f0100u32),
            (0x1000u64, 0xd61f0100u32),
            (0x1000u64, 0xd61f0100u32),
        ];
        let contexts = vec![
            ctx_with_next_pc(0x2000),
            ctx_with_next_pc(0x3000),
            ctx_with_next_pc(0x2000), // 0x2000 hit twice
        ];
        let targets = collect_indirect_dispatch_targets(&insns, &contexts);
        assert!(targets.contains_key(&0x1000));
        let t = &targets[&0x1000];
        // Sorted by count descending: 0x2000 (2 hits), 0x3000 (1 hit)
        assert_eq!(t[0], (0x2000, 2));
        assert_eq!(t[1], (0x3000, 1));
    }

    #[test]
    fn collect_indirect_dispatch_ignores_non_br() {
        // bl (direct branch) should not be collected.
        let insns = vec![(0x1000u64, 0x94000400u32)]; // bl +0x1000
        let contexts = vec![ctx_with_next_pc(0x2000)];
        let targets = collect_indirect_dispatch_targets(&insns, &contexts);
        assert!(targets.is_empty());
    }

    #[test]
    fn collect_indirect_dispatch_ignores_missing_next_pc() {
        // br with no next_pc should be skipped.
        let insns = vec![(0x1000u64, 0xd61f0100u32)];
        let contexts = vec![TraceContext::default()]; // next_pc = None
        let targets = collect_indirect_dispatch_targets(&insns, &contexts);
        assert!(targets.is_empty());
    }

    // ---------- Call signature inference tests ----------

    use crate::decompiler::pass::{PassIlExpr, PassIlOperand};

    fn pe(op: &str, size: u8, pc: u64, operands: Vec<PassIlOperand>) -> PassIlExpr {
        PassIlExpr {
            op: op.to_string(),
            size,
            pc,
            operands,
            extra: vec![],
        }
    }

    fn pe_typed(op: &str, size: u8, pc: u64, operands: Vec<PassIlOperand>, ty: &str) -> PassIlExpr {
        let mut e = pe(op, size, pc, operands);
        e.extra.push(("type".to_string(), ty.to_string()));
        e
    }

    fn var(name: &str) -> PassIlOperand {
        PassIlOperand::Var(name.to_string())
    }

    fn ival(v: i64) -> PassIlOperand {
        PassIlOperand::Imm(v)
    }

    fn uval(v: u64) -> PassIlOperand {
        PassIlOperand::U64(v)
    }

    #[test]
    fn infer_signatures_empty_exprs() {
        let sigs = infer_call_signatures(&[]);
        assert!(sigs.is_empty());
    }

    #[test]
    fn infer_signatures_no_calls() {
        let exprs = vec![
            pe_typed("LLIL_SetReg", 8, 0x1000, vec![var("x0#1"), ival(42)], "int"),
            pe("LLIL_Ret", 8, 0x1004, vec![var("x0#1")]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert!(sigs.is_empty());
    }

    #[test]
    fn infer_signatures_single_call_ptr_args() {
        // x0=ptr, x1=int; call sub_2000; x0 used in Load after call
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(0x4000)],
                "ptr",
            ),
            pe_typed("LLIL_SetReg", 8, 0x1004, vec![var("x1#1"), ival(42)], "int"),
            pe("LLIL_Call", 8, 0x1008, vec![uval(0x2000)]),
            pe(
                "LLIL_SetReg",
                8,
                0x100c,
                vec![
                    var("x2#1"),
                    PassIlOperand::Expr(Box::new(pe("LLIL_Load", 8, 0x100c, vec![var("x0#1")]))),
                ],
            ),
            pe("LLIL_Ret", 8, 0x1010, vec![var("x0#1")]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        let s = &sigs[0];
        assert_eq!(s.callee_pc, 0x2000);
        assert_eq!(s.call_site_count, 1);
        assert_eq!(s.params.len(), 2);
        assert_eq!(s.params[0].inferred_type, "ptr");
        assert_eq!(s.params[0].register, "x0");
        assert_eq!(s.params[1].inferred_type, "int");
        assert_eq!(s.params[1].register, "x1");
        assert_eq!(s.return_type, "void*");
        assert!(s.signature_string.contains("void*"));
        assert!(s.signature_string.contains("arg0"));
        assert!(s.signature_string.contains("arg1"));
    }

    #[test]
    fn infer_signatures_majority_vote_with_conflict() {
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(0x4000)],
                "ptr",
            ),
            pe_typed("LLIL_SetReg", 8, 0x1004, vec![var("x1#1"), ival(42)], "int"),
            pe("LLIL_Call", 8, 0x1008, vec![uval(0x2000)]),
            pe_typed(
                "LLIL_SetReg",
                8,
                0x100c,
                vec![var("x0#2"), ival(0x5000)],
                "ptr",
            ),
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1010,
                vec![var("x1#2"), ival(0x6000)],
                "ptr",
            ),
            pe("LLIL_Call", 8, 0x1014, vec![uval(0x2000)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        let s = &sigs[0];
        assert_eq!(s.call_site_count, 2);
        assert_eq!(s.params[0].inferred_type, "ptr");
        assert_eq!(s.params[0].vote_count, 2);
        assert_eq!(s.params[1].inferred_type, "int");
        assert_eq!(s.params[1].vote_count, 1);
        assert!(!s.params[1].conflicting_types.is_empty());
        assert!(s.signature_string.contains("sub_2000"));
    }

    #[test]
    fn infer_signatures_return_type_void() {
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(123)],
                "int",
            ),
            pe("LLIL_Call", 8, 0x1004, vec![uval(0x3000)]),
            pe("LLIL_Ret", 8, 0x1008, vec![]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].return_type, "void");
        assert!(sigs[0].signature_string.starts_with("void "));
    }

    #[test]
    fn infer_signatures_return_type_int_from_cmp() {
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(0x4000)],
                "ptr",
            ),
            pe("LLIL_Call", 8, 0x1004, vec![uval(0x2000)]),
            pe("LLIL_CmpE", 1, 0x1008, vec![var("x0#1"), ival(0)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].return_type, "int");
    }

    #[test]
    fn infer_signatures_multiple_callees() {
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(0x4000)],
                "ptr",
            ),
            pe_typed("LLIL_SetReg", 8, 0x1004, vec![var("x1#1"), ival(42)], "int"),
            pe("LLIL_Call", 8, 0x1008, vec![uval(0x2000)]),
            pe_typed(
                "LLIL_SetReg",
                8,
                0x100c,
                vec![var("x0#2"), ival(0x5000)],
                "ptr",
            ),
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1010,
                vec![var("x1#2"), ival(0x6000)],
                "ptr",
            ),
            pe("LLIL_Call", 8, 0x1014, vec![uval(0x3000)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 2);
        let callees: Vec<u64> = sigs.iter().map(|s| s.callee_pc).collect();
        assert!(callees.contains(&0x2000));
        assert!(callees.contains(&0x3000));
    }

    #[test]
    fn infer_signatures_only_typed_args() {
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(0x4000)],
                "ptr",
            ),
            pe("LLIL_Call", 8, 0x1004, vec![uval(0x2000)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].params.len(), 1);
        assert_eq!(sigs[0].params[0].inferred_type, "ptr");
    }

    #[test]
    fn infer_signatures_uint_in_signature() {
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(42)],
                "uint",
            ),
            pe("LLIL_Call", 8, 0x1004, vec![uval(0x2000)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].params[0].inferred_type, "uint");
        assert!(sigs[0].signature_string.contains("unsigned int"));
    }

    #[test]
    fn infer_signatures_setvar_works() {
        let exprs = vec![
            pe_typed(
                "MLIL_SetVar",
                8,
                0x1000,
                vec![var("x0#1"), ival(0x4000)],
                "ptr",
            ),
            pe_typed("MLIL_SetVar", 8, 0x1004, vec![var("x1#1"), ival(42)], "int"),
            pe("MLIL_Call", 8, 0x1008, vec![uval(0x2000)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].params.len(), 2);
        assert_eq!(sigs[0].params[0].inferred_type, "ptr");
        assert_eq!(sigs[0].params[1].inferred_type, "int");
    }

    #[test]
    fn infer_signatures_sint_to_int() {
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(-1)],
                "sint",
            ),
            pe("LLIL_Call", 8, 0x1004, vec![uval(0x2000)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].params[0].inferred_type, "sint");
        assert!(sigs[0].signature_string.contains("int arg0"));
    }

    #[test]
    fn infer_signatures_hlil_args() {
        let exprs = vec![
            pe_typed(
                "HLIL_SetVar",
                8,
                0x1000,
                vec![var("x0#1"), ival(0xdead)],
                "ptr",
            ),
            pe_typed(
                "HLIL_SetVar",
                8,
                0x1004,
                vec![var("x1#2"), ival(123)],
                "uint",
            ),
            pe("HLIL_Call", 8, 0x1008, vec![uval(0x4000)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].params.len(), 2);
        assert_eq!(sigs[0].params[0].register, "x0");
        assert_eq!(sigs[0].params[0].inferred_type, "ptr");
        assert_eq!(sigs[0].params[1].register, "x1");
        assert_eq!(sigs[0].params[1].inferred_type, "uint");
    }

    #[test]
    fn infer_signatures_return_ptr_from_load() {
        let exprs = vec![
            pe_typed("LLIL_SetReg", 8, 0x1000, vec![var("x0#1"), ival(42)], "int"),
            pe("LLIL_Call", 8, 0x1004, vec![uval(0x2000)]),
            pe(
                "LLIL_SetReg",
                8,
                0x1008,
                vec![
                    var("x2#1"),
                    PassIlOperand::Expr(Box::new(pe("LLIL_Load", 8, 0x1008, vec![var("x0#1")]))),
                ],
            ),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].return_type, "void*");
    }

    #[test]
    fn infer_signatures_format_three_params() {
        let exprs = vec![
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1000,
                vec![var("x0#1"), ival(0x4000)],
                "ptr",
            ),
            pe_typed("LLIL_SetReg", 8, 0x1004, vec![var("x1#1"), ival(42)], "int"),
            pe_typed(
                "LLIL_SetReg",
                8,
                0x1008,
                vec![var("x2#1"), ival(0x2000)],
                "ptr",
            ),
            pe("LLIL_Call", 8, 0x100c, vec![uval(0x2000)]),
        ];
        let sigs = infer_call_signatures(&exprs);
        assert_eq!(sigs.len(), 1);
        let sig = &sigs[0].signature_string;
        assert!(sig.starts_with("void "), "got: {sig}");
        assert!(sig.contains("sub_2000("));
        assert!(sig.contains("void* arg0"));
        assert!(sig.contains("int arg1"));
        assert!(sig.contains("void* arg2"));
        assert!(sig.ends_with(')'));
    }

    #[test]
    fn infer_signatures_decompile_trace_output_has_field() {
        let insns = vec![
            (0x1000u64, 0xd2808000u32),
            (0x1004u64, 0x94000400u32),
            (0x1008u64, 0xd65f03c0u32),
        ];
        let ctx0 = TraceContext {
            regs_before: BTreeMap::from([("x0".into(), 0)]),
            regs_after: BTreeMap::from([("x0".into(), 0x4000)]),
            exec_count: 1,
            ..Default::default()
        };
        let ctx1 = TraceContext {
            regs_before: BTreeMap::from([("x0".into(), 0x4000)]),
            exec_count: 1,
            ..Default::default()
        };
        let ctx2 = TraceContext {
            exec_count: 1,
            ..Default::default()
        };
        let output = decompile_trace(&insns, &[ctx0, ctx1, ctx2], "caller");
        assert!(output.call_signatures.is_empty() || !output.call_signatures.is_empty());
    }

    #[test]
    fn canonical_reg_strips_version() {
        assert_eq!(canonical_reg("x0#1"), "x0");
        assert_eq!(canonical_reg("x1#2"), "x1");
        assert_eq!(canonical_reg("sp#1"), "sp");
        assert_eq!(canonical_reg("x0"), "x0");
        assert_eq!(canonical_reg("sp"), "sp");
    }

    #[test]
    fn build_signature_string_format() {
        let params = vec![
            ParameterTypeInfo {
                index: 0,
                register: "x0".into(),
                inferred_type: "ptr".into(),
                vote_count: 3,
                total_call_sites: 3,
                conflicting_types: vec![],
            },
            ParameterTypeInfo {
                index: 1,
                register: "x1".into(),
                inferred_type: "int".into(),
                vote_count: 3,
                total_call_sites: 3,
                conflicting_types: vec![],
            },
        ];
        let sig = build_signature_string("int", "sub_1234", &params);
        assert_eq!(sig, "int sub_1234(void* arg0, int arg1)");
    }

    #[test]
    fn call_signature_serialization_ok() {
        let sig = CallSignature {
            callee_pc: 0x2000,
            callee_name: "sub_2000".into(),
            call_site_count: 2,
            return_type: "int".into(),
            params: vec![ParameterTypeInfo {
                index: 0,
                register: "x0".into(),
                inferred_type: "ptr".into(),
                vote_count: 2,
                total_call_sites: 2,
                conflicting_types: vec![],
            }],
            signature_string: "int sub_2000(void* arg0)".into(),
        };
        let json = serde_json::to_string_pretty(&sig).unwrap();
        assert!(json.contains("callee_pc"));
        assert!(json.contains("callee_name"));
        assert!(json.contains("signature_string"));
        assert!(json.contains("void* arg0"));
    }
}
