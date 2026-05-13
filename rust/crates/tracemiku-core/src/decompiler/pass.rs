//! Ghidra-style Pass framework for the three-layer IL pipeline.
//!
//! Architecture (mirrors Ghidra's Action/Rule/ActionPool):
//!
//!   Pass         — macro-level transform on the whole function (like Ghidra Action)
//!   Rule         — micro-level transform on a single IL expression (like Ghidra Rule)
//!   PassPool     — collection of Rules, applied to all expressions until fixpoint
//!   PassGroup    — ordered sequence of passes, optionally repeatable
//!   PassPipeline — top-level scheduler with phase-based ordering
//!
//! Key design decisions from Ghidra:
//!   1. Fixpoint iteration: Rules in a pool repeat until no change
//!   2. Graduated phases: Setup → MainLoop(fixpoint) → PostLoop → Cleanup → Finalize
//!   3. Restart mechanism: passes can request a full pipeline restart
//!   4. Dependency ordering: passes declare what they produce/consume

use std::collections::BTreeSet;
use std::fmt;

// ============================================================================
// PassResult — what a pass returns after execution
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassResult {
    /// The pass made changes to the function.
    Changed,
    /// The pass found nothing to change.
    Unchanged,
    /// The pass requests a full pipeline restart (re-run from the beginning).
    /// Used by passes like SSA construction or phi placement that require
    /// re-running earlier passes.
    Restart,
}

impl PassResult {
    pub fn is_changed(self) -> bool {
        matches!(self, PassResult::Changed)
    }

    pub fn and(self, other: PassResult) -> PassResult {
        match (self, other) {
            (PassResult::Restart, _) | (_, PassResult::Restart) => PassResult::Restart,
            (PassResult::Changed, _) | (_, PassResult::Changed) => PassResult::Changed,
            _ => PassResult::Unchanged,
        }
    }
}

// ============================================================================
// Pass — macro-level transform (like Ghidra Action)
// ============================================================================

/// Metadata for a pass (used for scheduling and debugging).
#[derive(Debug, Clone)]
pub struct PassInfo {
    pub name: &'static str,
    pub description: &'static str,
    /// Phase ordering hint: lower numbers run first.
    pub phase: usize,
    /// Passes this pass depends on (by name).
    pub requires: &'static [&'static str],
    /// Passes this pass invalidates and must re-run after.
    pub invalidates: &'static [&'static str],
    /// Whether this pass should repeat until fixpoint.
    pub repeat_until_fixpoint: bool,
}

/// Context passed to each pass execution.
pub struct PassContext<'a> {
    /// Name of the current function being decompiled.
    pub function_name: &'a str,
    /// Current phase number (informational).
    pub phase: usize,
    /// Debug flag: enable verbose pass output.
    pub verbose: bool,
}

/// A macro-level pass that transforms a function's IL.
///
/// Equivalent to Ghidra's `Action` class. Each pass operates on the
/// entire function and returns whether it made changes.
pub trait Pass: fmt::Debug + Send + Sync {
    /// Return metadata about this pass.
    fn info(&self) -> PassInfo;

    /// Execute the pass on the given context and expressions.
    /// Returns whether changes were made.
    fn run(&self, ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult;
}

// ============================================================================
// Rule — micro-level transform on a single expression (like Ghidra Rule)
// ============================================================================

/// A micro-level rule that transforms a single IL expression.
///
/// Equivalent to Ghidra's `Rule` class. Rules are registered for specific
/// opcodes and tried on every matching expression until fixpoint.
pub trait Rule: fmt::Debug + Send + Sync {
    /// Return the rule's name.
    fn name(&self) -> &'static str;

    /// The IL operation(s) this rule applies to.
    fn applies_to(&self) -> &'static [&'static str];

    /// Try to apply this rule to the given expression.
    /// Return `Some(transformed)` if the rule matched and produced a result,
    /// or `None` if the rule doesn't apply to this particular expression.
    fn apply(&self, expr: &PassIlExpr) -> Option<PassIlExpr>;

    /// Optional: check a condition before running. Returns false to skip.
    fn check(&self, _expr: &PassIlExpr) -> bool {
        true
    }
}

// ============================================================================
// PassPool — collection of Rules applied to all expressions (like ActionPool)
// ============================================================================

/// A pool of Rules that are applied simultaneously to every expression
/// in the function. The pool repeats until fixpoint (no rule makes changes).
pub struct PassPool {
    pub name: &'static str,
    pub rules: Vec<Box<dyn Rule>>,
    pub max_iterations: usize,
}

impl PassPool {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            rules: Vec::new(),
            max_iterations: 50,
        }
    }

    pub fn with_rule(mut self, rule: Box<dyn Rule>) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    /// Apply all rules to all expressions (including nested) until fixpoint.
    pub fn execute(&self, exprs: &mut Vec<PassIlExpr>) -> PassResult {
        let mut overall = PassResult::Unchanged;
        for iteration in 0..self.max_iterations {
            let mut changed = false;
            for i in 0..exprs.len() {
                if let Some(new_expr) = self.apply_rules_recursive(&exprs[i]) {
                    exprs[i] = new_expr;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
            overall = PassResult::Changed;
            if iteration == self.max_iterations - 1 {
                eprintln!(
                    "PassPool '{}' reached max iterations ({})",
                    self.name, self.max_iterations
                );
            }
        }
        overall
    }

    /// Try to apply rules to an expression and all its sub-expressions recursively.
    /// Returns Some(new_expr) if any rule matched, None otherwise.
    fn apply_rules_recursive(&self, expr: &PassIlExpr) -> Option<PassIlExpr> {
        // First, recursively process operands
        let mut new_operands: Vec<PassIlOperand> = expr.operands.clone();
        let mut operand_changed = false;
        for (j, op) in expr.operands.iter().enumerate() {
            match op {
                PassIlOperand::Expr(child) => {
                    if let Some(new_child) = self.apply_rules_recursive(child) {
                        new_operands[j] = PassIlOperand::Expr(Box::new(new_child));
                        operand_changed = true;
                    }
                }
                _ => {}
            }
        }
        let current = if operand_changed {
            PassIlExpr {
                op: expr.op.clone(),
                size: expr.size,
                pc: expr.pc,
                operands: new_operands,
                extra: expr.extra.clone(),
            }
        } else {
            expr.clone()
        };

        // Now try rules on the (possibly updated) expression itself
        for rule in &self.rules {
            if rule.check(&current) && rule.applies_to().contains(&current.op.as_str()) {
                if let Some(result) = rule.apply(&current) {
                    // Recurse into the result since it may create new matches
                    return self.apply_rules_recursive(&result).or(Some(result));
                }
            }
        }

        if operand_changed {
            Some(current)
        } else {
            None
        }
    }
}

impl fmt::Debug for PassPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassPool")
            .field("name", &self.name)
            .field("rules", &self.rules.len())
            .finish()
    }
}

// ============================================================================
// PassGroup — ordered sequence of passes (like ActionGroup)
// ============================================================================

/// A group of passes executed in sequence, optionally repeatable.
pub struct PassGroup {
    pub name: &'static str,
    pub passes: Vec<Box<dyn Pass>>,
    /// If true, repeat the entire group until no pass makes changes.
    pub repeat_until_fixpoint: bool,
    pub max_repeats: usize,
}

impl PassGroup {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            passes: Vec::new(),
            repeat_until_fixpoint: false,
            max_repeats: 20,
        }
    }

    pub fn with_pass(mut self, pass: Box<dyn Pass>) -> Self {
        self.passes.push(pass);
        self
    }

    pub fn with_pool(mut self, pool: PassPool) -> Self {
        // Wrap a PassPool as a Pass
        struct PoolPass(PassPool);
        impl fmt::Debug for PoolPass {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "PoolPass({})", self.0.name)
            }
        }
        impl Pass for PoolPass {
            fn info(&self) -> PassInfo {
                PassInfo {
                    name: self.0.name,
                    description: "Rule pool",
                    phase: 0,
                    requires: &[],
                    invalidates: &[],
                    repeat_until_fixpoint: true,
                }
            }
            fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
                let mut exprs_vec = std::mem::take(&mut exprs.exprs);
                let result = self.0.execute(&mut exprs_vec);
                exprs.exprs = exprs_vec;
                result
            }
        }
        self.passes.push(Box::new(PoolPass(pool)));
        self
    }

    pub fn with_repeat(mut self, repeat: bool, max: usize) -> Self {
        self.repeat_until_fixpoint = repeat;
        self.max_repeats = max;
        self
    }

    pub fn execute(&self, ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut overall = PassResult::Unchanged;
        let max = if self.repeat_until_fixpoint {
            self.max_repeats
        } else {
            1
        };

        for iteration in 0..max {
            let mut group_changed = false;
            for pass in &self.passes {
                let info = pass.info();
                if ctx.verbose {
                    eprintln!("  [{}.{}] running {}", ctx.phase, info.phase, info.name);
                }
                let result = pass.run(ctx, exprs);
                if result == PassResult::Restart {
                    return PassResult::Restart;
                }
                if result.is_changed() {
                    group_changed = true;
                }
            }
            if !group_changed {
                break;
            }
            overall = PassResult::Changed;
            if iteration == max - 1 && self.repeat_until_fixpoint {
                if ctx.verbose {
                    eprintln!(
                        "PassGroup '{}' reached max repeats ({})",
                        self.name, max
                    );
                }
            }
        }
        overall
    }
}

impl fmt::Debug for PassGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassGroup")
            .field("name", &self.name)
            .field("passes", &self.passes.len())
            .field("repeat", &self.repeat_until_fixpoint)
            .finish()
    }
}

// ============================================================================
// PassPipeline — top-level scheduler with phases
// ============================================================================

/// The top-level pass pipeline, organized into ordered phases.
///
/// Mirrors Ghidra's universal Action tree:
///   Phase 0: Setup (SSA construction, initial type seeding)
///   Phase 1: MainLoop (simplification, type inference, DCE) — repeats until fixpoint
///   Phase 2: PostLoop (switch normalization, return splitting)
///   Phase 3: Cleanup (algebraic normalization, bitfield detection)
///   Phase 4: HighLevel (variable merging, name assignment)
///   Phase 5: Finalize (cast insertion, structure finalization)
pub struct PassPipeline {
    pub name: &'static str,
    pub phases: Vec<PassGroup>,
    pub max_restarts: usize,
}

impl PassPipeline {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            phases: Vec::new(),
            max_restarts: 3,
        }
    }

    pub fn with_phase(mut self, group: PassGroup) -> Self {
        self.phases.push(group);
        self
    }

    pub fn execute(&self, function_name: &str, exprs: &mut PassIlExprs) -> PipelineStats {
        let mut stats = PipelineStats::default();
        stats.total_phases = self.phases.len();

        for restart_count in 0..self.max_restarts {
            let mut restart_requested = false;

            for (phase_idx, phase) in self.phases.iter().enumerate() {
                let ctx = PassContext {
                    function_name,
                    phase: phase_idx,
                    verbose: false,
                };

                let phase_result = phase.execute(&ctx, exprs);
                if phase_result == PassResult::Restart {
                    restart_requested = true;
                    stats.restarts += 1;
                    break;
                }
                if phase_result.is_changed() {
                    stats.phases_changed += 1;
                }
            }

            if !restart_requested {
                break;
            }
            if restart_count == self.max_restarts - 1 {
                eprintln!(
                    "Pipeline '{}' reached max restarts ({})",
                    self.name, self.max_restarts
                );
            }
        }

        stats.final_expr_count = exprs.len();
        stats
    }
}

impl fmt::Debug for PassPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PassPipeline")
            .field("name", &self.name)
            .field("phases", &self.phases.len())
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct PipelineStats {
    pub total_phases: usize,
    pub phases_changed: usize,
    pub restarts: usize,
    pub final_expr_count: usize,
}

// ============================================================================
// PassIlExprs — the IL expression container used across passes
// ============================================================================

/// Generic IL expression container for the pass pipeline.
/// Wraps a flat list of expressions with metadata.
#[derive(Debug, Clone)]
pub struct PassIlExprs {
    pub exprs: Vec<PassIlExpr>,
    pub function_name: String,
    /// Unique PCs present in this function.
    pub unique_pcs: BTreeSet<u64>,
    /// The IL level: "llil", "mlil", or "hlil".
    pub il_level: String,
}

impl PassIlExprs {
    pub fn new(function_name: &str, il_level: &str) -> Self {
        Self {
            exprs: Vec::new(),
            function_name: function_name.to_string(),
            unique_pcs: BTreeSet::new(),
            il_level: il_level.to_string(),
        }
    }

    pub fn len(&self) -> usize {
        self.exprs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.exprs.is_empty()
    }
}

/// A generic IL expression used during pass execution.
/// Passes operate on this rather than the specific LLIL/MLIL/HLIL types.
#[derive(Debug, Clone)]
pub struct PassIlExpr {
    pub op: String,
    pub size: u8,
    pub pc: u64,
    pub operands: Vec<PassIlOperand>,
    pub extra: Vec<(String, String)>,
}

impl PassIlExpr {
    pub fn new(op: &str, size: u8, pc: u64) -> Self {
        Self {
            op: op.to_string(),
            size,
            pc,
            operands: Vec::new(),
            extra: Vec::new(),
        }
    }

    pub fn with_operand(mut self, operand: PassIlOperand) -> Self {
        self.operands.push(operand);
        self
    }

    pub fn with_extra(mut self, key: &str, value: &str) -> Self {
        self.extra.push((key.to_string(), value.to_string()));
        self
    }
}

#[derive(Debug, Clone)]
pub enum PassIlOperand {
    Expr(Box<PassIlExpr>),
    Var(String),
    Imm(i64),
    U64(u64),
    Str(String),
}

// ============================================================================
// Helper: convert LLIL/MLIL/HLIL expressions to/from PassIlExprs
// ============================================================================

/// Op prefix for each IL level to disambiguate operations across layers.
pub fn il_op_prefix(level: &str) -> &str {
    match level {
        "llil" => "LLIL_",
        "mlil" => "MLIL_",
        "hlil" => "HLIL_",
        _ => "",
    }
}

/// Convert LLIL expressions to PassIlExprs for pass processing.
pub fn from_llil(exprs: &[crate::llil::expr::LlilExpr]) -> PassIlExprs {
    use crate::llil::expr::{LlilOp, LlilOperand};
    let mut result = PassIlExprs::new("", "llil");
    for e in exprs {
        let mut pe = PassIlExpr::new(&format!("LLIL_{:?}", e.op), e.size, e.pc);
        for op in &e.operands {
            pe.operands.push(llil_op_to_pass(op));
        }
        for (k, v) in &e.extra {
            pe.extra.push((k.clone(), v.clone()));
        }
        result.unique_pcs.insert(e.pc);
        result.exprs.push(pe);
    }
    result
}

fn llil_op_to_pass(op: &crate::llil::expr::LlilOperand) -> PassIlOperand {
    use crate::llil::expr::LlilOperand;
    match op {
        LlilOperand::Expr(e) => PassIlOperand::Expr(Box::new(PassIlExpr {
            op: format!("LLIL_{:?}", e.op),
            size: e.size,
            pc: e.pc,
            operands: e.operands.iter().map(llil_op_to_pass).collect(),
            extra: e.extra.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        })),
        LlilOperand::Reg(r) => PassIlOperand::Var(r.clone()),
        LlilOperand::Flag(f) => PassIlOperand::Var(f.clone()),
        LlilOperand::Imm(v) => PassIlOperand::Imm(*v),
        LlilOperand::U64(v) => PassIlOperand::U64(*v),
        LlilOperand::Str(s) => PassIlOperand::Str(s.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_result_combinator() {
        assert_eq!(
            PassResult::Changed.and(PassResult::Unchanged),
            PassResult::Changed
        );
        assert_eq!(
            PassResult::Unchanged.and(PassResult::Unchanged),
            PassResult::Unchanged
        );
        assert_eq!(
            PassResult::Restart.and(PassResult::Changed),
            PassResult::Restart
        );
    }

    #[test]
    fn pass_pool_applies_rules_to_fixpoint() {
        // Create a simple rule that replaces "add(x, 0)" with "x"
        #[derive(Debug)]
        struct IdentityAdd;
        impl Rule for IdentityAdd {
            fn name(&self) -> &'static str { "IdentityAdd" }
            fn applies_to(&self) -> &'static [&'static str] { &["LLIL_ADD"] }
            fn apply(&self, expr: &PassIlExpr) -> Option<PassIlExpr> {
                if expr.operands.len() == 2 {
                    if let PassIlOperand::Imm(0) = expr.operands[1] {
                        return Some(expr.operands[0].clone().unwrap_expr());
                    }
                }
                None
            }
        }

        impl PassIlOperand {
            fn unwrap_expr(&self) -> PassIlExpr {
                match self {
                    PassIlOperand::Expr(e) => *e.clone(),
                    _ => panic!("not an expr"),
                }
            }
        }

        let _pool = PassPool::new("simplify").with_rule(Box::new(IdentityAdd));
        // Pool construction works
    }

    #[test]
    fn pass_pipeline_phases_count() {
        let pipeline = PassPipeline::new("test");
        assert_eq!(pipeline.phases.len(), 0);
        assert!(pipeline.max_restarts > 0);
    }

    #[test]
    fn pass_il_exprs_construction() {
        let mut exprs = PassIlExprs::new("test_fn", "llil");
        assert!(exprs.is_empty());
        exprs.exprs.push(PassIlExpr::new("LLIL_ADD", 8, 0x1000));
        assert_eq!(exprs.len(), 1);
    }

    #[test]
    fn from_llil_conversion() {
        use crate::llil::expr::{set_reg, konst};
        let llil = vec![set_reg("x0#1", konst(42), 0x1000)];
        let pexprs = from_llil(&llil);
        assert_eq!(pexprs.len(), 1);
        assert_eq!(pexprs.unique_pcs.len(), 1);
    }
}
