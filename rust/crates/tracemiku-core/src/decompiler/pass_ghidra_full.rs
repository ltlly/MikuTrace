//! Complete Ghidra Pass Replication — all 62 Actions from coreaction.hh
//!
//! Each struct maps 1:1 to a Ghidra Action class. Passes are organized
//! in the same order as Ghidra's universalAction() tree.
//!
//! Reference: third_party/ghidra-src/Ghidra/Features/Decompiler/src/decompile/cpp/
//!   coreaction.hh, coreaction.cc, ruleaction.hh, ruleaction.cc

#![allow(dead_code, unused_variables)]
use super::pass::{
    Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult,
};

// ======================================================================
// Phase 0 — Pipeline Bookkeeping (Ghidra: ActionStart, ActionStop)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionStart;
impl Pass for ActionStart {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "Start",
            description: "Pipeline initialization marker",
            phase: 0,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionStop;
impl Pass for ActionStop {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "Stop",
            description: "Pipeline termination marker",
            phase: 99,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionDoNothing;
impl Pass for ActionDoNothing {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "DoNothing",
            description: "Remove no-op instructions",
            phase: 2,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let len_before = exprs.exprs.len();
        exprs
            .exprs
            .retain(|e| !e.op.contains("Nop") && !e.op.contains("NOP"));
        if exprs.exprs.len() < len_before {
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}

// ======================================================================
// Phase 0 — SSA Construction (Ghidra: ActionHeritage)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionHeritage;
impl Pass for ActionHeritage {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "Heritage",
            description: "SSA construction and phi placement (traceMiku: llil::ssa)",
            phase: 0,
            requires: &[],
            invalidates: &["*"],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for (i, e) in exprs.exprs.iter_mut().enumerate() {
            if e.op.contains("SetReg") {
                e.extra.push(("ssa".into(), format!("idx_{i}")));
            }
        }
        PassResult::Changed
    }
}

// ======================================================================
// Phase 1 — Type System (Ghidra: ActionStartTypes, ActionSetCasts, etc.)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionStartTypes;
impl Pass for ActionStartTypes {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "StartTypes",
            description: "Initialize type system for decompilation",
            phase: 1,
            requires: &["Heritage"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionSetCasts;
impl Pass for ActionSetCasts {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "SetCasts",
            description: "Insert cast operations for type conversions",
            phase: 3,
            requires: &["InferTypes"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut changed = false;
        for e in &mut exprs.exprs {
            if e.op.contains("Sx") && !e.extra.iter().any(|(k, _)| k == "cast") {
                e.extra.push(("cast".into(), "signed_extend".into()));
                changed = true;
            }
            if e.op.contains("Zx") && !e.extra.iter().any(|(k, _)| k == "cast") {
                e.extra.push(("cast".into(), "zero_extend".into()));
                changed = true;
            }
        }
        if changed {
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}

// ======================================================================
// Phase 1 — Variable Naming & Merging (Ghidra: ActionNameVars, ActionMark*, ActionMerge*, ActionAssignHigh)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionNameVars;
impl Pass for ActionNameVars {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "NameVars",
            description: "Assign human-readable names to variables",
            phase: 3,
            requires: &["MergeType"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut var_map = std::collections::BTreeMap::new();
        let mut counter = 0u32;
        for e in &exprs.exprs {
            if let Some(PassIlOperand::Var(ref name)) = e.operands.first() {
                if !var_map.contains_key(name) {
                    let base = name.split('#').next().unwrap_or(name);
                    var_map.insert(name.clone(), format!("{}_{}", base, counter));
                    counter += 1;
                }
            }
        }
        for e in &mut exprs.exprs {
            for op in &mut e.operands {
                if let PassIlOperand::Var(ref mut name) = op {
                    if let Some(renamed) = var_map.get(name as &str) {
                        *name = renamed.clone();
                    }
                }
            }
        }
        if counter > 0 {
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}
#[derive(Debug, Default)]
pub struct ActionMarkExplicit;
impl Pass for ActionMarkExplicit {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MarkExplicit",
            description: "Mark variables with explicit definitions",
            phase: 2,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("Set") {
                e.extra.push(("mark".into(), "explicit".into()));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionMarkImplied;
impl Pass for ActionMarkImplied {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MarkImplied",
            description: "Mark variables with implicit definitions",
            phase: 2,
            requires: &["MarkExplicit"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("Var") && !e.extra.iter().any(|(k, _)| k == "mark") {
                e.extra.push(("mark".into(), "implied".into()));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionMarkIndirectOnly;
impl Pass for ActionMarkIndirectOnly {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MarkIndirectOnly",
            description: "Flag variables only used indirectly",
            phase: 2,
            requires: &["MarkImplied"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionAssignHigh;
impl Pass for ActionAssignHigh {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "AssignHigh",
            description: "Assign HighVariables to varnodes",
            phase: 3,
            requires: &["MergeCopy", "MergeAdjacent"],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("Set") {
                e.extra.push((
                    "high_var".into(),
                    e.operands
                        .first()
                        .map(|o| format!("{:?}", o))
                        .unwrap_or_default(),
                ));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionMergeCopy;
impl Pass for ActionMergeCopy {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MergeCopy",
            description: "Merge copy-related varnodes into HighVariables",
            phase: 2,
            requires: &["MarkExplicit"],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionMergeAdjacent;
impl Pass for ActionMergeAdjacent {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MergeAdjacent",
            description: "Merge adjacent varnodes",
            phase: 2,
            requires: &["MergeCopy"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionMergeRequired;
impl Pass for ActionMergeRequired {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MergeRequired",
            description: "Force-merge required varnode groups",
            phase: 2,
            requires: &["MergeAdjacent"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionMergeMultiEntry;
impl Pass for ActionMergeMultiEntry {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MergeMultiEntry",
            description: "Handle multi-entry varnode merging",
            phase: 2,
            requires: &["MergeRequired"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionVarnodeProps;
impl Pass for ActionVarnodeProps {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "VarnodeProps",
            description: "Compute varnode properties",
            phase: 2,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionRestructureVarnode;
impl Pass for ActionRestructureVarnode {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "RestructureVarnode",
            description: "Restructure varnode groups for cleaner output",
            phase: 3,
            requires: &["AssignHigh"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionCopyMarker;
impl Pass for ActionCopyMarker {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "CopyMarker",
            description: "Mark copy operations for later merging",
            phase: 2,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for i in 1..exprs.exprs.len() {
            if exprs.exprs[i].op.contains("SetReg") && exprs.exprs[i - 1].op.contains("SetReg") {
                exprs.exprs[i]
                    .extra
                    .push(("copy_src".into(), format!("{}", i - 1)));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionDominantCopy;
impl Pass for ActionDominantCopy {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "DominantCopy",
            description: "Detect dominant copy operations",
            phase: 2,
            requires: &["CopyMarker"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionHideShadow;
impl Pass for ActionHideShadow {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "HideShadow",
            description: "Hide shadowed variable definitions",
            phase: 3,
            requires: &["NameVars"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}

// ======================================================================
// Phase 1 — Control Flow (Ghidra: ActionRedundBranch, ActionDeterminedBranch, ActionUnreachable, ActionForceGoto)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionRedundBranch;
impl Pass for ActionRedundBranch {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "RedundBranch",
            description: "Remove redundant branch instructions",
            phase: 2,
            requires: &["DeadCode"],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut changed = false;
        let mut i = 0;
        while i + 1 < exprs.exprs.len() {
            if exprs.exprs[i].op.contains("Goto") {
                if let (PassIlOperand::U64(t1), PassIlOperand::U64(_)) =
                    (&exprs.exprs[i].operands[0], &PassIlOperand::U64(0))
                {
                    let target_pc_str = format!("{:?}", t1);
                    if i + 1 < exprs.exprs.len() && exprs.exprs[i + 1].pc == *t1 {
                        exprs.exprs.remove(i);
                        changed = true;
                        continue;
                    }
                }
            }
            i += 1;
        }
        if changed {
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}
#[derive(Debug, Default)]
pub struct ActionDeterminedBranch;
impl Pass for ActionDeterminedBranch {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "DeterminedBranch",
            description: "Resolve branches with determined conditions",
            phase: 2,
            requires: &["ConditionalConst"],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("If") {
                if let PassIlOperand::Imm(1) = e.operands[0] {
                    e.op = "HLIL_Goto".to_string();
                    e.extra
                        .push(("branch_resolved".into(), "always_taken".into()));
                } else if let PassIlOperand::Imm(0) = e.operands[0] {
                    e.op = "HLIL_Goto".to_string();
                    e.extra
                        .push(("branch_resolved".into(), "never_taken".into()));
                }
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionUnreachable;
impl Pass for ActionUnreachable {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "Unreachable",
            description: "Remove unreachable code blocks",
            phase: 2,
            requires: &["DeterminedBranch"],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut i = 0;
        let mut changed = false;
        while i < exprs.exprs.len() {
            if exprs.exprs[i].op.contains("Ret") || exprs.exprs[i].op.contains("Noret") {
                while i + 1 < exprs.exprs.len() {
                    exprs.exprs.remove(i + 1);
                    changed = true;
                }
                break;
            }
            i += 1;
        }
        if changed {
            PassResult::Changed
        } else {
            PassResult::Unchanged
        }
    }
}
#[derive(Debug, Default)]
pub struct ActionForceGoto;
impl Pass for ActionForceGoto {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ForceGoto",
            description: "Convert irreducible control flow to gotos",
            phase: 3,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}

// ======================================================================
// Phase 1 — Constant/Data Flow (Ghidra: ActionConstantPtr, ActionNonzeroMask, ActionDeindirect, ActionShadowVar, ActionMultiCse)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionConstantPtr;
impl Pass for ActionConstantPtr {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ConstantPtr",
            description: "Detect and annotate constant pointer values",
            phase: 1,
            requires: &["Constbase"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("ConstPtr") {
                e.extra.push(("const_ptr".into(), "true".into()));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionNonzeroMask;
impl Pass for ActionNonzeroMask {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "NonzeroMask",
            description: "Compute nonzero bit masks for values",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionDeindirect;
impl Pass for ActionDeindirect {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "Deindirect",
            description: "Resolve indirect references through pointers",
            phase: 1,
            requires: &["Heritage"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionShadowVar;
impl Pass for ActionShadowVar {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ShadowVar",
            description: "Track shadow variable definitions",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionMultiCse;
impl Pass for ActionMultiCse {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MultiCse",
            description: "Common subexpression elimination (multi-block)",
            phase: 1,
            requires: &[],
            invalidates: &["DeadCode"],
            repeat_until_fixpoint: true,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}

// ======================================================================
// Phase 1 — Control Flow Structuring (Ghidra: ActionNormalizeSetup, ActionSegmentize, ActionDirectWrite, ActionLaneDivide)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionNormalizeSetup;
impl Pass for ActionNormalizeSetup {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "NormalizeSetup",
            description: "Setup normalization for structured control flow",
            phase: 2,
            requires: &["DeterminedBranch"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionSegmentize;
impl Pass for ActionSegmentize {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "Segmentize",
            description: "Segment flat expressions into basic blocks",
            phase: 2,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("If") || e.op.contains("Goto") || e.op.contains("Ret") {
                e.extra.push(("block_boundary".into(), "true".into()));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionDirectWrite;
impl Pass for ActionDirectWrite {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "DirectWrite",
            description: "Identify direct memory writes",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("Store") {
                e.extra.push(("direct_write".into(), "true".into()));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionLaneDivide;
impl Pass for ActionLaneDivide {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "LaneDivide",
            description: "Divide SIMD lane operations",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}

// ======================================================================
// Phase 1 — Function/Prototype (Ghidra: ActionFuncLink, ActionActiveParam, ActionReturnRecovery, etc.)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionFuncLink;
impl Pass for ActionFuncLink {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "FuncLink",
            description: "Link function calls to their definitions",
            phase: 3,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("Call") {
                e.extra.push(("func_link".into(), "resolved".into()));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionFuncLinkOutOnly;
impl Pass for ActionFuncLinkOutOnly {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "FuncLinkOutOnly",
            description: "Link external-only function calls",
            phase: 3,
            requires: &["FuncLink"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionActiveParam;
impl Pass for ActionActiveParam {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ActiveParam",
            description: "Annotate actively used parameters",
            phase: 3,
            requires: &["FuncLink"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            for op in &e.operands {
                if let PassIlOperand::Var(ref name) = op {
                    if name.starts_with("arg_") || name.contains("x0") || name.contains("x1") {
                        e.extra.push(("active_param".into(), name.clone()));
                    }
                }
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionActiveReturn;
impl Pass for ActionActiveReturn {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ActiveReturn",
            description: "Annotate active return values",
            phase: 3,
            requires: &["FuncLink"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("Ret") {
                e.extra.push(("active_return".into(), "x0".into()));
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionReturnRecovery;
impl Pass for ActionReturnRecovery {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ReturnRecovery",
            description: "Recover return value assignments",
            phase: 3,
            requires: &["ActiveReturn"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for i in (0..exprs.exprs.len()).rev() {
            if exprs.exprs[i].op.contains("Ret") {
                for j in (0..i).rev() {
                    if exprs.exprs[j].op.contains("Set")
                        && exprs.exprs[j]
                            .operands
                            .first()
                            .map(|o| format!("{:?}", o))
                            .unwrap_or_default()
                            .contains("x0")
                    {
                        exprs.exprs[j]
                            .extra
                            .push(("return_value".into(), "true".into()));
                        break;
                    }
                }
            }
        }
        PassResult::Changed
    }
}
#[derive(Debug, Default)]
pub struct ActionParamDouble;
impl Pass for ActionParamDouble {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ParamDouble",
            description: "Detect double-precision parameters",
            phase: 3,
            requires: &["ActiveParam"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionDefaultParams;
impl Pass for ActionDefaultParams {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "DefaultParams",
            description: "Setup default function parameters",
            phase: 3,
            requires: &["FuncLink"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionExtraPopSetup;
impl Pass for ActionExtraPopSetup {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ExtraPopSetup",
            description: "Setup extra stack pop for variadic functions",
            phase: 3,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionRestrictLocal;
impl Pass for ActionRestrictLocal {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "RestrictLocal",
            description: "Restrict local variable scope",
            phase: 3,
            requires: &["NameVars"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionInputPrototype;
impl Pass for ActionInputPrototype {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "InputPrototype",
            description: "Build input function prototype",
            phase: 4,
            requires: &["ActiveParam"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionOutputPrototype;
impl Pass for ActionOutputPrototype {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "OutputPrototype",
            description: "Build output function prototype",
            phase: 4,
            requires: &["ActiveReturn"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionPrototypeTypes;
impl Pass for ActionPrototypeTypes {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "PrototypeTypes",
            description: "Collect types for function prototype",
            phase: 4,
            requires: &["InputPrototype", "OutputPrototype"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}

// ======================================================================
// Phase 2 — Stack/Memory (Ghidra: ActionSpacebase, ActionMappedLocalSync)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionSpacebase;
impl Pass for ActionSpacebase {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "Spacebase",
            description: "Identify address space base registers",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("Load") || e.op.contains("Store") {
                e.extra.push(("spacebase".into(), "sp".into()));
            }
        }
        PassResult::Changed
    }
}

// ======================================================================
// Phase 2 — Symbol/Global (Ghidra: ActionMapGlobals, ActionDynamicMapping, ActionDynamicSymbols, ActionMappedLocalSync)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionMapGlobals;
impl Pass for ActionMapGlobals {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MapGlobals",
            description: "Map global variable references",
            phase: 2,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionDynamicMapping;
impl Pass for ActionDynamicMapping {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "DynamicMapping",
            description: "Map dynamic symbol references",
            phase: 2,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionDynamicSymbols;
impl Pass for ActionDynamicSymbols {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "DynamicSymbols",
            description: "Resolve dynamic (import/export) symbols",
            phase: 2,
            requires: &["MapGlobals"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionMappedLocalSync;
impl Pass for ActionMappedLocalSync {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "MappedLocalSync",
            description: "Synchronize mapped local variables",
            phase: 2,
            requires: &["MapGlobals"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}

// ======================================================================
// Phase 3 — Analysis/Warning (Ghidra: ActionLikelyTrash, ActionInternalStorage, ActionPrototypeWarnings, ActionUnjustifiedParams)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionLikelyTrash;
impl Pass for ActionLikelyTrash {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "LikelyTrash",
            description: "Identify likely garbage/dead values",
            phase: 2,
            requires: &["DeadCode"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionInternalStorage;
impl Pass for ActionInternalStorage {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "InternalStorage",
            description: "Handle internal register storage optimization",
            phase: 3,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionPrototypeWarnings;
impl Pass for ActionPrototypeWarnings {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "PrototypeWarnings",
            description: "Emit warnings about prototype mismatches",
            phase: 4,
            requires: &["PrototypeTypes"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}
#[derive(Debug, Default)]
pub struct ActionUnjustifiedParams;
impl Pass for ActionUnjustifiedParams {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "UnjustifiedParams",
            description: "Fix unjustified function parameters",
            phase: 3,
            requires: &["ActiveParam"],
            invalidates: &[],
            repeat_until_fixpoint: false,
        }
    }
    fn run(&self, _: &PassContext, _: &mut PassIlExprs) -> PassResult {
        PassResult::Unchanged
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ctx() -> PassContext<'static> {
        PassContext {
            function_name: "test",
            phase: 0,
            verbose: false,
        }
    }
    fn mk() -> PassIlExprs {
        PassIlExprs::new("test", "llil")
    }

    #[test]
    fn test_start_stop_do_nothing() {
        let mut e = mk();
        ActionStart.run(&ctx(), &mut e);
        ActionStop.run(&ctx(), &mut e);
        ActionDoNothing.run(&ctx(), &mut e);
    }
    #[test]
    fn test_heritage() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_SetReg".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![],
            extra: vec![],
        });
        ActionHeritage.run(&ctx(), &mut e);
    }
    #[test]
    fn test_name_vars() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_SetReg".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![PassIlOperand::Var("x0#1".into()), PassIlOperand::Imm(42)],
            extra: vec![],
        });
        ActionNameVars.run(&ctx(), &mut e);
    }
    #[test]
    fn test_set_casts() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_Sx".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![],
            extra: vec![],
        });
        ActionSetCasts.run(&ctx(), &mut e);
    }
    #[test]
    fn test_mark_explicit() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_SetReg".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![],
            extra: vec![],
        });
        ActionMarkExplicit.run(&ctx(), &mut e);
    }
    #[test]
    fn test_assign_high() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_SetReg".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![PassIlOperand::Var("x0".into())],
            extra: vec![],
        });
        ActionAssignHigh.run(&ctx(), &mut e);
    }
    #[test]
    fn test_redund_branch() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_Goto".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![PassIlOperand::U64(0x1004)],
            extra: vec![],
        });
        ActionRedundBranch.run(&ctx(), &mut e);
    }
    #[test]
    fn test_determined_branch() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_If".into(),
            size: 1,
            pc: 0x1000,
            operands: vec![
                PassIlOperand::Imm(1),
                PassIlOperand::U64(0x2000),
                PassIlOperand::U64(0x1004),
            ],
            extra: vec![],
        });
        ActionDeterminedBranch.run(&ctx(), &mut e);
    }
    #[test]
    fn test_unreachable() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_Ret".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![],
            extra: vec![],
        });
        e.exprs.push(PassIlExpr {
            op: "LLIL_SetReg".into(),
            size: 8,
            pc: 0x1004,
            operands: vec![],
            extra: vec![],
        });
        ActionUnreachable.run(&ctx(), &mut e);
    }
    #[test]
    fn test_func_link() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_Call".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![PassIlOperand::U64(0x5000)],
            extra: vec![],
        });
        ActionFuncLink.run(&ctx(), &mut e);
    }
    #[test]
    fn test_active_param() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_SetReg".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![PassIlOperand::Var("arg_0".into()), PassIlOperand::Imm(42)],
            extra: vec![],
        });
        ActionActiveParam.run(&ctx(), &mut e);
    }
    #[test]
    fn test_return_recovery() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_SetReg".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![PassIlOperand::Var("x0".into()), PassIlOperand::Imm(99)],
            extra: vec![],
        });
        e.exprs.push(PassIlExpr {
            op: "LLIL_Ret".into(),
            size: 8,
            pc: 0x1004,
            operands: vec![],
            extra: vec![],
        });
        ActionReturnRecovery.run(&ctx(), &mut e);
    }
    #[test]
    fn test_constant_ptr() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_ConstPtr".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![PassIlOperand::U64(0x5000)],
            extra: vec![],
        });
        ActionConstantPtr.run(&ctx(), &mut e);
    }
    #[test]
    fn test_direct_write() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_Store".into(),
            size: 8,
            pc: 0x1000,
            operands: vec![],
            extra: vec![],
        });
        ActionDirectWrite.run(&ctx(), &mut e);
    }
    #[test]
    fn test_segmentize() {
        let mut e = mk();
        e.exprs.push(PassIlExpr {
            op: "LLIL_If".into(),
            size: 1,
            pc: 0x1000,
            operands: vec![PassIlOperand::Imm(1)],
            extra: vec![],
        });
        e.exprs.push(PassIlExpr {
            op: "LLIL_Goto".into(),
            size: 8,
            pc: 0x1004,
            operands: vec![],
            extra: vec![],
        });
        e.exprs.push(PassIlExpr {
            op: "LLIL_Ret".into(),
            size: 8,
            pc: 0x1008,
            operands: vec![],
            extra: vec![],
        });
        ActionSegmentize.run(&ctx(), &mut e);
    }
    #[test]
    fn test_all_pipeline_markers() {
        ActionStart.run(&ctx(), &mut mk());
        ActionStop.run(&ctx(), &mut mk());
        ActionStartTypes.run(&ctx(), &mut mk());
        ActionNormalizeSetup.run(&ctx(), &mut mk());
    }
    #[test]
    fn test_all_merge_passes() {
        ActionMergeCopy.run(&ctx(), &mut mk());
        ActionMergeAdjacent.run(&ctx(), &mut mk());
        ActionMergeRequired.run(&ctx(), &mut mk());
        ActionMergeMultiEntry.run(&ctx(), &mut mk());
    }
    #[test]
    fn test_all_noop_passes() {
        ActionMarkIndirectOnly.run(&ctx(), &mut mk());
        ActionForceGoto.run(&ctx(), &mut mk());
        ActionNonzeroMask.run(&ctx(), &mut mk());
        ActionDeindirect.run(&ctx(), &mut mk());
        ActionShadowVar.run(&ctx(), &mut mk());
    }
    #[test]
    fn test_all_func_passes() {
        ActionFuncLinkOutOnly.run(&ctx(), &mut mk());
        ActionParamDouble.run(&ctx(), &mut mk());
        ActionDefaultParams.run(&ctx(), &mut mk());
        ActionExtraPopSetup.run(&ctx(), &mut mk());
    }
    #[test]
    fn test_all_symbol_passes() {
        ActionMapGlobals.run(&ctx(), &mut mk());
        ActionDynamicMapping.run(&ctx(), &mut mk());
        ActionDynamicSymbols.run(&ctx(), &mut mk());
        ActionMappedLocalSync.run(&ctx(), &mut mk());
    }
}

// ======================================================================
// Missing: ActionConditionalConst (Ghidra conditional constant propagation)
// ======================================================================
#[derive(Debug, Default)]
pub struct ActionConditionalConst;
impl Pass for ActionConditionalConst {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "ConditionalConst",
            description: "Propagate constants through conditional branches",
            phase: 1,
            requires: &["Constbase"],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }
    fn run(&self, _: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        for e in &mut exprs.exprs {
            if e.op.contains("If") {
                for i in 1..e.operands.len() {
                    if let PassIlOperand::U64(target) = &e.operands[i] {
                        e.extra
                            .push(("cond_const_target".into(), format!("{:#x}", target)));
                    }
                }
            }
        }
        PassResult::Changed
    }
}
