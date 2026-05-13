//! Type inference pass (Ghidra: ActionInferTypes).
//!
//! Infers variable types from usage patterns:
//!   - Used as address in Load/Store → Ptr
//!   - Used in Add/Sub with a known pointer → Ptr
//!   - Only arithmetic → Int
//!   - Zero-extended → Uint
//!   - Sign-extended → Sint
//!
//! Attaches type hints to PassIlExpr.extra["type"] and propagates
//! types forward through SetReg/SetVar assignments.

use std::collections::BTreeMap;

use super::pass::{Pass, PassContext, PassIlExpr, PassIlExprs, PassIlOperand, PassInfo, PassResult};

/// The type kind inferred for a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InferredType {
    Unknown = 0,
    Int = 1,
    Uint = 2,
    Sint = 3,
    Ptr = 4,
}

impl InferredType {
    fn as_str(self) -> &'static str {
        match self {
            InferredType::Unknown => "unknown",
            InferredType::Int => "int",
            InferredType::Uint => "uint",
            InferredType::Sint => "sint",
            InferredType::Ptr => "ptr",
        }
    }

    fn merge(self, other: InferredType) -> InferredType {
        if other as u8 > self as u8 { other } else { self }
    }
}

/// Type propagation pass.
#[derive(Debug)]
pub struct TypePropagationPass;

impl TypePropagationPass {
    fn walk_operand_vars(
        op: &PassIlOperand,
        parent_op: &str,
        operand_idx: usize,
        sibling_ops: &[PassIlOperand],
        cb: &mut dyn FnMut(&str, &str, usize, &[PassIlOperand]),
    ) {
        match op {
            PassIlOperand::Var(name) => { cb(name, parent_op, operand_idx, sibling_ops); }
            PassIlOperand::Expr(e) => {
                for (i, child) in e.operands.iter().enumerate() {
                    Self::walk_operand_vars(child, &e.op, i, &e.operands, cb);
                }
            }
            _ => {}
        }
    }

    fn collect_type_hints(exprs: &[PassIlExpr]) -> BTreeMap<String, InferredType> {
        let mut types: BTreeMap<String, InferredType> = BTreeMap::new();
        for e in exprs {
            let skip_first = matches!(
                e.op.as_str(),
                "LLIL_SetReg" | "MLIL_SetVar" | "HLIL_SetVar"
            );
            for (i, op) in e.operands.iter().enumerate() {
                if skip_first && i == 0 { continue; }
                Self::walk_operand_vars(op, &e.op, i, &e.operands, &mut |var_name, ctx_op, idx, siblings| {
                    let ty = Self::infer_from_context(var_name, ctx_op, idx, siblings, &types);
                    if ty != InferredType::Unknown {
                        let entry = types.entry(var_name.to_string()).or_insert(InferredType::Unknown);
                        *entry = entry.merge(ty);
                    }
                });
            }
        }
        types
    }

    fn infer_from_context(
        _var_name: &str, context_op: &str, operand_idx: usize,
        siblings: &[PassIlOperand], known_types: &BTreeMap<String, InferredType>,
    ) -> InferredType {
        match context_op {
            "LLIL_Load" | "MLIL_Load" | "HLIL_Load" => {
                if operand_idx == 0 { InferredType::Ptr } else { InferredType::Unknown }
            }
            "LLIL_Store" | "MLIL_Store" | "HLIL_Store" => {
                if operand_idx == 0 { InferredType::Ptr } else { InferredType::Unknown }
            }
            "LLIL_Zx" | "MLIL_Zx" | "HLIL_Zx" => {
                if operand_idx == 0 { InferredType::Uint } else { InferredType::Unknown }
            }
            "LLIL_Sx" | "MLIL_Sx" | "HLIL_Sx" => {
                if operand_idx == 0 { InferredType::Sint } else { InferredType::Unknown }
            }
            "LLIL_Add" | "MLIL_Add" | "HLIL_Add"
            | "LLIL_Sub" | "MLIL_Sub" | "HLIL_Sub" => {
                for (si, sib) in siblings.iter().enumerate() {
                    if si == operand_idx { continue; }
                    if let PassIlOperand::Var(name) = sib {
                        if let Some(&InferredType::Ptr) = known_types.get(name) {
                            return InferredType::Ptr;
                        }
                    }
                }
                InferredType::Int
            }
            "LLIL_Mul" | "MLIL_Mul" | "HLIL_Mul"
            | "LLIL_DivS" | "MLIL_DivS" | "LLIL_DivU" | "MLIL_DivU"
            | "LLIL_And" | "MLIL_And" | "HLIL_And"
            | "LLIL_Or" | "MLIL_Or" | "HLIL_Or"
            | "LLIL_Xor" | "MLIL_Xor" | "HLIL_Xor"
            | "LLIL_Neg" | "MLIL_Neg" | "HLIL_Neg"
            | "LLIL_Lsl" | "MLIL_Lsl" | "HLIL_Lsl"
            | "LLIL_Lsr" | "MLIL_Lsr" | "HLIL_Lsr"
            | "LLIL_Asr" | "MLIL_Asr" | "HLIL_Asr"
            | "LLIL_CmpE" | "MLIL_CmpE" | "LLIL_CmpNe" | "MLIL_CmpNe"
            | "LLIL_CmpSlt" | "LLIL_CmpSle" | "LLIL_CmpSgt" | "LLIL_CmpSge"
            | "LLIL_CmpUlt" | "LLIL_CmpUle" | "LLIL_CmpUgt" | "LLIL_CmpUge" => {
                InferredType::Int
            }
            _ => InferredType::Unknown,
        }
    }

    fn propagate_through_assignments(
        exprs: &[PassIlExpr], types: &mut BTreeMap<String, InferredType>,
    ) -> bool {
        let mut changed = false;
        for e in exprs {
            match e.op.as_str() {
                "LLIL_SetReg" | "MLIL_SetVar" | "HLIL_SetVar" => {
                    if e.operands.len() < 2 { continue; }
                    if let PassIlOperand::Var(dest) = &e.operands[0] {
                        let mut src_type = InferredType::Unknown;
                        Self::collect_max_type(&e.operands[1], types, &mut src_type);
                        if src_type != InferredType::Unknown {
                            let entry = types.entry(dest.clone()).or_insert(InferredType::Unknown);
                            if *entry != src_type && src_type as u8 > (*entry) as u8 {
                                *entry = src_type;
                                changed = true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        changed
    }

    fn collect_max_type(op: &PassIlOperand, types: &BTreeMap<String, InferredType>, max_ty: &mut InferredType) {
        match op {
            PassIlOperand::Var(name) => {
                if let Some(&ty) = types.get(name) { *max_ty = max_ty.merge(ty); }
            }
            PassIlOperand::Expr(e) => {
                for child in &e.operands { Self::collect_max_type(child, types, max_ty); }
            }
            _ => {}
        }
    }

    fn annotate_types(exprs: &mut [PassIlExpr], types: &BTreeMap<String, InferredType>) -> bool {
        let mut changed = false;
        for e in exprs.iter_mut() {
            match e.op.as_str() {
                "LLIL_SetReg" | "MLIL_SetVar" | "HLIL_SetVar" => {
                    if e.operands.is_empty() { continue; }
                    if let PassIlOperand::Var(dest) = &e.operands[0] {
                        if let Some(&ty) = types.get(dest) {
                            if ty != InferredType::Unknown {
                                let already = e.extra.iter().any(|(k, v)| k == "type" && v == ty.as_str());
                                if !already {
                                    e.extra.retain(|(k, _)| k != "type");
                                    e.extra.push(("type".to_string(), ty.as_str().to_string()));
                                    changed = true;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        changed
    }
}

impl Pass for TypePropagationPass {
    fn info(&self) -> PassInfo {
        PassInfo {
            name: "TypePropagation",
            description: "Infer variable types (Ptr/Uint/Sint/Int) from usage patterns and propagate forward",
            phase: 1,
            requires: &[],
            invalidates: &[],
            repeat_until_fixpoint: true,
        }
    }

    fn run(&self, _ctx: &PassContext, exprs: &mut PassIlExprs) -> PassResult {
        let mut types = Self::collect_type_hints(&exprs.exprs);
        if types.is_empty() { return PassResult::Unchanged; }
        for _ in 0..10 {
            if !Self::propagate_through_assignments(&exprs.exprs, &mut types) { break; }
        }
        if Self::annotate_types(&mut exprs.exprs, &types) { PassResult::Changed }
        else { PassResult::Unchanged }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::pass::PassIlOperand;

    fn make_expr(op: &str, operands: Vec<PassIlOperand>) -> PassIlExpr {
        PassIlExpr { op: op.to_string(), size: 8, pc: 0x1000, operands, extra: vec![] }
    }
    fn imm(v: i64) -> PassIlOperand { PassIlOperand::Imm(v) }
    fn reg(name: &str) -> PassIlOperand { PassIlOperand::Var(name.to_string()) }

    #[test]
    fn test_infer_ptr_from_load() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(0x1000)]),
            make_expr("LLIL_SetReg", vec![
                reg("x1#1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Load", vec![reg("x0#1")]))),
            ]),
        ];
        let pass = TypePropagationPass;
        let ctx = PassContext { function_name: "test", phase: 1, verbose: false };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let has_ptr = exprs.exprs[0].extra.iter().any(|(k, v)| k == "type" && v == "ptr");
        assert!(has_ptr, "x0#1 should be inferred as ptr");
    }

    #[test]
    fn test_infer_uint_from_zext() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_SetReg", vec![
                reg("x1#1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Zx", vec![reg("x0#1")]))),
            ]),
        ];
        let pass = TypePropagationPass;
        let ctx = PassContext { function_name: "test", phase: 1, verbose: false };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let has_uint = exprs.exprs[0].extra.iter().any(|(k, v)| k == "type" && v == "uint");
        assert!(has_uint, "x0#1 should be inferred as uint");
    }

    #[test]
    fn test_infer_sint_from_sext() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_SetReg", vec![
                reg("x1#1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Sx", vec![reg("x0#1")]))),
            ]),
        ];
        let pass = TypePropagationPass;
        let ctx = PassContext { function_name: "test", phase: 1, verbose: false };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let has_sint = exprs.exprs[0].extra.iter().any(|(k, v)| k == "type" && v == "sint");
        assert!(has_sint, "x0#1 should be inferred as sint");
    }

    #[test]
    fn test_infer_int_from_arithmetic() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(10)]),
            make_expr("LLIL_SetReg", vec![
                reg("x1#1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Add", vec![reg("x0#1"), imm(5)]))),
            ]),
        ];
        let pass = TypePropagationPass;
        let ctx = PassContext { function_name: "test", phase: 1, verbose: false };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let has_int = exprs.exprs[0].extra.iter().any(|(k, v)| k == "type" && v == "int");
        assert!(has_int, "x0#1 should be inferred as int");
    }

    #[test]
    fn test_forward_propagate_type() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![
                reg("x0#1"),
                PassIlOperand::Expr(Box::new(make_expr("LLIL_Load", vec![reg("x1#1")]))),
            ]),
            make_expr("LLIL_SetReg", vec![reg("x2#1"), reg("x1#1")]),
        ];
        let pass = TypePropagationPass;
        let ctx = PassContext { function_name: "test", phase: 1, verbose: false };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let has_ptr = exprs.exprs[1].extra.iter().any(|(k, v)| k == "type" && v == "ptr");
        assert!(has_ptr, "x2#1 should inherit ptr type");
    }

    #[test]
    fn test_no_inference_for_unused() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(42)]),
            make_expr("LLIL_Ret", vec![reg("x0#1")]),
        ];
        let pass = TypePropagationPass;
        let ctx = PassContext { function_name: "test", phase: 1, verbose: false };
        let result = pass.run(&ctx, &mut exprs);
        assert!(!result.is_changed());
    }

    #[test]
    fn test_store_address_is_ptr() {
        let mut exprs = PassIlExprs::new("test", "llil");
        exprs.exprs = vec![
            make_expr("LLIL_SetReg", vec![reg("x0#1"), imm(0x2000)]),
            make_expr("LLIL_Store", vec![reg("x0#1"), imm(42)]),
        ];
        let pass = TypePropagationPass;
        let ctx = PassContext { function_name: "test", phase: 1, verbose: false };
        let result = pass.run(&ctx, &mut exprs);
        assert!(result.is_changed());
        let has_ptr = exprs.exprs[0].extra.iter().any(|(k, v)| k == "type" && v == "ptr");
        assert!(has_ptr);
    }
}
