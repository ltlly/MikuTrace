//! Stable variable naming for SSA registers.

use std::collections::BTreeMap;

use crate::llil::expr::{LlilExpr, LlilOperand};
use crate::llil::util::{parse_ssa_reg, set_reg_dst, walk_expr};

pub type VarNameMap = BTreeMap<String, String>;

const ARG_REGS: [&str; 8] = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"];
const CALLEE_SAVED: [&str; 10] = [
    "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
];

pub fn unify_vars(exprs: &[LlilExpr]) -> VarNameMap {
    let mut seen = std::collections::BTreeSet::new();
    for r in ARG_REGS {
        seen.insert(format!("{r}#0"));
    }
    seen.insert("sp#0".to_string());
    seen.insert("fp#0".to_string());
    for root in exprs {
        if let Some(dst) = set_reg_dst(root) {
            seen.insert(dst.to_string());
        }
        let mut nodes = Vec::new();
        walk_expr(root, &mut nodes);
        for node in nodes {
            for op in &node.operands {
                if let LlilOperand::Reg(r) = op {
                    if parse_ssa_reg(r).is_some() {
                        seen.insert(r.clone());
                    }
                }
            }
        }
    }
    seen.into_iter()
        .map(|reg| {
            let name = var_name(&reg);
            (reg, name)
        })
        .collect()
}

fn var_name(reg: &str) -> String {
    let Some((name, version)) = parse_ssa_reg(reg) else {
        return reg.to_string();
    };
    if version == 0 && name == "sp" {
        return "sp".to_string();
    }
    if version == 0 && name == "fp" {
        return "fp".to_string();
    }
    if version == 0 && name == "lr" {
        return "lr".to_string();
    }
    if version == 0 && ARG_REGS.contains(&name) {
        return format!("arg_{}", ARG_REGS.iter().position(|r| *r == name).unwrap());
    }
    if version == 0 && CALLEE_SAVED.contains(&name) {
        return format!("cs_{name}");
    }
    format!("{}_v{}", name, version)
}

#[cfg(test)]
mod tests {
    use crate::llil::expr::{binary, konst, reg, set_reg, LlilOp};

    use super::*;

    #[test]
    fn names_args_and_versions() {
        let exprs = vec![set_reg(
            "x9#1",
            binary(LlilOp::Add, reg("x0#0"), konst(1)),
            0x1000,
        )];
        let names = unify_vars(&exprs);
        assert_eq!(names.get("x0#0").map(String::as_str), Some("arg_0"));
        assert_eq!(names.get("x9#1").map(String::as_str), Some("x9_v1"));
    }
}
