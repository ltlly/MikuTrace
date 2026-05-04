//! TraceIR — LLM-friendly skeleton intermediate representation.
//!
//! Direct port of `viewer/decompiler/ir.py`. Pure data carriers (no
//! analysis methods beyond `TopIR::fn_by_id`).
//!
//! Layer: TopIR ⊃ FuncIR[] ⊃ {BlockIR[], LoopIR[], CallIR[]}.
//! Stable IDs: F0/F1/... B0/B1/... L0/L1/...

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// One basic block. PC is absolute runtime address (matches trace).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockIR {
    pub id: String,
    pub pc: u64,
    pub end_pc: u64,
    pub insns: u32,
    pub exec_count: u64,
    #[serde(default)]
    pub exits: Vec<EdgeIR>,
    #[serde(default)]
    pub samples: HashMap<String, i64>,
    #[serde(default)]
    pub asm: String,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none", default)]
    pub ref_id: Option<String>,
    #[serde(default)]
    pub tier: String,
}

impl Default for BlockIR {
    fn default() -> Self {
        Self {
            id: String::new(),
            pc: 0,
            end_pc: 0,
            insns: 0,
            exec_count: 0,
            exits: Vec::new(),
            samples: HashMap::new(),
            asm: String::new(),
            ref_id: None,
            tier: "hot".to_string(),
        }
    }
}

/// One CFG edge.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EdgeIR {
    pub dst: String,
    pub kind: String,
    #[serde(default)]
    pub taken_count: u64,
    #[serde(default)]
    pub not_taken_count: u64,
}

/// One induction var candidate (DEC3-C).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InductionVarIR {
    pub reg: String,
    pub init: i64,
    #[serde(rename = "final")]
    pub final_value: i64,
    pub step: f64,
    pub n_iters: u64,
    pub classification: String,
    pub linearity_score: f64,
    #[serde(default)]
    pub samples: Vec<i64>,
}

/// One loop (SCC of size>1 or size=1 self-loop).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoopIR {
    pub id: String,
    pub header: String,
    pub body: Vec<String>,
    pub iters: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub induction_var: Option<serde_json::Value>,
    #[serde(default)]
    pub induction_vars: Vec<InductionVarIR>,
}

/// One bl/blr call event observed in trace.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CallIR {
    pub idx: usize,
    pub src_block: String,
    pub callee_pc: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub callee_fn: Option<String>,
    #[serde(default)]
    pub callee_name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ret_idx: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ret_val_x0: Option<i64>,
}

/// One type anchor at a specific bl idx (DEC3-B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeAnchorIR {
    pub idx: usize,
    pub callee_pc: u64,
    pub callee_name: String,
    #[serde(default)]
    pub params: Vec<(String, String)>,
    #[serde(default)]
    pub ret_reg: String,
    #[serde(default)]
    pub ret_type: String,
    #[serde(default)]
    pub provenance: String,
}

impl Default for TypeAnchorIR {
    fn default() -> Self {
        Self {
            idx: 0,
            callee_pc: 0,
            callee_name: String::new(),
            params: Vec::new(),
            ret_reg: "x0".to_string(),
            ret_type: String::new(),
            provenance: String::new(),
        }
    }
}

/// One function. MVP: split by calltree; without BN, name='?'.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncIR {
    pub id: String,
    pub name: String,
    pub pc_start: u64,
    pub pc_end: u64,
    pub entry_idx: usize,
    pub exit_idx: usize,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub last_insn_is_ret: bool,
    #[serde(default)]
    pub blocks: Vec<BlockIR>,
    #[serde(default)]
    pub loops: Vec<LoopIR>,
    #[serde(default)]
    pub calls: Vec<CallIR>,
    #[serde(rename = "static", skip_serializing_if = "Option::is_none", default)]
    pub static_info: Option<serde_json::Value>,
    #[serde(default)]
    pub exec_count: u64,
    #[serde(default)]
    pub type_anchors: Vec<TypeAnchorIR>,
}

impl Default for FuncIR {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            pc_start: 0,
            pc_end: 0,
            entry_idx: 0,
            exit_idx: 0,
            truncated: false,
            last_insn_is_ret: false,
            blocks: Vec::new(),
            loops: Vec::new(),
            calls: Vec::new(),
            static_info: None,
            exec_count: 1,
            type_anchors: Vec::new(),
        }
    }
}

/// One VM dispatcher candidate region (DEC3-D).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VmCandidateIR {
    pub dispatcher_pc: u64,
    pub confidence: f64,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub reader_pc: u64,
    #[serde(default)]
    pub reader_inst: String,
    #[serde(default)]
    pub reader_hits: u64,
    #[serde(default)]
    pub reader_base_reg: String,
    #[serde(default)]
    pub bytecode_addr: u64,
    #[serde(default)]
    pub bytecode_len: u64,
    #[serde(default)]
    pub hex_dump: Vec<String>,
}

/// Top-level trace IR — summary level.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TopIR {
    pub records: u64,
    pub truncated: bool,
    pub last_insn_is_ret: bool,
    #[serde(default)]
    pub module_name: String,
    #[serde(default)]
    pub module_base: u64,
    #[serde(default)]
    pub module_size: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cmd: Option<i64>,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub fns: Vec<FuncIR>,
    #[serde(default)]
    pub vm_candidates: Vec<VmCandidateIR>,
    #[serde(default)]
    pub tracemiku_version: String,
    #[serde(default)]
    pub generated_at: String,
}

impl TopIR {
    pub fn fn_by_id(&self, fn_id: &str) -> Option<&FuncIR> {
        self.fns.iter().find(|f| f.id == fn_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topir_fn_by_id_finds_the_funcir() {
        let mut top = TopIR::default();
        top.fns.push(FuncIR {
            id: "F0".to_string(),
            name: "root".to_string(),
            ..Default::default()
        });
        top.fns.push(FuncIR {
            id: "F1".to_string(),
            name: "alpha".to_string(),
            ..Default::default()
        });
        let f = top.fn_by_id("F1").unwrap();
        assert_eq!(f.name, "alpha");
        assert!(top.fn_by_id("F2").is_none());
    }

    #[test]
    fn block_ir_ref_field_serializes_as_ref_when_set() {
        let blk = BlockIR {
            id: "B0".to_string(),
            ref_id: Some("B5".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&blk).unwrap();
        assert!(json.contains(r#""ref":"B5""#), "got {json}");
    }

    #[test]
    fn block_ir_ref_field_omitted_when_none() {
        let blk = BlockIR {
            id: "B0".to_string(),
            ref_id: None,
            ..Default::default()
        };
        let json = serde_json::to_string(&blk).unwrap();
        assert!(
            !json.contains(r#""ref""#),
            "ref must be omitted when None: {json}"
        );
    }
}
