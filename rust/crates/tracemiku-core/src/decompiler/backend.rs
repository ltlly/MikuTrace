//! Decompiler backend abstraction. Port of viewer/decompiler/backend.py.
//!
//! M3-δ ships the trait + NoneBackend stub. Real backends (binja, ghidra)
//! land in later milestones — they need PyO3 / sidecar plumbing that is
//! out of scope for the v2 trace-side rewrite.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Function {
    pub start: u64,
    pub end: u64,
    pub name: String,
    pub backend: String,
    // Python carries a backend-specific `raw` handle. Rust uses a separate
    // trait method to fetch the handle when needed.
}

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub cls: String,
    pub addr: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct HlilLine {
    pub text: String,
    pub pc_lo: u64,
    pub pc_hi: u64,
    pub indent: u32,
    pub tokens: Vec<Token>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CfgBlock {
    pub start: u64,
    pub end: u64,
    pub lines: Vec<HlilLine>,
    pub exec_count: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct CfgEdge {
    pub src: u64,
    pub dst: u64,
    pub kind: String,
    pub seen_in_trace: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct FieldHint {
    /// Renamed from Python's `struct` — Rust keyword. Wire format keeps
    /// the field unrenamed for now since no FieldHint endpoint exists yet
    /// (M5+ wires this). When the wire becomes a contract, add
    /// #[serde(rename = "struct")].
    pub struct_name: String,
    pub field: String,
    pub offset: i64,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct VarType {
    pub name: String,
    pub type_name: String,
    pub storage: String,
}

/// Decompiler backend protocol — port of viewer/decompiler/backend.py:98.
///
/// Hot-path queries should be < 50ms after open(). NoneBackend (the M3-δ
/// stub impl) returns trivial defaults — placeholder until M5+ wires
/// real BN/Ghidra backends.
pub trait Backend: Send + Sync {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn open(&mut self, so_path: &str, base: u64) -> anyhow::Result<()>;
    fn close(&mut self);
    fn loaded_base(&self) -> u64;
    fn function_at(&self, pc: u64) -> Option<Function>;
    fn hlil_for(&self, fn_: &Function) -> Vec<HlilLine>;
    fn vars_for(&self, fn_: &Function) -> Vec<VarType>;
    fn field_at(&self, pc: u64, reg: &str, offset: i64) -> Option<FieldHint>;
    fn xrefs_to(&self, addr: u64) -> Vec<u64>;
    fn cfg_for(&self, fn_: &Function, mode: &str) -> (Vec<CfgBlock>, Vec<CfgEdge>);
    fn asm_tokens_at(&self, pc: u64) -> Option<Vec<Token>>;
}

/// Stub backend — placeholder when no real decompiler is available.
/// All queries return None / Default. Useful for tests and the
/// no-binja-installed code path.
#[derive(Debug, Default)]
pub struct NoneBackend;

impl NoneBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Backend for NoneBackend {
    fn name(&self) -> &str {
        "none"
    }
    fn is_available(&self) -> bool {
        true
    }
    fn open(&mut self, _so_path: &str, _base: u64) -> anyhow::Result<()> {
        Ok(())
    }
    fn close(&mut self) {}
    fn loaded_base(&self) -> u64 {
        0
    }
    fn function_at(&self, _pc: u64) -> Option<Function> {
        None
    }
    fn hlil_for(&self, _fn_: &Function) -> Vec<HlilLine> {
        Vec::new()
    }
    fn vars_for(&self, _fn_: &Function) -> Vec<VarType> {
        Vec::new()
    }
    fn field_at(&self, _pc: u64, _reg: &str, _offset: i64) -> Option<FieldHint> {
        None
    }
    fn xrefs_to(&self, _addr: u64) -> Vec<u64> {
        Vec::new()
    }
    fn cfg_for(&self, _fn_: &Function, _mode: &str) -> (Vec<CfgBlock>, Vec<CfgEdge>) {
        (Vec::new(), Vec::new())
    }
    fn asm_tokens_at(&self, _pc: u64) -> Option<Vec<Token>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_backend_returns_placeholders() {
        let bn = NoneBackend::new();
        assert_eq!(bn.name(), "none");
        assert!(bn.is_available());
        assert_eq!(bn.loaded_base(), 0);
        assert!(bn.function_at(0x1000).is_none());
        let f = Function::default();
        assert!(bn.hlil_for(&f).is_empty());
        assert!(bn.vars_for(&f).is_empty());
        assert!(bn.field_at(0, "x0", 0).is_none());
        assert!(bn.xrefs_to(0).is_empty());
        let (blocks, edges) = bn.cfg_for(&f, "asm");
        assert!(blocks.is_empty() && edges.is_empty());
        assert!(bn.asm_tokens_at(0).is_none());
    }

    #[test]
    fn none_backend_open_close_roundtrip() {
        let mut bn = NoneBackend::new();
        bn.open("/nonexistent.so", 0x10000).unwrap();
        bn.close();
    }
}
