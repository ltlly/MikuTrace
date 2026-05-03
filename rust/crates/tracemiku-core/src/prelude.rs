//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::cfg::{Block, CFG};
pub use crate::disasm::{decode, normalize_disasm_reg, DecodedInsn};
pub use crate::function_index::{
    build_from_symbols as build_function_index, make_bn_id, make_sym_id, make_trace_id, parse_id,
    FunctionEntry, FunctionIndex,
};
pub use crate::index::Index;
pub use crate::symbols::{build_from_trace, ModuleResolver, SymbolMap};
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta, REC_NUM_REGS, REC_SIZE,
};
