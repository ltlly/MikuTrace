//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::disasm::{decode, normalize_disasm_reg, DecodedInsn};
pub use crate::index::Index;
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta, REC_NUM_REGS, REC_SIZE,
};
