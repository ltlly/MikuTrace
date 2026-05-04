//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::calltree::{build_call_tree, CallNode};
pub use crate::cfg::{Block, CFG};
pub use crate::decompiler::backend::{
    Backend, CfgBlock as DecCfgBlock, CfgEdge as DecCfgEdge, FieldHint, Function as DecFunction,
    HlilLine, NoneBackend, Token as DecToken, VarType,
};
pub use crate::decompiler::builder::{
    attach_type_anchors, build_symbol_func_ir, build_trace_ir, classify_blocks_by_tier,
};
pub use crate::decompiler::ir::{
    BlockIR, CallIR, EdgeIR, FuncIR, InductionVarIR, LoopIR, TopIR, TypeAnchorIR, VmCandidateIR,
};
pub use crate::decompiler::render::{render_func_md, render_summary_md};
pub use crate::decompiler::type_anchor::{find_anchors, load_type_specs, TypeAnchor, TypeSpec};
pub use crate::decompiler::vm_candidate::detect_vm_candidates;
pub use crate::disasm::{decode, normalize_disasm_reg, DecodedInsn};
pub use crate::function_index::{
    build_from_symbols as build_function_index, make_bn_id, make_sym_id, make_trace_id, parse_id,
    FunctionEntry, FunctionIndex,
};
pub use crate::index::{Index, MemRec};
pub use crate::memshadow::{ByteEvent, MemRec as ShadowMemRec, MemShadow};
pub use crate::ollvmdet::{ollvm_detect_vm, OllvmFinding};
pub use crate::symbols::{build_from_trace, ModuleResolver, SymbolMap};
pub use crate::taint::{
    backward_taint, build_frame_depth_map, default_frame_reg_set, forward_taint, TaintHit,
    DEFAULT_FRAME_REGS,
};
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta, REC_NUM_REGS, REC_SIZE,
};
