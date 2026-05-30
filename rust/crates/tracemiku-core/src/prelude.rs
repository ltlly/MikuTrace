//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::analysis_index::{
    AnalysisIndex, AnalysisSummary, DepEdge, DepKind, DependencyIndex, FunctionSummary,
    MemLastDefEntry, PcSummary, RegCheckpoint,
};
pub use crate::bfs_slice::{
    bfs_slice, bfs_slice_multi, bfs_slice_one, slice_edge_stats, Bitset, SliceEdgeStats, SliceMode,
    SliceOptions, SliceResult,
};
pub use crate::calltree::{build_call_tree, build_call_tree_indexed, CallNode};
pub use crate::cfg::{Block, CFG};
pub use crate::decompiler::backend::{
    Backend, CfgBlock as DecCfgBlock, CfgEdge as DecCfgEdge, FieldHint, Function as DecFunction,
    HlilLine, NoneBackend, Token as DecToken, VarType,
};
pub use crate::decompiler::builder::{
    attach_type_anchors, attach_type_anchors_indexed, build_symbol_func_ir,
    build_symbol_func_ir_at, build_symbol_func_ir_at_indexed, build_symbol_func_ir_indexed,
    build_trace_ir, classify_blocks_by_tier,
};
pub use crate::decompiler::ir::{
    BlockIR, CallIR, EdgeIR, FuncIR, InductionVarIR, LoopIR, TopIR, TypeAnchorIR, VmCandidateIR,
};
pub use crate::decompiler::prompt::{
    build_fn_decompile_prompt, build_summary_prompt, Bundle as PromptBundle,
    SYSTEM_PROMPT_DECOMPILE, SYSTEM_PROMPT_DECOMPILE_ZH, SYSTEM_PROMPT_SUMMARY,
};
pub use crate::decompiler::render::{render_func_md, render_summary_md};
pub use crate::decompiler::type_anchor::{
    find_anchors, find_anchors_indexed, load_type_specs, TypeAnchor, TypeSpec,
};
pub use crate::decompiler::vm_candidate::detect_vm_candidates;
pub use crate::disasm::{decode, normalize_disasm_reg, DecodedInsn};
pub use crate::forward_dep_tree::{
    forward_dep_tree, DependencyUsers, ForwardEdge, ForwardNode, ForwardOptions, ForwardTree,
    UserEdge,
};
pub use crate::function_index::{
    build_from_symbols as build_function_index, make_bn_id, make_sym_addr_id, make_sym_id,
    make_trace_id, parse_id, FunctionEntry, FunctionIndex,
};
pub use crate::hashfin::{hash_finalize_detect, HashFinalizeCandidate};
pub use crate::index::{Index, MemRec};
pub use crate::llil::{
    collect_uidf, collect_uidf_indexed, constfold_block, constfold_expr, dce_block,
    flag_elim_block, join_type, lift_arm64, render_expr, render_llil_block,
    render_llil_block_with_names, render_stmt, restructure_block, ssa_block, struct_recover_block,
    typelat_block, unify_vars, DceResult, FieldAccess, FlagElimResult, LiftStats, LlilExpr, LlilOp,
    LlilOperand, ObservedValues, SsaBlock, SsaVar, StructNode, StructShape, TypeEnv, TypeKind,
    VarNameMap,
};
pub use crate::memshadow::{ByteEvent, MemRec as ShadowMemRec, MemShadow};
pub use crate::ollvmdet::{ollvm_detect_vm, OllvmFinding};
pub use crate::symbols::{build_from_trace, ModuleResolver, SymbolMap};
pub use crate::taint::{
    backward_taint, backward_taint_ext, build_frame_depth_map, default_frame_reg_set,
    forward_taint, forward_taint_ext, StopReason as TaintStopReason, TaintHit, TaintOptions,
    TaintWalkResult, DEFAULT_FRAME_REGS,
};
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta, REC_NUM_REGS, REC_SIZE,
};
pub use crate::watchpoints::{
    watchpoint_scan, WatchpointHit, WatchpointScan, WatchpointSpec,
};
