//! Re-exports the public API surface for downstream consumers.
//!
//! Use `use tracemiku_core::prelude::*;` rather than reaching into
//! submodules directly.

pub use crate::address_parse::{parse_address, parse_address_opt, ParseAddressError};
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
pub use crate::disasm::{decode, normalize_disasm_reg, DecodedInsn};
pub use crate::forward_dep_tree::{
    forward_dep_tree, DependencyUsers, ForwardEdge, ForwardNode, ForwardOptions, ForwardTree,
    UserEdge,
};
pub use crate::function_index::{
    build_from_symbols as build_function_index, make_bn_id, make_sym_addr_id, make_sym_id,
    parse_id, FunctionEntry, FunctionIndex,
};
pub use crate::hashfin::{hash_finalize_detect, HashFinalizeCandidate};
pub use crate::index::{Index, MemRec};
pub use crate::memshadow::{ByteEvent, MemRec as ShadowMemRec, MemShadow, MemSnapshot, SnapRegion};
pub use crate::ollvmdet::{ollvm_detect_vm, OllvmFinding};
pub use crate::symbols::{build_from_trace, ModuleResolver, SymbolMap};
pub use crate::taint::{
    backward_taint, backward_taint_ext, build_frame_depth_map, default_frame_reg_set,
    forward_taint, forward_taint_ext, StopReason as TaintStopReason, TaintHit, TaintOptions,
    TaintWalkResult, DEFAULT_FRAME_REGS,
};
pub use crate::trace::{
    CallInfo, MetaError, ModuleInfo, Record, Trace, TraceMeta, FORMAT_VERSION, REC_NUM_REGS,
    REC_SIZE,
};
pub use crate::watchpoints::{watchpoint_scan, WatchpointHit, WatchpointScan, WatchpointSpec};
