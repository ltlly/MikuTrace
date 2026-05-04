//! Decompiler — TraceIR + Backend abstraction.
//!
//! M3-δ ships skeleton only: IR dataclasses, Backend trait + NoneBackend,
//! and a build_trace_ir that emits a single root FuncIR. M3-ε fills
//! BlockIR, callee splits, type anchors, VM candidates, /api/dec/fn/{id}.
//!
//! See `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
//! §13.3 for the migration table.

pub mod backend;
pub mod builder;
pub mod ir;
pub mod render;
pub mod type_anchor;
pub mod vm_candidate;
