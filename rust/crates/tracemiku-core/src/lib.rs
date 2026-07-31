//! traceMiku v2 — analysis core.
//!
//! 架构说明见仓库根目录 `AGENTS.md` 与 `docs/trace-decompiler-design.md`。
//! for the architecture. This crate contains all trace-side analysis;
//! the HTTP server lives in `tracemiku-server`, the CLI in `tracemiku-cli`.
//!
//! Public surface is re-exported from [`prelude`].

#![deny(unused_must_use)]
#![warn(clippy::all)]

pub mod address_parse;
pub mod analysis_index;
pub mod bfs_slice;
pub mod call_analysis;
pub mod calltree;
pub mod cfg;
pub mod crypto_scan;
// The decompiler pipeline (lift → IL → MLIL → HLIL) is a separate product
// area: it is intentionally excluded from the clippy -D warnings baseline
// while the trace-analysis core is held to zero warnings. See TODO.md.
#[allow(clippy::all, unused_imports, unused_variables, unused_assignments)]
pub mod decompiler;
pub mod disasm;
pub mod forward_dep_tree;
pub mod function_index;
pub mod hashfin;
#[allow(clippy::all, unused_imports, unused_variables)]
pub mod hlil;
pub mod index;
#[allow(clippy::all, unused_imports, unused_variables)]
pub mod llil;
pub mod memshadow;
#[allow(clippy::all, unused_imports, unused_variables)]
pub mod mlil;
pub mod ollvmdet;
pub mod parallel;
pub mod prelude;
pub mod sidecar_io;
pub mod symbols;
pub mod taint;
pub mod trace;
pub mod watchpoints;
