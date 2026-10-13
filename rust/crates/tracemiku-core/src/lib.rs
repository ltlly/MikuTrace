//! traceMiku v2 — analysis core.
//!
//! 架构说明见仓库根目录 `AGENTS.md`。This crate contains all trace-side
//! analysis. `tracemiku-cli` parses arguments and serializes these results.
//!
//! Public surface is re-exported from [`prelude`].

#![deny(unused_must_use)]
#![warn(clippy::all)]

pub mod address_parse;
pub mod analysis;
pub mod analysis_index;
pub mod bfs_slice;
pub mod calltree;
pub mod cfg;
pub mod crypto_scan;
pub mod disasm;
pub mod forward_dep_tree;
pub mod function_index;
pub mod index;
pub mod memshadow;
pub mod parallel;
pub mod prelude;
pub mod replay;
pub mod sidecar_io;
pub mod symbols;
pub mod taint;
pub mod trace;
pub mod watchpoints;
pub mod write_bursts;
