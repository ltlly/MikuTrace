//! traceMiku v2 — analysis core.
//!
//! See `docs/superpowers/specs/2026-05-03-analysis-v2-rust-ts-design.md`
//! for the architecture. This crate contains all trace-side analysis;
//! the HTTP server lives in `tracemiku-server`, the CLI in `tracemiku-cli`.
//!
//! Public surface is re-exported from [`prelude`].

#![deny(unused_must_use)]
#![warn(clippy::all)]

pub mod disasm;
pub mod prelude;
pub mod trace;
