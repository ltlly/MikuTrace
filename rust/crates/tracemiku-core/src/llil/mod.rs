//! In-house ARM64 LLIL pipeline.
//!
//! M5 ports the Python `viewer/decompiler/llil/` route into Rust in stages.
//! This module starts with the stable wire/data model plus the ARM64 lifter;
//! SSA, simplification passes, and C-like rendering are layered on top.

pub mod expr;
pub mod lift;

pub use expr::{LlilExpr, LlilOp, LlilOperand};
pub use lift::{lift_arm64, LiftStats};
