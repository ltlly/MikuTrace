//! In-house ARM64 LLIL pipeline.
//!
//! M5 ports the Python `viewer/decompiler/llil/` route into Rust in stages.
//! This module starts with the stable wire/data model plus the ARM64 lifter;
//! SSA, simplification passes, and C-like rendering are layered on top.

pub mod expr;
pub mod lift;
pub mod pass_constfold;
pub mod pass_dce;
pub mod ssa;

pub use expr::{LlilExpr, LlilOp, LlilOperand};
pub use lift::{lift_arm64, LiftStats};
pub use pass_constfold::{constfold_block, constfold_expr};
pub use pass_dce::{dce_block, DceResult};
pub use ssa::{ssa_block, SsaBlock, SsaVar};
