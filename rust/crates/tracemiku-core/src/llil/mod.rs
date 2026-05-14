//! In-house ARM64 LLIL pipeline.
//!
//! M5 ports the Python `viewer/decompiler/llil/` route into Rust in stages.
//! This module starts with the stable wire/data model plus the ARM64 lifter;
//! SSA, simplification passes, and C-like rendering are layered on top.

pub mod expr;
pub mod lift;
pub mod pass_constfold;
pub mod pass_dce;
pub mod pass_flag_elim;
pub mod pass_frame_fold;
pub mod pass_phi;
pub mod pass_restructure;
pub mod pass_struct;
pub mod pass_typelat;
pub mod pass_uidf;
pub mod pass_var_unify;
pub mod render;
pub mod ssa;
pub mod util;

pub use expr::{LlilExpr, LlilOp, LlilOperand};
pub use lift::{lift_arm64, LiftStats};
pub use pass_constfold::{constfold_block, constfold_expr};
pub use pass_dce::{dce_block, DceResult};
pub use pass_flag_elim::{flag_elim_block, FlagElimResult};
pub use pass_phi::{phi_cfg, PhiCfg};
pub use pass_restructure::{restructure_block, restructure_cfg, StructNode};
pub use pass_struct::{struct_recover_block, FieldAccess, StructShape};
pub use pass_typelat::{join_type, typelat_block, TypeEnv, TypeKind};
pub use pass_uidf::{collect_uidf, collect_uidf_indexed, ObservedValues};
pub use pass_var_unify::{unify_vars, VarNameMap};
pub use render::{render_expr, render_llil_block, render_llil_block_with_names, render_stmt};
pub use ssa::{ssa_block, SsaBlock, SsaVar};
