//! HLIL — High-Level IL (structured control flow, C-like semantics).
//!
//! Mirrors Binary Ninja's HLIL layer. Transforms variable-based MLIL into
//! structured HLIL with if/while/for, variable declarations, dereferences,
//! and C-like semantics.
//!
//! Key features:
//!   - Structured control flow: If, While, DoWhile, For, Switch
//!   - Variable declarations: VarDeclare, VarInit
//!   - Dereference instead of raw loads
//!   - Break/Continue for loop control
//!   - Labels for unstructured code fallback

pub mod expr;
pub mod lower;
pub mod pass_restructure;
pub mod render;
pub mod render_tokens;
pub mod token;

pub use expr::{
    address_of, address_of_field, array_index, assign, binary, block, break_, call, const_data,
    const_ptr, continue_, deref, deref_field, do_while, expr, goto, if_else, konst, label,
    low_part, nop, ret, struct_field, sx, unary, unreachable, var, var_declare, var_init,
    while_loop, zx, HlilExpr, HlilOp, HlilOperand,
};
pub use lower::{lower_mlil_to_hlil, LowerStats};
pub use render::{render_expr, render_hlil};
pub use render_tokens::render_hlil_tokens;
pub use token::{CToken, CTokenKind, CTokenLine, CTokenWire};
