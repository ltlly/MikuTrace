//! MLIL — Medium-Level IL (variable-based, flag-free).
//!
//! Mirrors Binary Ninja's MLIL layer. Transforms register-based LLIL into
//! variable-based MLIL with direct comparisons instead of flag tracking.
//!
//! Key differences from LLIL:
//!   - SetVar/Var instead of SetReg/Reg (variables, not registers)
//!   - No flag operations (flags folded into direct comparisons)
//!   - LoadStruct/StoreStruct for struct field access
//!   - AddressOf/AddressOfField for pointer operations

pub mod expr;
pub mod lower;
pub mod render;
pub mod render_tokens;

pub use expr::{
    address_of, address_of_field, binary, const_data, const_ptr, csel, expr, konst, load,
    load_struct, low_part, set_var, set_var_field, store, store_struct, sx, unary, var, zx,
    MlilExpr, MlilOp, MlilOperand,
};
pub use lower::{lower_llil_to_mlil, LowerStats};
pub use render::{render_expr, render_mlil_block, render_stmt};
