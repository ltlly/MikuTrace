//! Mnemonic-based branch/call/ret classification. Pure functions over &str.
//!
//! Mirrors the Python logic in `viewer/disasm.py:65-71`:
//!   is_branch = mnem in {"b","bl","br","blr","ret","cbz","cbnz","tbz","tbnz"}
//!               OR mnem.startswith("b.")
//!   is_call   = mnem in {"bl","blr"}
//!   is_ret    = mnem == "ret"

/// `true` if mnemonic is any branch (conditional, indirect, compare-and-branch,
/// test-and-branch, ret).
pub fn is_branch_mnem(mnem: &str) -> bool {
    matches!(
        mnem,
        "b" | "bl" | "br" | "blr" | "ret" | "cbz" | "cbnz" | "tbz" | "tbnz"
    ) || mnem.starts_with("b.")
}

/// `true` if mnemonic branches conditionally on NZCV or a tested register.
pub fn is_conditional_branch_mnem(mnem: &str) -> bool {
    matches!(mnem, "cbz" | "cbnz" | "tbz" | "tbnz")
        || (mnem.starts_with("b.") && !matches!(mnem, "b.al" | "b.nv"))
}

/// `true` if mnemonic is a function call (direct or indirect).
pub fn is_call_mnem(mnem: &str) -> bool {
    matches!(mnem, "bl" | "blr")
}

/// `true` if mnemonic is the function-return instruction.
pub fn is_ret_mnem(mnem: &str) -> bool {
    mnem == "ret"
}
