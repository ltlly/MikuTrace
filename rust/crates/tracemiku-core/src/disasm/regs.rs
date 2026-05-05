//! ARM64 register name normalization. Direct port of viewer/regs.py.
//!
//! Capstone returns reg names like "w0", "X29", "WZR", "wsp". Our internal
//! canonical form is what the trace stores: x0..x28, fp, lr, sp, pc, xzr.

/// Map capstone's reg name to the canonical name used in record reg slots.
///
/// - `w0..w28` → `x0..x28` (32-bit alias of the 64-bit register)
/// - `w29` → `fp`, `w30` → `lr`
/// - `x29` → `fp` (frame pointer alias used by trace storage)
/// - `x30` → `lr` (link register alias)
/// - `wsp` → `sp` (stack pointer 32-bit alias)
/// - `xzr` / `wzr` → `xzr` (zero register)
/// - empty input → empty output
pub fn normalize_disasm_reg(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let n = name.to_ascii_lowercase();

    // w0..w30 → x0..x30, then canonicalize frame/link aliases.
    if let Some(rest) = n.strip_prefix('w') {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return match rest {
                "29" => "fp".to_string(),
                "30" => "lr".to_string(),
                _ => format!("x{rest}"),
            };
        }
    }

    // Zero registers
    if n == "xzr" || n == "wzr" {
        return "xzr".to_string();
    }

    // Aliases
    match n.as_str() {
        "x29" => "fp".to_string(),
        "x30" => "lr".to_string(),
        "wsp" => "sp".to_string(),
        _ => n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_w_to_x() {
        assert_eq!(normalize_disasm_reg("w0"), "x0");
        assert_eq!(normalize_disasm_reg("w28"), "x28");
        assert_eq!(normalize_disasm_reg("W29"), "fp");
        assert_eq!(normalize_disasm_reg("W30"), "lr");
    }

    #[test]
    fn normalize_aliases() {
        assert_eq!(normalize_disasm_reg("x29"), "fp");
        assert_eq!(normalize_disasm_reg("x30"), "lr");
        assert_eq!(normalize_disasm_reg("wsp"), "sp");
    }

    #[test]
    fn normalize_zero_regs() {
        assert_eq!(normalize_disasm_reg("xzr"), "xzr");
        assert_eq!(normalize_disasm_reg("wzr"), "xzr");
        assert_eq!(normalize_disasm_reg("WZR"), "xzr");
    }

    #[test]
    fn normalize_canonical_passthrough() {
        assert_eq!(normalize_disasm_reg("x0"), "x0");
        assert_eq!(normalize_disasm_reg("fp"), "fp");
        assert_eq!(normalize_disasm_reg("lr"), "lr");
        assert_eq!(normalize_disasm_reg("sp"), "sp");
        assert_eq!(normalize_disasm_reg("pc"), "pc");
    }

    #[test]
    fn normalize_empty_and_garbage() {
        assert_eq!(normalize_disasm_reg(""), "");
        assert_eq!(normalize_disasm_reg("wfoo"), "wfoo");
        assert_eq!(normalize_disasm_reg("garbage"), "garbage");
    }
}
