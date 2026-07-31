//! Shared address/number parsing helpers for route query params.
//!
//! Two conventions exist across routes, and both are committed by tests:
//! - **hex-first** (`parse_hex_u64`): bare tokens are hex (disassembler
//!   convention for addresses/offsets); explicit `d`/`D` prefix opts into
//!   decimal. Used by resolve/coverage/cfg and friends — matches the CLI
//!   guidance "地址和偏移默认按十六进制解析".
//! - **decimal-first** (`parse_dec_u64`): bare tokens are decimal; `0x`
//!   prefix opts into hex. Used by index-style routes (bfs-slice, dep-graph,
//!   seed-resolver) where values are counts/indices.
//!
//! Both used to be defined as `parse_u64` in multiple route files with
//! silently different semantics; the explicit names prevent that confusion.

/// Hex-first parse: `0x`/bare → hex, `d`/`D` prefix → decimal.
pub(crate) fn parse_hex_u64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(dec) = s.strip_prefix('d').or_else(|| s.strip_prefix('D')) {
        dec.parse::<u64>().ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
}

/// Decimal-first parse: bare → decimal, `0x` prefix → hex.
pub(crate) fn parse_dec_u64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_first_parses_bare_token_as_hex() {
        assert_eq!(parse_hex_u64("0x10"), Some(16));
        assert_eq!(parse_hex_u64("10"), Some(16));
        assert_eq!(parse_hex_u64("ff"), Some(255));
        assert_eq!(parse_hex_u64("d16"), Some(16));
        assert_eq!(parse_hex_u64("D255"), Some(255));
        assert_eq!(parse_hex_u64("not-a-number"), None);
    }

    #[test]
    fn decimal_first_parses_bare_token_as_decimal() {
        assert_eq!(parse_dec_u64("0x10"), Some(16));
        assert_eq!(parse_dec_u64("10"), Some(10));
        assert_eq!(parse_dec_u64("66"), Some(66));
        assert_eq!(parse_dec_u64(""), None);
        assert_eq!(parse_dec_u64("not-a-number"), None);
    }
}
