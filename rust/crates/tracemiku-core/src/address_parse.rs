//! Unified address/offset parsing for traceMiku.
//!
//! Addresses and offsets are universally hex in disassemblers (IDA/BN/Ghidra),
//! so a bare token is treated as hex (`10` -> `0x10`), NOT decimal. This avoids
//! the ambiguity where `--off 10` and `--off 6a30` would silently use different
//! bases. Use `d`/`D` prefix to force decimal when needed (`d16` -> 16).

use thiserror::Error;

/// Error returned when address/offset parsing fails.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseAddressError {
    #[error("invalid address format: {input}")]
    InvalidFormat { input: String },

    #[error("address value out of range: {input}")]
    OutOfRange { input: String },

    #[error("empty address string")]
    Empty,
}

/// Parse an address or offset the way a reverse engineer writes one.
///
/// # Format
/// - `0x1234` or `0X1234` - explicit hexadecimal
/// - `1234` - bare token treated as hex (disassembler convention)
/// - `d1234` or `D1234` - explicit decimal
///
/// # Examples
/// ```
/// use tracemiku_core::address_parse::parse_address;
///
/// assert_eq!(parse_address("0x10").unwrap(), 16);
/// assert_eq!(parse_address("10").unwrap(), 16);  // hex by default
/// assert_eq!(parse_address("d16").unwrap(), 16); // explicit decimal
/// assert_eq!(parse_address("ff").unwrap(), 255);
/// assert!(parse_address("").is_err());
/// assert!(parse_address("zz").is_err());
/// ```
pub fn parse_address(raw: &str) -> Result<u64, ParseAddressError> {
    let s = raw.trim();

    if s.is_empty() {
        return Err(ParseAddressError::Empty);
    }

    let result = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else if let Some(dec) = s.strip_prefix('d').or_else(|| s.strip_prefix('D')) {
        dec.parse::<u64>()
    } else {
        // Bare token: hex by default (IDA/BN/Ghidra convention)
        u64::from_str_radix(s, 16)
    };

    result.map_err(|_| ParseAddressError::InvalidFormat {
        input: raw.to_string(),
    })
}

/// Parse an address or offset, returning `None` on failure.
///
/// Convenience wrapper around [`parse_address`] that returns `Option` instead
/// of `Result` for cases where error details aren't needed.
pub fn parse_address_opt(raw: &str) -> Option<u64> {
    parse_address(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_address_treats_bare_token_as_hex() {
        assert_eq!(parse_address("0x10").unwrap(), 16);
        assert_eq!(parse_address("0X10").unwrap(), 16);
        assert_eq!(parse_address("10").unwrap(), 16); // hex, NOT decimal
        assert_eq!(parse_address("6a30").unwrap(), 0x6a30);
        assert_eq!(parse_address("ff").unwrap(), 255);
        assert_eq!(parse_address("FF").unwrap(), 255);
    }

    #[test]
    fn parse_address_explicit_decimal() {
        assert_eq!(parse_address("d16").unwrap(), 16);
        assert_eq!(parse_address("D255").unwrap(), 255);
        assert_eq!(parse_address("d0").unwrap(), 0);
    }

    #[test]
    fn parse_address_rejects_invalid_input() {
        assert!(matches!(parse_address(""), Err(ParseAddressError::Empty)));
        assert!(matches!(
            parse_address("zz"),
            Err(ParseAddressError::InvalidFormat { .. })
        ));
        assert!(matches!(
            parse_address("0xZZ"),
            Err(ParseAddressError::InvalidFormat { .. })
        ));
        assert!(matches!(
            parse_address("d99999999999999999999999999"),
            Err(ParseAddressError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn parse_address_opt_returns_none_on_error() {
        assert_eq!(parse_address_opt("0x10"), Some(16));
        assert_eq!(parse_address_opt("10"), Some(16));
        assert_eq!(parse_address_opt("zz"), None);
        assert_eq!(parse_address_opt(""), None);
    }

    #[test]
    fn parse_address_handles_whitespace() {
        assert_eq!(parse_address("  0x10  ").unwrap(), 16);
        assert_eq!(parse_address("\t10\n").unwrap(), 16);
    }
}
