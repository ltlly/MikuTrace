//! Black-box contract tests for crypto fingerprint constants.
//!
//! The 64-bit hash constants (XXH64, FNV-1a 64) are stored as split lo/hi
//! 32-bit fingerprints. The lo halves must be the true low 32 bits of the
//! canonical 64-bit constants; a previous bug copied the high 32 bits
//! (XXH32 values) into the lo fields, which makes constscan mislabel
//! algorithms — a deterministic wrong answer for AI consumers.

use tracemiku_core::crypto_scan::build_fingerprints;

fn find_value(name: &str) -> u32 {
    build_fingerprints()
        .into_iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("fingerprint {name} missing"))
        .value
}

#[test]
fn xxh32_primes_match_canonical() {
    // XXH32 primes (unchanged baseline; guards the fixture itself).
    assert_eq!(find_value("XXH32.PRIME1"), 0x9e3779b1);
    assert_eq!(find_value("XXH32.PRIME2"), 0x85ebca77);
}

#[test]
fn xxh64_prime1_lo_is_low_word() {
    // XXH64 PRIME1 = 0x9E3779B185EBCA87.
    assert_eq!(find_value("XXH64.PRIME1_lo"), 0x85ebca87);
}

#[test]
fn xxh64_prime2_lo_is_low_word() {
    // XXH64 PRIME2 = 0xC2B2AE3D27D4EB4F.
    assert_eq!(find_value("XXH64.PRIME2_lo"), 0x27d4eb4f);
}

#[test]
fn fnv64_offset_lo_is_low_word() {
    // FNV-1a 64 offset basis = 0xCBF29CE484222325.
    assert_eq!(find_value("FNV64.offset_lo"), 0x84222325);
}

#[test]
fn fnv64_prime_lo_is_low_word() {
    // FNV-1a 64 prime = 0x00000100000001B3.
    assert_eq!(find_value("FNV64.prime_lo"), 0x000001b3);
}

#[test]
fn fnv32_constants_unchanged() {
    assert_eq!(find_value("FNV32.offset"), 0x811c9dc5);
    assert_eq!(find_value("FNV32.prime"), 0x01000193);
}
