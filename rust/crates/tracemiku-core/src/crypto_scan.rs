//! Cryptographic constant fingerprint scanning and ARM Crypto Extensions detection.
//!
//! Two analysis passes:
//! - `scan_constants`: matches 97 cryptographic constants (MD5/SHA/AES/SM3/etc.)
//!   against immediate values and register contents in the trace.
//! - `scan_crypto_instrs`: detects ARMv8 Crypto Extensions hardware instructions.
//!
//! Inspired by AlgoKiller's `constscan` and `cryptoinstr` tools.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::trace::Trace;

// ---------------------------------------------------------------------------
// Fingerprint table
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Hash,
    SymCipher,
    Ecc,
    Crc,
    Mac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Direct evidence from load-immediate or memory-read.
    Real,
    /// NEON SIMD load (HMAC ipad/opad).
    RealSimd,
    /// ALU computation result — high false-positive rate, ignore.
    AluOnly,
    /// Indirect signal only (e.g. from mem_w target address).
    Weak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub name: String,
    pub category: Category,
    pub alg: String,
    /// 32-bit value to match (masked with `mask`).
    pub value: u32,
    /// Bitmask applied before comparison. Use 0xFFFFFFFF for exact match.
    pub mask: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstHit {
    pub fingerprint: String,
    pub category: Category,
    pub alg: String,
    pub idx: usize,
    pub pc: u64,
    pub source: ConstHitSource,
    pub verdict: Verdict,
    pub sample_value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstHitSource {
    /// Immediate operand in the instruction.
    Imm,
    /// Value read from a general-purpose register.
    Reg,
    /// Value read from memory (observed in register after a load).
    MemR,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintSummary {
    pub name: String,
    pub category: Category,
    pub alg: String,
    pub total_hits: usize,
    pub first_idx: Option<usize>,
    pub sample_idxs: Vec<usize>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstScanResult {
    pub hits: Vec<ConstHit>,
    pub summaries: Vec<FingerprintSummary>,
    pub records_scanned: usize,
}

// ---------------------------------------------------------------------------
// Crypto instruction tables
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoInstrHit {
    pub mnemonic: String,
    pub alg: String,
    pub count: usize,
    pub first_idx: Option<usize>,
    pub sample_idxs: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoInstrResult {
    pub hits: Vec<CryptoInstrHit>,
    pub records_scanned: usize,
}

// ---------------------------------------------------------------------------
// Fingerprint database
// ---------------------------------------------------------------------------

fn make_fingerprint(
    name: &str,
    category: Category,
    alg: &str,
    value: u32,
    mask: u32,
) -> Fingerprint {
    Fingerprint {
        name: name.to_string(),
        category,
        alg: alg.to_string(),
        value,
        mask,
    }
}

fn exact(name: &str, cat: Category, alg: &str, val: u32) -> Fingerprint {
    make_fingerprint(name, cat, alg, val, 0xFFFFFFFF)
}

/// Build the full fingerprint database (97 entries).
pub fn build_fingerprints() -> Vec<Fingerprint> {
    let mut fps = Vec::with_capacity(128);

    // === MD5 ===
    fps.push(exact("MD5.IV0", Category::Hash, "MD5", 0x67452301));
    fps.push(exact("MD5.IV1", Category::Hash, "MD5", 0xefcdab89));
    fps.push(exact("MD5.IV2", Category::Hash, "MD5", 0x98badcfe));
    fps.push(exact("MD5.IV3", Category::Hash, "MD5", 0x10325476));

    // MD5 T table: T[i] = floor(2^32 * |sin(i+1)|) for i=0..63
    let md5_t: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    for (i, &t) in md5_t.iter().enumerate() {
        fps.push(exact(&format!("MD5.T[{}]", i), Category::Hash, "MD5", t));
    }

    // === SHA-1 ===
    fps.push(exact("SHA1.IV0", Category::Hash, "SHA-1", 0x67452301));
    fps.push(exact("SHA1.IV1", Category::Hash, "SHA-1", 0xefcdab89));
    fps.push(exact("SHA1.IV2", Category::Hash, "SHA-1", 0x98badcfe));
    fps.push(exact("SHA1.IV3", Category::Hash, "SHA-1", 0x10325476));
    fps.push(exact("SHA1.IV4", Category::Hash, "SHA-1", 0xc3d2e1f0));

    // SHA-1 round constants
    fps.push(exact("SHA1.K0", Category::Hash, "SHA-1", 0x5a827999));
    fps.push(exact("SHA1.K1", Category::Hash, "SHA-1", 0x6ed9eba1));
    fps.push(exact("SHA1.K2", Category::Hash, "SHA-1", 0x8f1bbcdc));
    fps.push(exact("SHA1.K3", Category::Hash, "SHA-1", 0xca62c1d6));

    // === SHA-256 ===
    let sha256_iv: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    for (i, &v) in sha256_iv.iter().enumerate() {
        fps.push(exact(
            &format!("SHA256.IV{}", i),
            Category::Hash,
            "SHA-256",
            v,
        ));
    }

    // SHA-256 K table (first 16 are most discriminative)
    let sha256_k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    for (i, &k) in sha256_k.iter().enumerate() {
        fps.push(exact(
            &format!("SHA256.K[{}]", i),
            Category::Hash,
            "SHA-256",
            k,
        ));
    }

    // === SM3 ===
    let sm3_iv: [u32; 8] = [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d,
        0xb0fb0e4e,
    ];
    for (i, &v) in sm3_iv.iter().enumerate() {
        fps.push(exact(&format!("SM3.IV{}", i), Category::Hash, "SM3", v));
    }

    let sm3_tj: [u32; 2] = [0x79cc4519, 0x7a879d8a];
    for (i, &t) in sm3_tj.iter().enumerate() {
        fps.push(exact(&format!("SM3.T_j[{}]", i), Category::Hash, "SM3", t));
    }

    // === SHA-3 constants (round constants RC[0..23]) ===
    let sha3_rc: [u64; 24] = [
        0x0000000000000001,
        0x0000000000008082,
        0x800000000000808a,
        0x8000000080008000,
        0x000000000000808b,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008a,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000a,
        0x000000008000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008,
    ];
    for (i, &rc) in sha3_rc.iter().enumerate() {
        // Only the low 32 bits are easily observable as immediates
        fps.push(exact(
            &format!("SHA3.RC[{}]", i),
            Category::Hash,
            "SHA-3",
            rc as u32,
        ));
    }

    // === AES ===
    fps.push(exact("AES.sbox[0]", Category::SymCipher, "AES", 0x63));
    fps.push(exact("AES.sbox[1]", Category::SymCipher, "AES", 0x7c));
    // AES Te0 table (first few entries — the full 256 entries are possible but
    // these are the most distinctive)
    fps.push(exact("AES.Te0[0]", Category::SymCipher, "AES", 0xc66363a5));
    fps.push(exact("AES.Te0[1]", Category::SymCipher, "AES", 0xf87c7c84));
    fps.push(exact("AES.Te0[2]", Category::SymCipher, "AES", 0xee777799));
    fps.push(exact("AES.Te0[3]", Category::SymCipher, "AES", 0xf67b7b8d));

    // === SM4 ===
    let sm4_fk: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
    for (i, &fk) in sm4_fk.iter().enumerate() {
        fps.push(exact(
            &format!("SM4.FK[{}]", i),
            Category::SymCipher,
            "SM4",
            fk,
        ));
    }
    let sm4_ck: [u32; 4] = [0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269];
    for (i, &ck) in sm4_ck.iter().enumerate() {
        fps.push(exact(
            &format!("SM4.CK[{}]", i),
            Category::SymCipher,
            "SM4",
            ck,
        ));
    }

    // === ChaCha20 ===
    fps.push(exact(
        "ChaCha20.expand0",
        Category::SymCipher,
        "ChaCha20",
        0x61707865,
    ));
    fps.push(exact(
        "ChaCha20.expand1",
        Category::SymCipher,
        "ChaCha20",
        0x3320646e,
    ));
    fps.push(exact(
        "ChaCha20.expand2",
        Category::SymCipher,
        "ChaCha20",
        0x79622d32,
    ));
    fps.push(exact(
        "ChaCha20.expand3",
        Category::SymCipher,
        "ChaCha20",
        0x6b206574,
    ));

    // === Poly1305 ===
    fps.push(exact(
        "Poly1305.r_mask",
        Category::Mac,
        "Poly1305",
        0x0ffffffc,
    ));

    // === SipHash ===
    fps.push(exact("SipHash.IV0", Category::Mac, "SipHash", 0x736f6d65));
    fps.push(exact("SipHash.IV1", Category::Mac, "SipHash", 0x646f7261));
    fps.push(exact("SipHash.IV2", Category::Mac, "SipHash", 0x6c796765));
    fps.push(exact("SipHash.IV3", Category::Mac, "SipHash", 0x74656462));

    // === HMAC ipad/opad ===
    fps.push(exact("HMAC.ipad", Category::Mac, "HMAC", 0x36363636));
    fps.push(exact("HMAC.opad", Category::Mac, "HMAC", 0x5c5c5c5c));

    // === CRC32 ===
    fps.push(exact("CRC32.poly", Category::Crc, "CRC32", 0xedb88320));
    fps.push(exact("CRC32C.poly", Category::Crc, "CRC32C", 0x82f63b78));

    // === ECC ===
    fps.push(exact("P256.p", Category::Ecc, "P-256", 0xffffffff));
    // secp256k1 p (low word)
    fps.push(exact(
        "secp256k1.p_lo",
        Category::Ecc,
        "secp256k1",
        0xfffffc2f,
    ));
    // Curve25519 p = 2^255 - 19
    fps.push(exact(
        "Curve25519.p_lo",
        Category::Ecc,
        "Curve25519",
        0xffffffed,
    ));

    // Ed25519 d = -121665/121666 mod p (low word)
    fps.push(exact("Ed25519.d", Category::Ecc, "Ed25519", 0x52036cee));

    // === SHA-512 ===
    let sha512_iv: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    for (i, &v) in sha512_iv.iter().enumerate() {
        fps.push(exact(
            &format!("SHA512.IV{}", i),
            Category::Hash,
            "SHA-512",
            v as u32,
        ));
    }
    // SHA-512 K[0..15] (most distinctive)
    let sha512_k: [u64; 16] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
    ];
    for (i, &k) in sha512_k.iter().enumerate() {
        fps.push(exact(
            &format!("SHA512.K[{}]", i),
            Category::Hash,
            "SHA-512",
            k as u32,
        ));
    }

    // === Blake2b ===
    let blake2b_iv: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    for (i, &v) in blake2b_iv.iter().enumerate() {
        fps.push(exact(
            &format!("Blake2b.IV{}", i),
            Category::Hash,
            "Blake2b",
            v as u32,
        ));
    }

    // === AES sbox — grouped by 4 bytes ===
    let aes_sbox: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
        0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
        0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
        0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
        0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
        0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
        0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
        0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
        0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
        0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
        0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
        0x16,
    ];
    for chunk in aes_sbox.chunks(4) {
        let idx = chunk[0] as usize / 4;
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let b3 = chunk.get(3).copied().unwrap_or(0) as u32;
        let val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        fps.push(exact(
            &format!("AES.sbox[{}..{}]", idx * 4, idx * 4 + 3),
            Category::SymCipher,
            "AES",
            val,
        ));
    }

    // === SM4 sbox — grouped by 4 bytes ===
    let sm4_sbox: [u8; 256] = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c,
        0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86,
        0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed,
        0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
        0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c,
        0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb,
        0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25,
        0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
        0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38,
        0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34,
        0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82,
        0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
        0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf,
        0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1,
        0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89,
        0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39,
        0x48,
    ];
    for chunk in sm4_sbox.chunks(4) {
        let idx = chunk[0] as usize / 4;
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let b3 = chunk.get(3).copied().unwrap_or(0) as u32;
        let val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        fps.push(exact(
            &format!("SM4.sbox[{}..{}]", idx * 4, idx * 4 + 3),
            Category::SymCipher,
            "SM4",
            val,
        ));
    }

    // === SM4 CK full table (32 entries) ===
    let sm4_ck_full: [u32; 32] = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x6c777e85, 0x848b9299, 0xa0a7aeb5,
        0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
        0x80878e95, 0x9ca3aab1, 0xb8bfc6cd, 0xd4dbe2e9, 0xf0f7fe05, 0x0c131a21, 0x282f363d,
        0x444b5259, 0x60676e75, 0x7c838a91, 0x989fa6ad, 0xb4bbc2c9, 0xd0d7dee5, 0xecf3fa01,
        0x080f161d, 0x242b3239, 0x40474e55, 0x5c636a71,
    ];
    for (i, &ck) in sm4_ck_full.iter().enumerate() {
        fps.push(exact(
            &format!("SM4.CK[{}]", i),
            Category::SymCipher,
            "SM4",
            ck,
        ));
    }

    // === XXH32/XXH64 primes ===
    fps.push(exact("XXH32.PRIME1", Category::Hash, "XXH32", 0x9e3779b1));
    fps.push(exact("XXH32.PRIME2", Category::Hash, "XXH32", 0x85ebca77));
    fps.push(exact("XXH32.PRIME3", Category::Hash, "XXH32", 0xc2b2ae3d));
    fps.push(exact("XXH32.PRIME4", Category::Hash, "XXH32", 0x27d4eb2f));
    fps.push(exact("XXH32.PRIME5", Category::Hash, "XXH32", 0x165667b1));
    fps.push(exact(
        "XXH64.PRIME1_lo",
        Category::Hash,
        "XXH64",
        0x85ebca87,
    ));
    fps.push(exact(
        "XXH64.PRIME2_lo",
        Category::Hash,
        "XXH64",
        0x27d4eb4f,
    ));

    // === MurmurHash3 ===
    fps.push(exact("Murmur3.c1", Category::Hash, "Murmur3", 0xcc9e2d51));
    fps.push(exact("Murmur3.c2", Category::Hash, "Murmur3", 0x1b873593));

    // === FNV-1a ===
    fps.push(exact("FNV32.offset", Category::Hash, "FNV-1a", 0x811c9dc5));
    fps.push(exact("FNV32.prime", Category::Hash, "FNV-1a", 0x01000193));
    fps.push(exact(
        "FNV64.offset_lo",
        Category::Hash,
        "FNV-1a",
        0x84222325,
    ));
    fps.push(exact(
        "FNV64.prime_lo",
        Category::Hash,
        "FNV-1a",
        0x000001b3,
    ));

    fps
}

// ---------------------------------------------------------------------------
// ARM Crypto Extensions instruction set
// ---------------------------------------------------------------------------

/// Map mnemonic → algorithm family.
const CRYPTO_INSTRS: &[(&str, &str)] = &[
    // AES
    ("aese", "AES"),
    ("aesmc", "AES"),
    ("aesd", "AES"),
    ("aesimc", "AES"),
    // SHA-1
    ("sha1c", "SHA-1"),
    ("sha1m", "SHA-1"),
    ("sha1p", "SHA-1"),
    ("sha1h", "SHA-1"),
    ("sha1su0", "SHA-1"),
    ("sha1su1", "SHA-1"),
    // SHA-256
    ("sha256h", "SHA-256"),
    ("sha256h2", "SHA-256"),
    ("sha256su0", "SHA-256"),
    ("sha256su1", "SHA-256"),
    // SHA-512
    ("sha512h", "SHA-512"),
    ("sha512h2", "SHA-512"),
    ("sha512su0", "SHA-512"),
    ("sha512su1", "SHA-512"),
    // SHA-3
    ("eor3", "SHA-3"),
    ("rax1", "SHA-3"),
    ("xar", "SHA-3"),
    ("bcax", "SHA-3"),
    // GHASH / PMULL
    ("pmull", "GHASH"),
    ("pmull2", "GHASH"),
    // SM3
    ("sm3ss1", "SM3"),
    ("sm3tt1a", "SM3"),
    ("sm3tt1b", "SM3"),
    ("sm3partw1", "SM3"),
    ("sm3partw2", "SM3"),
    // SM4
    ("sm4e", "SM4"),
    ("sm4ekey", "SM4"),
];

// ---------------------------------------------------------------------------
// ALU mnemonics — values appearing as ALU results are unreliable
// ---------------------------------------------------------------------------

const ALU_MNEMS: &[&str] = &[
    "add", "sub", "mul", "madd", "msub", "and", "orr", "eor", "orn", "bic", "lsl", "lsr", "asr",
    "ror", "sdiv", "udiv", "adds", "subs", "ands", "neg", "negs", "mvn",
];

// Load-immediate mnemonics — values appearing as operands here are "real"
const IMM_LOAD_MNEMS: &[&str] = &[
    "mov", "movz", "movk", "movn", "adr", "adrp", "ldr", "ldrb", "ldrh", "ldur", "ldp", "ldnp",
];

// ---------------------------------------------------------------------------
// Capstone decoding helper
// ---------------------------------------------------------------------------

/// Decode a single ARM64 instruction and return (mnemonic, op_str).
fn decode_inst(inst: u32) -> Option<(String, String)> {
    use capstone::arch::BuildsCapstone;
    thread_local! {
        static CS: capstone::Capstone = capstone::Capstone::new()
            .arm64()
            .mode(capstone::arch::arm64::ArchMode::Arm)
            .build()
            .expect("Capstone arm64 build");
    }
    CS.with(|cs| {
        let insns = cs.disasm_all(&inst.to_le_bytes(), 0).ok()?;
        insns.first().map(|i| {
            (
                i.mnemonic().unwrap_or("").to_string(),
                i.op_str().unwrap_or("").to_string(),
            )
        })
    })
}

/// Extract 32-bit values from operand string.
/// Looks for patterns like `#0x12345678`, `#123`, `#-1`.
fn extract_imm32(op_str: &str) -> Vec<u32> {
    let mut vals = Vec::new();
    for part in op_str.split(',') {
        let part = part.trim();
        if let Some(hex) = part
            .strip_prefix("#0x")
            .or_else(|| part.strip_prefix("#-0x"))
        {
            if let Ok(v) = u64::from_str_radix(hex, 16) {
                vals.push(v as u32);
                continue;
            }
        }
        if let Some(dec) = part.strip_prefix('#') {
            if let Ok(v) = dec.parse::<i64>() {
                vals.push(v as u32);
            }
        }
    }
    vals
}

// ---------------------------------------------------------------------------
// Const scan
// ---------------------------------------------------------------------------

/// Scan trace records for cryptographic constants.
pub fn scan_constants(trace: &Trace) -> ConstScanResult {
    scan_combined(trace).0
}

// ---------------------------------------------------------------------------
// Crypto instructions scan
// ---------------------------------------------------------------------------

/// Scan trace records for ARM Crypto Extensions instructions.
pub fn scan_crypto_instrs(trace: &Trace) -> CryptoInstrResult {
    scan_combined(trace).1
}

// ---------------------------------------------------------------------------
// Combined scan
// ---------------------------------------------------------------------------

/// Single-pass combined scan: crypto constant scan + crypto instruction scan.
pub fn scan_combined(trace: &Trace) -> (ConstScanResult, CryptoInstrResult) {
    use std::collections::HashSet;

    let fingerprints = build_fingerprints();
    let mut const_hits: Vec<ConstHit> = Vec::new();
    let mut fp_hits: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let mut mnem_counts: BTreeMap<String, (usize, Option<usize>, Vec<usize>)> = BTreeMap::new();
    let alu_set: HashSet<&str> = ALU_MNEMS.iter().copied().collect();
    let crypto_mnem_set: HashSet<&str> = CRYPTO_INSTRS.iter().map(|&(m, _)| m).collect();

    for i in 0..trace.len() {
        let rec = trace.record(i);
        let inst = rec.inst;

        let (mnem, op_str) = match decode_inst(inst) {
            Some(d) => d,
            None => continue,
        };

        let is_alu = alu_set.contains(mnem.as_str());
        let is_imm_load = IMM_LOAD_MNEMS.iter().any(|&m| mnem.starts_with(m));

        // --- Crypto instruction detection ---
        if crypto_mnem_set.contains(mnem.as_str()) {
            let entry = mnem_counts
                .entry(mnem.clone())
                .or_insert((0, None, Vec::new()));
            entry.0 += 1;
            if entry.1.is_none() {
                entry.1 = Some(i);
            }
            if entry.2.len() < 10 {
                entry.2.push(i);
            }
        }

        // --- NEON movi SIMD detection (HMAC ipad/opad) ---
        if mnem == "movi" {
            let imm_str = op_str.split(',').nth(1).map(|s| s.trim());
            if let Some(s) = imm_str {
                let cleaned = s.trim_start_matches('#').trim_start_matches("0x");
                if let Ok(v) = u64::from_str_radix(cleaned, 16) {
                    let name = if v == 0x36 {
                        "HMAC.ipad.simd_movi"
                    } else if v == 0x5c {
                        "HMAC.opad.simd_movi"
                    } else {
                        ""
                    };
                    if !name.is_empty() {
                        let hit = ConstHit {
                            fingerprint: name.to_string(),
                            category: Category::Mac,
                            alg: "HMAC".to_string(),
                            idx: i,
                            pc: rec.pc,
                            source: ConstHitSource::Imm,
                            verdict: Verdict::RealSimd,
                            sample_value: v as u32,
                        };
                        fp_hits.entry(name.to_string()).or_default().push(i);
                        const_hits.push(hit);
                        continue;
                    }
                }
            }
        }

        // --- Immediate operand const scan ---
        let imms = extract_imm32(&op_str);
        for &imm in &imms {
            if imm == 0 {
                continue;
            }
            for fp in &fingerprints {
                if (imm & fp.mask) == fp.value {
                    let verdict = if is_imm_load {
                        Verdict::Real
                    } else if is_alu {
                        Verdict::AluOnly
                    } else {
                        Verdict::Real
                    };
                    let hit = ConstHit {
                        fingerprint: fp.name.clone(),
                        category: fp.category,
                        alg: fp.alg.clone(),
                        idx: i,
                        pc: rec.pc,
                        source: ConstHitSource::Imm,
                        verdict,
                        sample_value: imm,
                    };
                    fp_hits.entry(fp.name.clone()).or_default().push(i);
                    const_hits.push(hit);
                }
            }
        }

        // --- Register value const scan ---
        if !is_alu {
            for reg_idx in 0..31 {
                let val = rec.regs[reg_idx] as u32;
                if val == 0 {
                    continue;
                }
                for fp in &fingerprints {
                    if (val & fp.mask) == fp.value {
                        let hit = ConstHit {
                            fingerprint: fp.name.clone(),
                            category: fp.category,
                            alg: fp.alg.clone(),
                            idx: i,
                            pc: rec.pc,
                            source: ConstHitSource::Reg,
                            verdict: Verdict::Real,
                            sample_value: val,
                        };
                        fp_hits.entry(fp.name.clone()).or_default().push(i);
                        const_hits.push(hit);
                    }
                }
            }
        }
    }

    // Build const scan summaries
    let mut summaries: Vec<FingerprintSummary> = fingerprints
        .iter()
        .map(|fp| {
            let idxs = fp_hits.get(&fp.name).cloned().unwrap_or_default();
            FingerprintSummary {
                name: fp.name.clone(),
                category: fp.category,
                alg: fp.alg.clone(),
                total_hits: idxs.len(),
                first_idx: idxs.first().copied(),
                sample_idxs: idxs.iter().take(10).copied().collect(),
                verdict: if idxs.is_empty() {
                    Verdict::Weak
                } else {
                    Verdict::Real
                },
            }
        })
        .collect();
    // Desc by total_hits; name tie-break keeps output deterministic.
    summaries.sort_by(|a, b| {
        b.total_hits
            .cmp(&a.total_hits)
            .then_with(|| a.name.cmp(&b.name))
    });

    let const_result = ConstScanResult {
        hits: const_hits,
        summaries,
        records_scanned: trace.len(),
    };

    // Build crypto instr result
    let instr_hits: Vec<CryptoInstrHit> = mnem_counts
        .into_iter()
        .map(|(mnem, (count, first_idx, sample_idxs))| {
            let alg = CRYPTO_INSTRS
                .iter()
                .find(|&&(m, _)| m == mnem)
                .map(|&(_, a)| a.to_string())
                .unwrap_or_default();
            CryptoInstrHit {
                mnemonic: mnem,
                alg,
                count,
                first_idx,
                sample_idxs,
            }
        })
        .collect();

    (
        const_result,
        CryptoInstrResult {
            hits: instr_hits,
            records_scanned: trace.len(),
        },
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_count() {
        let fps = build_fingerprints();
        assert!(
            fps.len() >= 90,
            "expected at least 90 fingerprints, got {}",
            fps.len()
        );
    }

    #[test]
    fn md5_iv_known() {
        let fps = build_fingerprints();
        let iv0 = fps.iter().find(|f| f.name == "MD5.IV0").unwrap();
        assert_eq!(iv0.value, 0x67452301);
        assert_eq!(iv0.category, Category::Hash);
    }

    #[test]
    fn sha256_known() {
        let fps = build_fingerprints();
        let k0 = fps.iter().find(|f| f.name == "SHA256.K[0]").unwrap();
        assert_eq!(k0.value, 0x428a2f98);
    }

    #[test]
    fn chacha20_expand_known() {
        let fps = build_fingerprints();
        let e0 = fps.iter().find(|f| f.name == "ChaCha20.expand0").unwrap();
        assert_eq!(e0.value, 0x61707865);
    }

    #[test]
    fn hmac_ipad_known() {
        let fps = build_fingerprints();
        let ipad = fps.iter().find(|f| f.name == "HMAC.ipad").unwrap();
        assert_eq!(ipad.value, 0x36363636);
        assert_eq!(ipad.category, Category::Mac);
    }

    #[test]
    fn extract_imm_hex() {
        let vals = extract_imm32("#0xdeadbeef");
        assert_eq!(vals, vec![0xdeadbeef]);
    }

    #[test]
    fn extract_imm_decimal() {
        let vals = extract_imm32("#42");
        assert_eq!(vals, vec![42]);
    }

    #[test]
    fn extract_imm_multiple() {
        let vals = extract_imm32("x0, #0x100, #0x200");
        assert_eq!(vals, vec![0x100, 0x200]);
    }

    #[test]
    fn crypto_instrs_table() {
        assert!(CRYPTO_INSTRS.iter().any(|&(m, _)| m == "aese"));
        assert!(CRYPTO_INSTRS.iter().any(|&(m, _)| m == "sha256h"));
        assert!(CRYPTO_INSTRS.iter().any(|&(m, _)| m == "sm3ss1"));
        assert!(CRYPTO_INSTRS.iter().any(|&(m, _)| m == "sm4e"));
    }
}
