//! Crypto constant scanning over MemShadow.

use std::collections::HashMap;

use serde::Serialize;
use tracemiku_core::prelude::MemShadow;

const CRYPTO_PATTERNS: &[(&str, &str)] = &[
    ("SHA1_H[0]/MD5_A", "01234567"),
    ("SHA1_H[1]/MD5_B", "89abcdef"),
    ("SHA1_H[2]", "fedcba98"),
    ("SHA1_H[3]/MD5_D", "76543210"),
    ("SHA1_H[4]", "f0e1d2c3"),
    ("MD5_T[1]", "78a46ad7"),
    ("SHA256_H[0]", "67e6096a"),
    ("SHA256_H[1]", "85ae67bb"),
    ("SHA256_H[2]", "72f36e3c"),
    ("SHA1_K[0]", "9979825a"),
    ("SHA1_K[1]", "a1ebd96e"),
    ("SHA1_K[2]", "dcbc1b8f"),
    ("SHA1_K[3]", "d6c162ca"),
    ("SHA256_K[0]", "982f8a42"),
    ("SHA256_K[1]", "91443771"),
    ("SHA256_K[2]", "cffbc0b5"),
    ("SHA256_K[3]", "a5dbb5e9"),
    ("SHA512_K[0]", "22ae28d7982f8a42"),
    ("SHA512_K[1]", "cd65ef2391443771"),
    ("TEA_DELTA", "b979379e"),
    ("AES_SBOX[0..3]", "637c777b"),
    ("AES_SBOX[4..7]", "f26b6fc5"),
    ("AES_SBOX[8..11]", "3001672b"),
    ("AES_SBOX[12..15]", "fed7ab76"),
    ("AES_invSBOX[0..3]", "52096ad5"),
    ("AES_Rcon[1..4]", "01020408"),
    ("AES_Te0[0]", "a56363c6"),
    ("HMAC_ipad_x4", "36363636"),
    ("HMAC_opad_x4", "5c5c5c5c"),
    ("CHACHA20_sigma", "657870616e64203332"),
    ("CHACHA20_sigma_full", "657870616e642033322d62797465206b"),
    ("POLY1305_clamp_mask", "ffffff0ffcffff0ffcffff0ffcffff0f"),
    ("SM3_IV[0]", "6f168073"),
    ("SM3_IV[1]", "b9b21449"),
    ("SM3_IV[2]", "d7422417"),
    ("SM3_T[0..15]", "1945cc79"),
    ("SM3_T[16..63]", "8a9d877a"),
    ("SM4_FK[0]", "c6bab1a3"),
    ("SM4_CK[0]", "150e0700"),
    ("SM4_CK[1]", "312a231c"),
    ("Blake2b_IV[0]", "08c9bcf367e6096a"),
    ("CRC32_table[1]", "96300777"),
    ("CRC32C_table[1]", "783bf682"),
    ("FNV32_offset", "c59d1c81"),
    ("FNV32_prime", "93010001"),
    ("MURMUR3_C1", "512d9ecc"),
    ("MURMUR3_C2", "9335871b"),
    ("XXH32_PRIME1", "b179379e"),
    ("XXH32_PRIME2", "77caeb85"),
    ("RC4_identity[0..7]", "0001020304050607"),
];

#[derive(Debug, Clone, Serialize)]
pub struct CryptoHit {
    pub addr: String,
    pub first_idx: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptoPrimitive {
    pub name: &'static str,
    pub pattern: &'static str,
    pub hit_count: usize,
    pub hits: Vec<CryptoHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptoScanResponse {
    pub status: &'static str,
    pub scanned: usize,
    pub primitives: Vec<CryptoPrimitive>,
    pub any_hit: bool,
}

pub fn scan_crypto_memory(mem: &MemShadow) -> CryptoScanResponse {
    if mem.bytes.is_empty() {
        return CryptoScanResponse {
            status: "ready",
            scanned: 0,
            primitives: Vec::new(),
            any_hit: false,
        };
    }

    let parsed = CRYPTO_PATTERNS
        .iter()
        .filter_map(|(name, hex_str)| {
            parse_hex_bytes(hex_str).map(|bytes| (*name, *hex_str, bytes))
        })
        .collect::<Vec<_>>();
    let mut hits_by_pattern = (0..parsed.len()).map(|_| Vec::new()).collect::<Vec<_>>();
    scan_patterns_by_first_byte(mem, &parsed, &mut hits_by_pattern);
    let primitives = parsed
        .into_iter()
        .zip(hits_by_pattern)
        .map(|((name, hex_str, _bytes), hits)| CryptoPrimitive {
            name,
            pattern: hex_str,
            hit_count: hits.len(),
            hits,
        })
        .collect::<Vec<_>>();
    let any_hit = primitives.iter().any(|p| p.hit_count > 0);
    CryptoScanResponse {
        status: "ready",
        scanned: mem.bytes.len(),
        primitives,
        any_hit,
    }
}

fn scan_patterns_by_first_byte(
    mem: &MemShadow,
    patterns: &[(&'static str, &'static str, Vec<u8>)],
    hits_by_pattern: &mut [Vec<CryptoHit>],
) {
    let mut by_first: HashMap<u8, Vec<usize>> = HashMap::new();
    for (idx, (_, _, bytes)) in patterns.iter().enumerate() {
        if let Some(&first) = bytes.first() {
            by_first.entry(first).or_default().push(idx);
        }
    }

    for (&addr, events) in &mem.bytes {
        let Some(last) = events.last() else {
            continue;
        };
        let Some(candidate_idxs) = by_first.get(&last.byte) else {
            continue;
        };
        for &pattern_idx in candidate_idxs {
            if hits_by_pattern[pattern_idx].len() >= 5 {
                continue;
            }
            let pattern = &patterns[pattern_idx].2;
            let Some(first_idx) = match_pattern_at(mem, addr, pattern) else {
                continue;
            };
            hits_by_pattern[pattern_idx].push(CryptoHit {
                addr: format!("{addr:#x}"),
                first_idx: Some(first_idx),
            });
        }
    }
}

fn match_pattern_at(mem: &MemShadow, addr: u64, pattern: &[u8]) -> Option<usize> {
    if pattern.is_empty() {
        return None;
    }
    let mut first_idx: Option<usize> = None;
    for (offset, want) in pattern.iter().enumerate() {
        let events = mem.bytes.get(&(addr + offset as u64))?;
        let last = events.last()?;
        if last.byte != *want {
            return None;
        }
        first_idx = Some(first_idx.map_or(last.idx, |old| old.min(last.idx)));
    }
    first_idx
}

fn parse_hex_bytes(hex_str: &str) -> Option<Vec<u8>> {
    let s = hex_str.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < s.len() {
        let b = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        out.push(b);
        i += 2;
    }
    Some(out)
}
