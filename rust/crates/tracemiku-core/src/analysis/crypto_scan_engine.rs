//! Crypto constant scanning over MemShadow.

use std::collections::HashMap;

use crate::prelude::MemShadow;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectedCryptoContext {
    pub algorithm: String,
    pub state_addr: String,
    pub init_idx: usize,
    pub final_update_idx: usize,
    pub state_le_hex: String,
    pub digest_hex: String,
}

struct ContextSpec {
    algorithm: &'static str,
    iv: &'static [u8],
    reverse_words: bool,
}

const CONTEXT_SPECS: &[ContextSpec] = &[
    // SHA-1 (20 bytes LE words)
    ContextSpec {
        algorithm: "SHA-1",
        iv: &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xf0, 0xe1, 0xd2, 0xc3,
        ],
        reverse_words: true,
    },
    // SHA-1 (20 bytes BE words)
    ContextSpec {
        algorithm: "SHA-1",
        iv: &[
            0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32,
            0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0,
        ],
        reverse_words: false,
    },
    // MD5 (16 bytes LE words)
    ContextSpec {
        algorithm: "MD5",
        iv: &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ],
        reverse_words: false,
    },
    // SHA-256 (32 bytes LE words)
    ContextSpec {
        algorithm: "SHA-256",
        iv: &[
            0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb, 0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5,
            0x4f, 0xa5, 0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b, 0xab, 0xd9, 0x83, 0x1f,
            0x19, 0xcd, 0xe0, 0x5b,
        ],
        reverse_words: true,
    },
    // SHA-256 (32 bytes BE words)
    ContextSpec {
        algorithm: "SHA-256",
        iv: &[
            0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f,
            0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab,
            0x5b, 0xe0, 0xcd, 0x19,
        ],
        reverse_words: false,
    },
    // SM3 (32 bytes LE words)
    ContextSpec {
        algorithm: "SM3",
        iv: &[
            0x6f, 0x16, 0x80, 0x73, 0xb9, 0xb2, 0x14, 0x49, 0xd7, 0x42, 0x24, 0x17, 0x00, 0x06,
            0x8a, 0xda, 0xbc, 0x30, 0x6f, 0xa9, 0xaa, 0x38, 0x31, 0x16, 0x4d, 0xee, 0x8d, 0xe3,
            0x4e, 0x0e, 0xfb, 0xb0,
        ],
        reverse_words: true,
    },
    // SM3 (32 bytes BE words)
    ContextSpec {
        algorithm: "SM3",
        iv: &[
            0x73, 0x80, 0x16, 0x6f, 0x49, 0x14, 0xb2, 0xb9, 0x17, 0x24, 0x42, 0xd7, 0xda, 0x8a,
            0x06, 0x00, 0xa9, 0x6f, 0x30, 0xbc, 0x16, 0x31, 0x38, 0xaa, 0xe3, 0x8d, 0xee, 0x4d,
            0xb0, 0xfb, 0x0e, 0x4e,
        ],
        reverse_words: false,
    },
    // ChaCha20 ("expand 32-byte k", 16 bytes)
    ContextSpec {
        algorithm: "ChaCha20",
        iv: b"expand 32-byte k",
        reverse_words: false,
    },
];

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

pub fn scan_crypto_contexts(mem: &MemShadow) -> Vec<DetectedCryptoContext> {
    if mem.bytes.is_empty() {
        return Vec::new();
    }

    let mut by_first: HashMap<u8, Vec<usize>> = HashMap::new();
    for (spec_idx, spec) in CONTEXT_SPECS.iter().enumerate() {
        if let Some(&first) = spec.iv.first() {
            by_first.entry(first).or_default().push(spec_idx);
        }
    }

    let mut raw_hits: Vec<(usize, u64, usize, usize)> = Vec::new();

    for (&addr, events) in &mem.bytes {
        let mut candidate_specs: Vec<usize> = Vec::new();
        for ev in events {
            if let Some(specs) = by_first.get(&ev.byte) {
                for &s in specs {
                    if !candidate_specs.contains(&s) {
                        candidate_specs.push(s);
                    }
                }
            }
        }
        if candidate_specs.is_empty() {
            continue;
        }

        for spec_idx in candidate_specs {
            let spec = &CONTEXT_SPECS[spec_idx];
            let intervals = match_pattern_intervals_at(mem, addr, spec.iv);
            for (enter_idx, leave_idx) in intervals {
                raw_hits.push((spec_idx, addr, enter_idx, leave_idx));
            }
        }
    }

    // Filter out MD5 hits that are actually part of SHA-1 at the same state_addr
    let sha1_hits: Vec<(u64, usize, usize)> = raw_hits
        .iter()
        .filter(|&&(spec_idx, _, _, _)| CONTEXT_SPECS[spec_idx].algorithm == "SHA-1")
        .map(|&(_, addr, enter, leave)| (addr, enter, leave))
        .collect();

    raw_hits.retain(|&(spec_idx, addr, enter, leave)| {
        if CONTEXT_SPECS[spec_idx].algorithm == "MD5" {
            let overlaps_sha1 = sha1_hits.iter().any(|&(s_addr, s_enter, s_leave)| {
                s_addr == addr
                    && ((enter <= s_leave && s_enter <= leave) || s_enter.abs_diff(enter) <= 64)
            });
            if overlaps_sha1 {
                return false;
            }
            // Also check if bytes +16..+20 equal SHA-1's H4 (f0 e1 d2 c3) at enter_idx or leave_idx
            let sha1_h4 = [0xf0u8, 0xe1, 0xd2, 0xc3];
            let has_h4_at_enter = (0..4)
                .all(|k| mem.byte_at(addr + 16 + k as u64, enter as u64).0 == Some(sha1_h4[k]));
            if has_h4_at_enter {
                return false;
            }
        }
        true
    });

    raw_hits.sort_by_key(|&(_, addr, enter, spec_idx)| (addr, enter, spec_idx));

    let mut out = Vec::with_capacity(raw_hits.len());
    for (i, &(spec_idx, addr, init_idx, _leave_idx)) in raw_hits.iter().enumerate() {
        let spec = &CONTEXT_SPECS[spec_idx];
        let iv_len = spec.iv.len();

        let next_init_idx = raw_hits[i + 1..]
            .iter()
            .find(|&&(_, next_addr, next_enter, _)| next_addr == addr && next_enter > init_idx)
            .map(|&(_, _, next_enter, _)| next_enter)
            .unwrap_or(usize::MAX);

        let final_update_idx =
            find_context_final_update_idx(mem, addr, iv_len, init_idx, next_init_idx);

        let mut state_bytes = Vec::with_capacity(iv_len);
        for offset in 0..iv_len {
            let (b, _, _) = mem.byte_at(addr + offset as u64, final_update_idx as u64);
            state_bytes.push(b.unwrap_or(spec.iv[offset]));
        }

        let state_le_hex = hex_encode(&state_bytes);
        let digest_hex = if spec.reverse_words {
            let mut digest_bytes = Vec::with_capacity(iv_len);
            for chunk in state_bytes.chunks(4) {
                for &b in chunk.iter().rev() {
                    digest_bytes.push(b);
                }
            }
            hex_encode(&digest_bytes)
        } else {
            state_le_hex.clone()
        };

        out.push(DetectedCryptoContext {
            algorithm: spec.algorithm.to_string(),
            state_addr: format!("{addr:#x}"),
            init_idx,
            final_update_idx,
            state_le_hex,
            digest_hex,
        });
    }

    out.sort_by(|a, b| {
        a.init_idx
            .cmp(&b.init_idx)
            .then_with(|| a.state_addr.cmp(&b.state_addr))
            .then_with(|| a.algorithm.cmp(&b.algorithm))
    });
    out
}

fn find_context_final_update_idx(
    mem: &MemShadow,
    addr: u64,
    iv_len: usize,
    init_idx: usize,
    next_init_idx: usize,
) -> usize {
    let num_words = iv_len / 4;
    let mut word_writes: Vec<usize> = Vec::new();
    for w in 0..num_words {
        if let Some(evs) = mem.bytes.get(&(addr + (w * 4) as u64)) {
            for ev in evs {
                if ev.idx > init_idx && ev.idx < next_init_idx && (ev.kind == "w" || ev.kind == "x")
                {
                    word_writes.push(ev.idx);
                }
            }
        }
    }
    word_writes.sort_unstable();
    word_writes.dedup();

    // Find the latest cluster of writes (within a 256-instruction window)
    // that updates all `num_words` 32-bit state words with non-trivial digest values.
    let mut best_cluster_end: Option<usize> = None;
    for &end_idx in &word_writes {
        let window_start = end_idx.saturating_sub(256).max(init_idx + 1);
        let all_words_written = (0..num_words).all(|w| {
            let mut written_in_window = false;
            for b in 0..4 {
                if let Some(evs) = mem.bytes.get(&(addr + (w * 4 + b) as u64)) {
                    let lo = evs.partition_point(|e| e.idx < window_start);
                    let hi = evs.partition_point(|e| e.idx <= end_idx);
                    if evs[lo..hi].iter().any(|e| e.kind == "w" || e.kind == "x") {
                        written_in_window = true;
                    }
                }
            }
            written_in_window
        });
        if !all_words_written {
            continue;
        }
        let non_zero_words = (0..num_words)
            .filter(|&w| {
                let mut word = [0u8; 4];
                for (b, slot) in word.iter_mut().enumerate() {
                    *slot = mem
                        .byte_at(addr + (w * 4 + b) as u64, end_idx as u64)
                        .0
                        .unwrap_or(0);
                }
                let val = u32::from_le_bytes(word);
                let nonzero_bytes = word.iter().filter(|&&byte| byte != 0).count();
                val != 0 && nonzero_bytes >= 2
            })
            .count();
        if non_zero_words == num_words {
            best_cluster_end = Some(end_idx);
        }
    }

    if let Some(end_idx) = best_cluster_end {
        return end_idx;
    }

    let mut fallback = init_idx;
    for offset in 0..iv_len {
        if let Some(evs) = mem.bytes.get(&(addr + offset as u64)) {
            for ev in evs {
                if ev.idx > init_idx
                    && ev.idx < next_init_idx
                    && (ev.kind == "w" || ev.kind == "x")
                    && ev.idx > fallback
                {
                    fallback = ev.idx;
                }
            }
        }
    }
    fallback
}

fn match_pattern_intervals_at(mem: &MemShadow, addr: u64, pattern: &[u8]) -> Vec<(usize, usize)> {
    if pattern.is_empty() {
        return Vec::new();
    }
    let mut current = byte_validity_intervals(mem, addr, pattern[0]);
    if current.is_empty() {
        return Vec::new();
    }
    for (offset, &want) in pattern.iter().enumerate().skip(1) {
        let next = byte_validity_intervals(mem, addr + offset as u64, want);
        if next.is_empty() {
            return Vec::new();
        }
        current = intersect_intervals(&current, &next);
        if current.is_empty() {
            return Vec::new();
        }
    }
    current
}

fn byte_validity_intervals(mem: &MemShadow, addr: u64, want: u8) -> Vec<(usize, usize)> {
    let mut intervals: Vec<(usize, usize)> = Vec::new();
    let mut active_start: Option<usize> = None;

    if let Some(snap) = &mem.snapshot {
        if snap.byte_at(addr) == Some(want) {
            active_start = Some(0);
        }
    }

    if let Some(evs) = mem.bytes.get(&addr) {
        for ev in evs {
            if ev.byte == want {
                if active_start.is_none() {
                    active_start = Some(ev.idx);
                }
            } else if let Some(start) = active_start.take() {
                if start < ev.idx {
                    intervals.push((start, ev.idx));
                }
            }
        }
    }

    if let Some(start) = active_start {
        intervals.push((start, usize::MAX));
    }

    intervals
}

fn intersect_intervals(a: &[(usize, usize)], b: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < a.len() && j < b.len() {
        let start = a[i].0.max(b[j].0);
        let end = a[i].1.min(b[j].1);
        if start < end {
            out.push((start, end));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}
