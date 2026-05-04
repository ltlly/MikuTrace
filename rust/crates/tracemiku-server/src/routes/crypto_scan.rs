//! GET /api/crypto-scan.

use std::collections::HashMap;

use axum::extract::State;
use axum::Json;
use serde::Serialize;

use tracemiku_core::prelude::MemShadow;

use crate::state::AppState;

const CRYPTO_PATTERNS: &[(&str, &str)] = &[
    ("SHA1_H[0]/MD5_A", "01234567"),
    ("SHA1_H[1]/MD5_B", "89abcdef"),
    ("SHA1_H[2]", "fedcba98"),
    ("SHA1_H[3]/MD5_D", "76543210"),
    ("SHA1_H[4]", "f0e1d2c3"),
    ("SHA256_H[0]", "67e6096a"),
    ("SHA256_H[1]", "85ae67bb"),
    ("SHA256_H[2]", "72f36e3c"),
    ("TEA_DELTA", "b979379e"),
    ("AES_SBOX[0..3]", "637c777b"),
    ("AES_SBOX[4..7]", "f26b6fc5"),
    ("AES_invSBOX[0..3]", "52096ad5"),
    ("AES_Rcon[1..4]", "01020408"),
    ("HMAC_ipad_x4", "36363636"),
    ("HMAC_opad_x4", "5c5c5c5c"),
    ("CHACHA20_sigma", "657870616e64203332"),
    ("SM3_IV[0]", "6f168073"),
    ("SM3_IV[1]", "b9b21449"),
    ("SM3_IV[2]", "d7422417"),
    ("SM4_FK[0]", "c6bab1a3"),
    ("Blake2b_IV[0]", "08c9bcf367e6096a"),
    ("CRC32_table[1]", "96300777"),
];

#[derive(Debug, Serialize)]
pub struct CryptoHit {
    pub addr: String,
    pub first_idx: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct CryptoPrimitive {
    pub name: &'static str,
    pub pattern: &'static str,
    pub hit_count: usize,
    pub hits: Vec<CryptoHit>,
}

#[derive(Debug, Serialize)]
pub struct CryptoScanResponse {
    pub status: &'static str,
    pub scanned: usize,
    pub primitives: Vec<CryptoPrimitive>,
    pub any_hit: bool,
}

pub async fn crypto_scan_handler(State(state): State<AppState>) -> Json<CryptoScanResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || crypto_scan_response(&inner))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "crypto scan worker failed: {err}");
                CryptoScanResponse {
                    status: "error",
                    scanned: 0,
                    primitives: Vec::new(),
                    any_hit: false,
                }
            }),
    )
}

fn crypto_scan_response(inner: &crate::state::AppStateInner) -> CryptoScanResponse {
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            return CryptoScanResponse {
                status,
                scanned: 0,
                primitives: Vec::new(),
                any_hit: false,
            };
        }
    };
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

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).ok()?);
    }
    Some(out)
}
