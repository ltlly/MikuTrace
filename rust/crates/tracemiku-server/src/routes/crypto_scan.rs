//! GET /api/crypto-scan.

use axum::extract::State;
use axum::Json;
use serde::Serialize;

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
    pub scanned: usize,
    pub primitives: Vec<CryptoPrimitive>,
    pub any_hit: bool,
}

pub async fn crypto_scan_handler(State(state): State<AppState>) -> Json<CryptoScanResponse> {
    if state.inner.memshadow().bytes.is_empty() {
        return Json(CryptoScanResponse {
            scanned: 0,
            primitives: Vec::new(),
            any_hit: false,
        });
    }
    let addrs = state
        .inner
        .memshadow()
        .bytes
        .keys()
        .copied()
        .collect::<Vec<_>>();
    let mut primitives = Vec::with_capacity(CRYPTO_PATTERNS.len());
    for (name, hex_str) in CRYPTO_PATTERNS {
        let pattern = parse_hex_bytes(hex_str).unwrap_or_default();
        let hits = scan_pattern(&state, &addrs, &pattern);
        primitives.push(CryptoPrimitive {
            name,
            pattern: hex_str,
            hit_count: hits.len(),
            hits,
        });
    }
    let any_hit = primitives.iter().any(|p| p.hit_count > 0);
    Json(CryptoScanResponse {
        scanned: addrs.len(),
        primitives,
        any_hit,
    })
}

fn scan_pattern(state: &AppState, addrs: &[u64], pattern: &[u8]) -> Vec<CryptoHit> {
    let mut hits = Vec::new();
    if pattern.is_empty() {
        return hits;
    }
    for &addr in addrs {
        let mut first_idx: Option<usize> = None;
        let mut matched = true;
        for (offset, want) in pattern.iter().enumerate() {
            let Some(events) = state.inner.memshadow().bytes.get(&(addr + offset as u64)) else {
                matched = false;
                break;
            };
            let Some(last) = events.last() else {
                matched = false;
                break;
            };
            if last.byte != *want {
                matched = false;
                break;
            }
            first_idx = Some(first_idx.map_or(last.idx, |old| old.min(last.idx)));
        }
        if matched {
            hits.push(CryptoHit {
                addr: format!("{addr:#x}"),
                first_idx,
            });
            if hits.len() >= 5 {
                break;
            }
        }
    }
    hits
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
