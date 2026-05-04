//! POST /api/hash-input-search.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use hmac::{Hmac, Mac};
use md5::Md5;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tracemiku_core::prelude::MemShadow;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct HashInputSearchRequest {
    pub target_bytes: String,
    pub inputs: Vec<String>,
    #[serde(default = "default_keys")]
    pub keys: Vec<String>,
    #[serde(default = "default_algos")]
    pub algos: Vec<String>,
    #[serde(default = "default_combos")]
    pub combos: Vec<String>,
    #[serde(default = "default_prefix_bytes")]
    pub prefix_bytes: usize,
    #[serde(default)]
    pub search_in_mem: bool,
}

fn default_keys() -> Vec<String> {
    vec![String::new()]
}

fn default_algos() -> Vec<String> {
    ["sha1", "md5", "sha256"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_combos() -> Vec<String> {
    ["plain", "prefix_key", "suffix_key", "key_prefix_input"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn default_prefix_bytes() -> usize {
    8
}

#[derive(Debug, Serialize)]
pub struct HashMemHit {
    pub addr: String,
    pub idx: usize,
}

#[derive(Debug, Serialize)]
pub struct HashFound {
    pub algo: String,
    pub input: String,
    pub key: String,
    pub combo: String,
    pub msg_hex: String,
    pub hash_full: String,
    pub full_match: Option<bool>,
    pub matches_n_bytes: Option<usize>,
    pub found_in_mem: Option<Vec<HashMemHit>>,
    pub match_type: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct HashInputSearchResponse {
    pub target_prefix: String,
    pub tried_combos: usize,
    pub found: Vec<HashFound>,
    pub found_count: usize,
}

pub async fn hash_input_search_handler(
    State(state): State<AppState>,
    Json(req): Json<HashInputSearchRequest>,
) -> Result<Json<HashInputSearchResponse>, StatusCode> {
    let response = tokio::task::spawn_blocking(move || hash_input_search_response(&state, req))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "hash input search worker failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })??;
    Ok(Json(response))
}

fn hash_input_search_response(
    state: &AppState,
    req: HashInputSearchRequest,
) -> Result<HashInputSearchResponse, StatusCode> {
    let target = parse_hex_bytes(&req.target_bytes).ok_or(StatusCode::BAD_REQUEST)?;
    let prefix_n = req.prefix_bytes.max(4).min(target.len());
    let target_prefix = &target[..prefix_n];
    for algo in &req.algos {
        if !is_valid_algo(algo) {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let keys = if req.keys.is_empty() {
        vec![String::new()]
    } else {
        req.keys.clone()
    };
    let mem = req.search_in_mem.then(|| state.inner.memshadow());

    let mut found = Vec::new();
    let mut tried = 0usize;
    for input in &req.inputs {
        for key in &keys {
            for combo in &req.combos {
                let msg = combo_msg(combo, input, key).ok_or(StatusCode::BAD_REQUEST)?;
                for algo in &req.algos {
                    if algo.starts_with("hmac-") && key.is_empty() {
                        continue;
                    }
                    let hash = hash_it(
                        algo,
                        key.as_bytes(),
                        if algo.starts_with("hmac-") {
                            input.as_bytes()
                        } else {
                            &msg
                        },
                    )
                    .ok_or(StatusCode::BAD_REQUEST)?;
                    tried += 1;
                    if hash.starts_with(target_prefix) {
                        let full_match = hash.starts_with(&target);
                        found.push(HashFound {
                            algo: algo.clone(),
                            input: input.clone(),
                            key: key.clone(),
                            combo: combo.clone(),
                            msg_hex: preview_hex(&msg),
                            hash_full: hex_encode(&hash),
                            full_match: Some(full_match),
                            matches_n_bytes: Some(if full_match { target.len() } else { prefix_n }),
                            found_in_mem: None,
                            match_type: None,
                        });
                        continue;
                    }
                    if let Some(mem) = mem {
                        let mem_hits = find_in_mem(mem, &hash[..prefix_n], 1);
                        if !mem_hits.is_empty() {
                            found.push(HashFound {
                                algo: algo.clone(),
                                input: input.clone(),
                                key: key.clone(),
                                combo: combo.clone(),
                                msg_hex: preview_hex(&msg),
                                hash_full: hex_encode(&hash),
                                full_match: None,
                                matches_n_bytes: None,
                                found_in_mem: Some(mem_hits),
                                match_type: Some("in_mem"),
                            });
                        }
                    }
                }
            }
        }
    }
    Ok(HashInputSearchResponse {
        target_prefix: hex_encode(target_prefix),
        tried_combos: tried,
        found_count: found.len(),
        found,
    })
}

fn is_valid_algo(algo: &str) -> bool {
    matches!(
        algo,
        "sha1"
            | "md5"
            | "sha256"
            | "sha384"
            | "sha512"
            | "hmac-sha1"
            | "hmac-md5"
            | "hmac-sha256"
            | "crc32"
    )
}

fn combo_msg(combo: &str, input: &str, key: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match combo {
        "plain" => out.extend_from_slice(input.as_bytes()),
        "prefix_key" => {
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(input.as_bytes());
        }
        "suffix_key" => {
            out.extend_from_slice(input.as_bytes());
            out.extend_from_slice(key.as_bytes());
        }
        "key_prefix_input" => {
            out.extend_from_slice(key.as_bytes());
            out.push(0);
            out.extend_from_slice(input.as_bytes());
        }
        "input_pipe_key" => {
            out.extend_from_slice(input.as_bytes());
            out.push(b'|');
            out.extend_from_slice(key.as_bytes());
        }
        "key_dot_input" => {
            out.extend_from_slice(key.as_bytes());
            out.push(b'.');
            out.extend_from_slice(input.as_bytes());
        }
        _ => return None,
    }
    Some(out)
}

fn hash_it(algo: &str, key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    Some(match algo {
        "sha1" => Sha1::digest(msg).to_vec(),
        "md5" => Md5::digest(msg).to_vec(),
        "sha256" => Sha256::digest(msg).to_vec(),
        "sha384" => Sha384::digest(msg).to_vec(),
        "sha512" => Sha512::digest(msg).to_vec(),
        "hmac-sha1" => hmac_sha1(key, msg)?,
        "hmac-md5" => hmac_md5(key, msg)?,
        "hmac-sha256" => hmac_sha256(key, msg)?,
        "crc32" => {
            let crc = crc32fast::hash(msg);
            let mut out = Vec::with_capacity(8);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&crc.to_be_bytes());
            out
        }
        _ => return None,
    })
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).ok()?;
    mac.update(msg);
    Some(mac.finalize().into_bytes().to_vec())
}

fn hmac_md5(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let mut mac = Hmac::<Md5>::new_from_slice(key).ok()?;
    mac.update(msg);
    Some(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(msg);
    Some(mac.finalize().into_bytes().to_vec())
}

fn find_in_mem(mem: &MemShadow, prefix: &[u8], max_hits: usize) -> Vec<HashMemHit> {
    let mut hits = Vec::new();
    for &addr in mem.bytes.keys() {
        let mut last_idx = None;
        let mut matched = true;
        for (offset, want) in prefix.iter().enumerate() {
            let Some(events) = mem.bytes.get(&(addr + offset as u64)) else {
                matched = false;
                break;
            };
            let Some(event) = events.last() else {
                matched = false;
                break;
            };
            if event.byte != *want {
                matched = false;
                break;
            }
            last_idx = Some(event.idx);
        }
        if matched {
            hits.push(HashMemHit {
                addr: format!("{addr:#x}"),
                idx: last_idx.unwrap_or(0),
            });
            if max_hits > 0 && hits.len() >= max_hits {
                break;
            }
        }
    }
    hits
}

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let cleaned = s.replace("0x", "").replace("0X", "").replace(' ', "");
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        out.push(u8::from_str_radix(&cleaned[i..i + 2], 16).ok()?);
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn preview_hex(bytes: &[u8]) -> String {
    let take = bytes.len().min(40);
    let mut out = hex_encode(&bytes[..take]);
    if bytes.len() > 40 {
        out.push_str("...");
    }
    out
}
