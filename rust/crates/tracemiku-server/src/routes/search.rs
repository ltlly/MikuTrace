//! GET /api/search?pattern=&max_results=
//!
//! Regex search over decoded instruction text. The response mirrors the
//! Python webui shape used by command search and xref navigation.

use axum::extract::{Query, State};
use axum::Json;
use std::cmp::Reverse;
use std::collections::BinaryHeap;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use tracemiku_core::prelude::*;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub pattern: String,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
}

fn default_max_results() -> usize {
    2000
}

#[derive(Debug, Serialize)]
pub struct SearchHit {
    pub idx: usize,
    pub pc: String,
    pub rel: Option<String>,
    pub func: Option<String>,
    pub off: Option<String>,
    pub asm: String,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub count: usize,
    pub pattern: String,
    pub hits: Vec<SearchHit>,
}

pub async fn search_handler(
    State(state): State<AppState>,
    Query(q): Query<SearchQuery>,
) -> Json<SearchResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || search_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "search worker failed: {err}");
                SearchResponse {
                    count: 0,
                    pattern: String::new(),
                    hits: Vec::new(),
                }
            }),
    )
}

fn search_response(inner: &crate::state::AppStateInner, q: SearchQuery) -> SearchResponse {
    let max_results = q.max_results.max(1);
    let re = compile_pattern(&q.pattern);
    let base = inner
        .meta
        .module
        .as_ref()
        .and_then(|m| u64::from_str_radix(m.base.trim_start_matches("0x"), 16).ok());
    let mut hits = Vec::new();
    let mut groups = Vec::new();

    for idxs in inner.index.pc_to_idxs.values() {
        let Some(&first_idx) = idxs.first() else {
            continue;
        };
        let r = inner.trace.record(first_idx);
        let d = decode(r.pc, r.inst);
        let asm = format!("{} {}", d.mnemonic, d.op_str).trim().to_string();
        if !matches_pattern(&re, &q.pattern, &asm) {
            continue;
        }
        groups.push(MatchedGroup { asm, idxs });
    }

    let mut heap = BinaryHeap::new();
    for (group_idx, group) in groups.iter().enumerate() {
        if let Some(&idx) = group.idxs.first() {
            heap.push(Reverse((idx, group_idx, 0usize)));
        }
    }

    while let Some(Reverse((i, group_idx, pos))) = heap.pop() {
        let group = &groups[group_idx];
        let r = inner.trace.record(i);
        let (func_name, func_off) = inner.symbols.lookup(r.pc);
        let (func, off) = if func_name == "?" {
            (None, None)
        } else {
            (Some(func_name), Some(format!("{func_off:#x}")))
        };
        hits.push(SearchHit {
            idx: i,
            pc: format!("{:#x}", r.pc),
            rel: base.map(|b| format!("{:#x}", r.pc.wrapping_sub(b))),
            func,
            off,
            asm: group.asm.clone(),
        });
        if hits.len() >= max_results {
            break;
        }
        let next_pos = pos + 1;
        if let Some(&next_idx) = group.idxs.get(next_pos) {
            heap.push(Reverse((next_idx, group_idx, next_pos)));
        }
    }

    SearchResponse {
        count: hits.len(),
        pattern: q.pattern,
        hits,
    }
}

struct MatchedGroup<'a> {
    asm: String,
    idxs: &'a [usize],
}

fn compile_pattern(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .ok()
}

fn matches_pattern(re: &Option<Regex>, pattern: &str, asm: &str) -> bool {
    if let Some(re) = re {
        re.is_match(asm)
    } else {
        asm.to_lowercase().contains(&pattern.to_lowercase())
    }
}
