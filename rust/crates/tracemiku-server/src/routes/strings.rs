//! GET /api/strings — printable ASCII runs from MemShadow.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct StringsQuery {
    #[serde(default = "default_min_len")]
    pub min_len: usize,
    #[serde(default)]
    pub q: String,
    /// -1 = no cursor filter; >=0 = only strings whose every byte was written
    /// at idx <= cursor. (Python uses signed int and -1 sentinel; preserved.)
    #[serde(default = "default_cursor")]
    pub cursor: i64,
    #[serde(default)]
    pub limit: usize,
}

fn default_min_len() -> usize {
    4
}
fn default_cursor() -> i64 {
    -1
}

#[derive(Debug, Serialize)]
pub struct StringEntry {
    pub addr: String,
    pub len: usize,
    pub str: String,
}

#[derive(Debug, Serialize)]
pub struct StringsResponse {
    pub status: &'static str,
    pub count: usize,
    pub cursor: i64,
    pub strings: Vec<StringEntry>,
}

pub async fn strings_handler(
    State(state): State<AppState>,
    Query(q): Query<StringsQuery>,
) -> Json<StringsResponse> {
    let inner = state.inner.clone();
    Json(
        tokio::task::spawn_blocking(move || strings_response(&inner, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "strings worker failed: {err}");
                StringsResponse {
                    status: "error",
                    count: 0,
                    cursor: -1,
                    strings: Vec::new(),
                }
            }),
    )
}

fn strings_response(inner: &crate::state::AppStateInner, q: StringsQuery) -> StringsResponse {
    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            return StringsResponse {
                status,
                count: 0,
                cursor: q.cursor,
                strings: Vec::new(),
            };
        }
    };
    let mut results = mem.find_strings(q.min_len);
    if q.cursor >= 0 {
        let cursor = q.cursor as u64;
        results.retain(|(addr, s)| {
            (0..s.len() as u64).all(|o| {
                let (b, _kind, src) = mem.byte_at(*addr + o, cursor);
                matches!((b, src), (Some(_), Some(idx)) if (idx as u64) <= cursor)
            })
        });
    }
    if !q.q.is_empty() {
        let needle = q.q.to_lowercase();
        results.retain(|(_a, s)| s.to_lowercase().contains(&needle));
    }
    if q.limit > 0 && results.len() > q.limit {
        results.truncate(q.limit);
    }
    let strings = results
        .into_iter()
        .map(|(addr, s)| StringEntry {
            addr: format!("{addr:#x}"),
            len: s.len(),
            str: s,
        })
        .collect::<Vec<_>>();
    StringsResponse {
        status: "ready",
        count: strings.len(),
        cursor: q.cursor,
        strings,
    }
}
