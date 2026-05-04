//! GET /api/auto-phase-detect.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracemiku_core::prelude::MemShadow;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AutoPhaseQuery {
    #[serde(default = "default_detect_byte_streams")]
    pub detect_byte_streams: bool,
}

fn default_detect_byte_streams() -> bool {
    true
}

#[derive(Debug, Serialize, Clone)]
pub struct PhaseEntry {
    pub idx: usize,
    pub phase: String,
    pub info: String,
}

#[derive(Debug, Serialize)]
pub struct AutoPhaseResponse {
    pub status: &'static str,
    pub trace_records: usize,
    pub phases: Vec<PhaseEntry>,
}

const CRYPTO_PHASE_PATTERNS: &[(&str, &[u8])] = &[
    ("sha1_init", &[0x01, 0x23, 0x45, 0x67]),
    ("sha1_init_h1", &[0x89, 0xab, 0xcd, 0xef]),
    ("sha1_init_h4", &[0xf0, 0xe1, 0xd2, 0xc3]),
    ("sha256_init", &[0x67, 0xe6, 0x09, 0x6a]),
];

pub async fn auto_phase_detect_handler(
    State(state): State<AppState>,
    Query(q): Query<AutoPhaseQuery>,
) -> Json<AutoPhaseResponse> {
    Json(
        tokio::task::spawn_blocking(move || auto_phase_response(&state, q))
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(target: "tracemiku-server", "auto phase worker failed: {err}");
                AutoPhaseResponse {
                    status: "error",
                    trace_records: 0,
                    phases: Vec::new(),
                }
            }),
    )
}

fn auto_phase_response(state: &AppState, q: AutoPhaseQuery) -> AutoPhaseResponse {
    let mut phases = Vec::new();
    append_jni_phases(state, &mut phases);
    let mem = match state.inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            phases.sort_by_key(|p| p.idx);
            return AutoPhaseResponse {
                status,
                trace_records: state.inner.trace.len(),
                phases,
            };
        }
    };
    append_crypto_phases(mem, &mut phases);
    if q.detect_byte_streams {
        append_byte_stream_phases(mem, &mut phases);
    }
    phases.sort_by_key(|p| p.idx);
    let mut dedup = Vec::<PhaseEntry>::new();
    for phase in phases {
        if dedup
            .last()
            .is_some_and(|prev| prev.phase == phase.phase && prev.idx.abs_diff(phase.idx) < 50)
        {
            continue;
        }
        dedup.push(phase);
    }
    AutoPhaseResponse {
        status: "ready",
        trace_records: state.inner.trace.len(),
        phases: dedup,
    }
}

fn append_jni_phases(state: &AppState, phases: &mut Vec<PhaseEntry>) {
    let path = state.inner.trace_dir.join("jni_hooks.jsonl");
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(idx) = value
            .get("trace_idx")
            .and_then(Value::as_u64)
            .map(|v| v as usize)
        else {
            continue;
        };
        let Some(op) = value.get("id").and_then(Value::as_str) else {
            continue;
        };
        match op {
            "GetStringUTFChars" => {
                let Some(ret) = value.get("ret").and_then(Value::as_str) else {
                    continue;
                };
                if !ret.starts_with("0x") {
                    phases.push(PhaseEntry {
                        idx,
                        phase: "jni_input".to_string(),
                        info: format!("GetStringUTFChars '{}'", truncate(ret, 32)),
                    });
                }
            }
            "NewStringUTF" => {
                let Some(bytes) = value
                    .get("args")
                    .and_then(|args| args.get("bytes"))
                    .and_then(Value::as_str)
                else {
                    continue;
                };
                phases.push(PhaseEntry {
                    idx,
                    phase: "jni_output".to_string(),
                    info: format!("NewStringUTF '{}'", truncate(bytes, 48)),
                });
            }
            _ => {}
        }
    }
}

fn append_crypto_phases(mem: &MemShadow, phases: &mut Vec<PhaseEntry>) {
    for (label, pattern) in CRYPTO_PHASE_PATTERNS {
        for &addr in mem.bytes.keys() {
            let mut first_idx: Option<usize> = None;
            let mut matched = true;
            for (offset, want) in pattern.iter().enumerate() {
                let Some(events) = mem.bytes.get(&(addr + offset as u64)) else {
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
                if let Some(first) = events.first() {
                    first_idx = Some(first_idx.map_or(first.idx, |old| old.min(first.idx)));
                }
            }
            if matched {
                if let Some(idx) = first_idx {
                    phases.push(PhaseEntry {
                        idx,
                        phase: (*label).to_string(),
                        info: format!("IV pattern at {addr:#x}"),
                    });
                }
            }
        }
    }
}

fn append_byte_stream_phases(mem: &MemShadow, phases: &mut Vec<PhaseEntry>) {
    let writes = mem
        .writes
        .iter()
        .filter(|w| w.size == 1)
        .collect::<Vec<_>>();
    for window in writes.windows(4) {
        if window[1].addr == window[0].addr + 1
            && window[2].addr == window[1].addr + 1
            && window[3].addr == window[2].addr + 1
            && window[3].idx.saturating_sub(window[0].idx) < 500
        {
            phases.push(PhaseEntry {
                idx: window[0].idx,
                phase: "byte_stream_write".to_string(),
                info: format!("4+ contiguous strb starting {:#x}", window[0].addr),
            });
        }
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}
