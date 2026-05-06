//! POST /api/diff-traces.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct DiffTracesRequest {
    pub traces: Vec<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub show_offsets: bool,
    #[serde(default)]
    pub show_per_byte: bool,
}

#[derive(Debug, Serialize)]
pub struct DiffTracesResponse {
    pub traces: Vec<String>,
    pub n_traces: usize,
    pub headers: BTreeMap<String, Value>,
}

#[derive(Debug)]
struct OutputValue {
    binary: Option<Vec<u8>>,
}

pub async fn diff_traces_handler(
    State(_state): State<AppState>,
    Json(req): Json<DiffTracesRequest>,
) -> Result<Json<DiffTracesResponse>, StatusCode> {
    tokio::task::spawn_blocking(move || diff_traces_response(req))
        .await
        .map_err(|err| {
            tracing::warn!(target: "tracemiku-server", "diff traces worker failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .map(Json)
}

fn diff_traces_response(req: DiffTracesRequest) -> Result<DiffTracesResponse, StatusCode> {
    if req.traces.len() < 2 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut all_outputs = Vec::new();
    for trace in &req.traces {
        let outputs = extract_outputs(Path::new(trace)).ok_or(StatusCode::BAD_REQUEST)?;
        all_outputs.push(outputs);
    }

    let selected_keys = selected_output_keys(&req.keys, &all_outputs);
    let mut headers = BTreeMap::new();
    for header in selected_keys {
        let binaries: Vec<Option<&[u8]>> = all_outputs
            .iter()
            .map(|outputs| outputs.get(&header).and_then(|o| o.binary.as_deref()))
            .collect();
        if binaries.iter().any(Option::is_none) {
            let per_trace_lens: Vec<Option<usize>> =
                binaries.iter().map(|b| b.map(<[u8]>::len)).collect();
            headers.insert(
                header.to_string(),
                json!({"error": "missing in some trace", "per_trace_lens": per_trace_lens}),
            );
            continue;
        }
        let binaries: Vec<&[u8]> = binaries.into_iter().map(Option::unwrap).collect();
        headers.insert(header, diff_header(&binaries, &req));
    }

    Ok(DiffTracesResponse {
        traces: req.traces,
        n_traces: all_outputs.len(),
        headers,
    })
}

fn selected_output_keys(
    requested: &[String],
    all_outputs: &[HashMap<String, OutputValue>],
) -> Vec<String> {
    if requested.is_empty() {
        return all_outputs
            .iter()
            .flat_map(|outputs| outputs.keys().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
    let mut seen = HashSet::new();
    requested
        .iter()
        .filter_map(|key| {
            let key = key.trim();
            (!key.is_empty() && seen.insert(key.to_string())).then(|| key.to_string())
        })
        .collect()
}

fn extract_outputs(trace_dir: &Path) -> Option<HashMap<String, OutputValue>> {
    let mut candidates = Vec::new();
    let direct = trace_dir.join("jni_hooks.jsonl");
    if direct.exists() {
        candidates.push(direct);
    }
    let calls = trace_dir.join("calls");
    if let Ok(entries) = std::fs::read_dir(calls) {
        for entry in entries.flatten() {
            let path = entry.path().join("jni_hooks.jsonl");
            if path.exists() {
                candidates.push(path);
            }
        }
    }
    if candidates.is_empty() {
        return None;
    }

    let mut events = Vec::new();
    for path in candidates {
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines() {
                if let Ok(value) = serde_json::from_str::<Value>(line) {
                    events.push(value);
                }
            }
        }
    }
    events.sort_by_key(|event| {
        event
            .get("trace_idx")
            .and_then(Value::as_u64)
            .unwrap_or_default()
    });

    let new_strings: Vec<Value> = events
        .into_iter()
        .filter(|event| {
            event.get("id").and_then(Value::as_str) == Some("NewStringUTF")
                && event
                    .get("args")
                    .and_then(|args| args.get("bytes"))
                    .and_then(Value::as_str)
                    .is_some()
        })
        .collect();

    let mut outputs = HashMap::new();
    for (idx, event) in new_strings.iter().enumerate() {
        let Some(header) = event
            .get("args")
            .and_then(|args| args.get("bytes"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if idx + 1 >= new_strings.len() {
            continue;
        }
        let Some(raw) = new_strings[idx + 1]
            .get("args")
            .and_then(|args| args.get("bytes"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let decoded = percent_decode(raw);
        let pad = "=".repeat((4 - decoded.len() % 4) % 4);
        let binary = STANDARD.decode(format!("{decoded}{pad}")).ok();
        outputs.insert(header.to_string(), OutputValue { binary });
    }
    Some(outputs)
}

fn diff_header(binaries: &[&[u8]], req: &DiffTracesRequest) -> Value {
    let lens: Vec<usize> = binaries.iter().map(|b| b.len()).collect();
    let n = lens.iter().copied().min().unwrap_or(0);
    let length_variable = lens.iter().any(|len| *len != lens[0]);
    let mut stable_offsets = Vec::new();
    let mut variable_offsets = Vec::new();
    let mut per_byte = Vec::new();
    for offset in 0..n {
        let vals: Vec<u8> = binaries.iter().map(|b| b[offset]).collect();
        if vals.iter().all(|v| *v == vals[0]) {
            stable_offsets.push(offset);
            per_byte.push(json!({"off": offset, "kind": "STABLE", "value": hex_u8(vals[0])}));
        } else {
            variable_offsets.push(offset);
            per_byte.push(json!({
                "off": offset,
                "kind": "VARIABLE",
                "values": vals.iter().map(|v| hex_u8(*v)).collect::<Vec<_>>()
            }));
        }
    }

    let mut alias_map: BTreeMap<Vec<u8>, Vec<usize>> = BTreeMap::new();
    for &offset in &variable_offsets {
        let tuple: Vec<u8> = binaries.iter().map(|b| b[offset]).collect();
        alias_map.entry(tuple).or_default().push(offset);
    }
    let mut alias_groups: Vec<Value> = alias_map
        .into_iter()
        .filter_map(|(tuple, positions)| {
            (positions.len() > 1).then(|| {
                json!({
                    "positions": positions,
                    "size": positions.len(),
                    "values_per_trace": tuple.iter().map(|v| hex_u8(*v)).collect::<Vec<_>>(),
                })
            })
        })
        .collect();
    alias_groups.sort_by_key(|group| {
        std::cmp::Reverse(
            group
                .get("size")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
        )
    });

    let mut nibble_findings = Vec::new();
    for &offset in &variable_offsets {
        let vals: Vec<u8> = binaries.iter().map(|b| b[offset]).collect();
        let his: std::collections::BTreeSet<u8> = vals.iter().map(|v| (v >> 4) & 0xf).collect();
        let los: std::collections::BTreeSet<u8> = vals.iter().map(|v| v & 0xf).collect();
        if his.len() == 1 {
            let hi = *his.iter().next().unwrap();
            nibble_findings.push(json!({
                "off": offset,
                "kind": "hi_fixed",
                "hi": hex_u8(hi),
                "lo_per_trace": vals.iter().map(|v| hex_u8(v & 0xf)).collect::<Vec<_>>(),
            }));
        } else if los.len() == 1 {
            let lo = *los.iter().next().unwrap();
            nibble_findings.push(json!({
                "off": offset,
                "kind": "lo_fixed",
                "lo": hex_u8(lo),
                "hi_per_trace": vals.iter().map(|v| hex_u8((v >> 4) & 0xf)).collect::<Vec<_>>(),
            }));
        }
    }

    let stable_pct = if n == 0 {
        0.0
    } else {
        ((1000.0 * stable_offsets.len() as f64 / n as f64).round()) / 10.0
    };
    let alias_group_count = alias_groups.len();
    json!({
        "len_compared": n,
        "lens_per_trace": lens,
        "length_variable": length_variable,
        "stable_count": stable_offsets.len(),
        "variable_count": variable_offsets.len(),
        "stable_pct": stable_pct,
        "stable_offsets": req.show_offsets.then_some(stable_offsets),
        "variable_offsets": req.show_offsets.then_some(variable_offsets),
        "alias_groups": alias_groups,
        "alias_group_count": alias_group_count,
        "nibble_findings": nibble_findings,
        "per_byte": req.show_per_byte.then_some(per_byte),
    })
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_u8(v: u8) -> String {
    format!("{v:#x}")
}
