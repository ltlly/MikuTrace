//! Shared auto-phase scan cache.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracemiku_core::prelude::MemShadow;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PhaseEntry {
    pub idx: usize,
    pub phase: String,
    pub info: String,
}

const CRYPTO_PHASE_PATTERNS: &[(&str, &[u8])] = &[
    ("sha1_init", &[0x01, 0x23, 0x45, 0x67]),
    ("sha1_init_h1", &[0x89, 0xab, 0xcd, 0xef]),
    ("sha1_init_h4", &[0xf0, 0xe1, 0xd2, 0xc3]),
    ("sha256_init", &[0x67, 0xe6, 0x09, 0x6a]),
];

pub fn build_auto_phases(
    trace_dir: &Path,
    mem: &MemShadow,
    detect_byte_streams: bool,
) -> Vec<PhaseEntry> {
    let mut phases = jni_phases(trace_dir);
    append_crypto_phases(mem, &mut phases);
    if detect_byte_streams {
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
    dedup
}

pub fn jni_phases(trace_dir: &Path) -> Vec<PhaseEntry> {
    let path = trace_dir.join("jni_hooks.jsonl");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut phases = Vec::new();
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
    phases
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
