//! Shared JNI-call scan cache.

use std::collections::HashMap;
use std::path::PathBuf;
use std::thread;

use serde_json::Value;
use tracemiku_core::prelude::{decode, Index, SymbolMap, Trace};

const PARALLEL_MIN_RECORDS: usize = 250_000;
const MIN_CHUNK_RECORDS: usize = 200_000;

#[derive(Debug, Clone)]
pub struct JniCallScan {
    pub calls: Vec<JniCallRecord>,
    pub vtable_size: usize,
}

#[derive(Debug, Clone)]
pub struct JniCallRecord {
    pub idx: usize,
    pub pc: u64,
    pub rel: Option<u64>,
    pub func_name: String,
    pub jni_fn: String,
    pub vtable_offset: u64,
    pub args: [u64; 5],
}

impl JniCallRecord {
    pub fn func_display(&self) -> Option<String> {
        (!self.func_name.is_empty()).then(|| self.func_name.clone())
    }

    pub fn arg(&self, reg: &str) -> Option<u64> {
        let index = match reg {
            "x0" => 0,
            "x1" => 1,
            "x2" => 2,
            "x3" => 3,
            "x4" => 4,
            _ => return None,
        };
        Some(self.args[index])
    }

    pub fn args_map(&self) -> HashMap<&'static str, String> {
        ["x0", "x1", "x2", "x3", "x4"]
            .into_iter()
            .zip(self.args)
            .map(|(reg, value)| (reg, format!("{value:#x}")))
            .collect()
    }

    pub fn args_map_without_x0(&self) -> HashMap<&'static str, String> {
        ["x1", "x2", "x3", "x4"]
            .into_iter()
            .zip(self.args[1..].iter().copied())
            .map(|(reg, value)| (reg, format!("{value:#x}")))
            .collect()
    }
}

pub fn scan_jni_calls(
    trace: &Trace,
    index: &Index,
    symbols: &SymbolMap,
    primary_base: Option<u64>,
) -> JniCallScan {
    let jni_vtable = load_jni_vtable().unwrap_or_default();
    if jni_vtable.is_empty() {
        return JniCallScan {
            calls: Vec::new(),
            vtable_size: 0,
        };
    }

    let entries = index
        .pc_to_idxs
        .iter()
        .map(|(&pc, idxs)| (pc, idxs.as_slice()))
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return JniCallScan {
            calls: Vec::new(),
            vtable_size: jni_vtable.len(),
        };
    }

    let workers = jni_worker_count(trace.len()).min(entries.len()).max(1);
    let mut calls = if workers <= 1 {
        scan_jni_call_entries(trace, symbols, primary_base, &jni_vtable, &entries)
    } else {
        tracing::info!(
            target: "tracemiku-server",
            records = trace.len(),
            pc_groups = entries.len(),
            workers,
            "scanning JNI calls in parallel"
        );
        let chunk_size = entries.len().div_ceil(workers);
        let partials = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            let table = &jni_vtable;
            for chunk in entries.chunks(chunk_size) {
                handles.push(scope.spawn(move || {
                    scan_jni_call_entries(trace, symbols, primary_base, table, chunk)
                }));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().expect("JNI scan worker panicked"))
                .collect::<Vec<_>>()
        });
        let mut merged = Vec::new();
        for mut part in partials {
            merged.append(&mut part);
        }
        merged
    };
    calls.sort_by_key(|hit| hit.idx);
    JniCallScan {
        calls,
        vtable_size: jni_vtable.len(),
    }
}

pub(crate) fn jni_worker_count(records: usize) -> usize {
    tracemiku_core::parallel::worker_count(
        records,
        "TRACEMIKU_JNI_THREADS",
        PARALLEL_MIN_RECORDS,
        MIN_CHUNK_RECORDS,
    )
}

fn scan_jni_call_entries(
    trace: &Trace,
    symbols: &SymbolMap,
    primary_base: Option<u64>,
    jni_vtable: &HashMap<u64, String>,
    entries: &[(u64, &[usize])],
) -> Vec<JniCallRecord> {
    let mut calls = Vec::new();
    for &(pc, idxs) in entries {
        let Some(&first_idx) = idxs.first() else {
            continue;
        };
        let decoded = decode(pc, trace.inst(first_idx));
        if decoded.mnemonic != "blr" {
            continue;
        }
        let Some(target_reg) = branch_reg(&decoded.op_str) else {
            continue;
        };

        for &i in idxs {
            if i == 0 {
                continue;
            }
            let record = trace.record(i);
            let prev_record = trace.record(i - 1);
            let prev_decoded = decode(prev_record.pc, prev_record.inst);
            if prev_decoded.mnemonic != "ldr"
                || !prev_decoded.regs_def.iter().any(|r| r == &target_reg)
                || prev_decoded.mem_op.first().is_none_or(|op| op.is_write)
            {
                continue;
            }
            let op = &prev_decoded.mem_op[0];
            let Ok(offset) = u64::try_from(op.disp) else {
                continue;
            };
            let Some(jni_fn) = jni_vtable.get(&offset) else {
                continue;
            };
            let (func_name, _) = symbols.lookup(record.pc);
            calls.push(JniCallRecord {
                idx: i,
                pc: record.pc,
                rel: primary_base.map(|base| record.pc.wrapping_sub(base)),
                func_name,
                jni_fn: jni_fn.clone(),
                vtable_offset: offset,
                args: [
                    record.reg_by_name("x0").unwrap_or(0),
                    record.reg_by_name("x1").unwrap_or(0),
                    record.reg_by_name("x2").unwrap_or(0),
                    record.reg_by_name("x3").unwrap_or(0),
                    record.reg_by_name("x4").unwrap_or(0),
                ],
            });
        }
    }
    calls
}

fn branch_reg(op_str: &str) -> Option<String> {
    let reg = op_str
        .split(',')
        .next()
        .unwrap_or(op_str)
        .trim()
        .to_lowercase();
    (!reg.is_empty()).then_some(reg)
}

fn load_jni_vtable() -> Option<HashMap<u64, String>> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest.parent()?.parent()?.parent()?;
    for path in [repo_root.join("tools").join("jni_offsets.json")] {
        if let Some(table) = load_jni_offsets_json(&path) {
            return Some(table);
        }
    }

    let header_path = repo_root.join("vendor").join("jni").join("jni_bn.h");
    load_jni_offsets_header(&header_path)
}

fn load_jni_offsets_json(path: &std::path::Path) -> Option<HashMap<u64, String>> {
    let text = std::fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<Value>(&text).ok()?;
    let raw = value.get("offsets").unwrap_or(&value).as_object()?;
    let mut out = HashMap::new();
    for (k, v) in raw {
        let offset = crate::routes::parse::parse_dec_u64(k)?;
        let name = v.as_str()?.to_string();
        out.insert(offset, name);
    }
    Some(out)
}

fn load_jni_offsets_header(path: &std::path::Path) -> Option<HashMap<u64, String>> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut in_struct = false;
    let mut slot = 0u64;
    let mut out = HashMap::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("struct JNINativeInterface_ {") {
            in_struct = true;
            continue;
        }
        if !in_struct {
            continue;
        }
        if trimmed.starts_with("};") {
            break;
        }
        if trimmed.is_empty() {
            continue;
        }

        if trimmed.starts_with("void *reserved") {
            slot += 1;
            continue;
        }

        if let Some(name) = parse_jni_fn_member(trimmed) {
            out.insert(slot * 8, name);
            slot += 1;
        }
    }

    (!out.is_empty()).then_some(out)
}

fn parse_jni_fn_member(line: &str) -> Option<String> {
    let marker = "(__stdcall *";
    let (_, after_star) = line.split_once(marker)?;
    let name = after_star.split(')').next()?.trim();
    if name.is_empty() || name.starts_with("reserved") {
        return None;
    }
    Some(name.to_string())
}
