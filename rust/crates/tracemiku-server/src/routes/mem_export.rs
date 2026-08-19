//! GET /api/mem-export?addr= | (so=&off=)  &len=  [&cursor=]
//!
//! Exports the RUNTIME-DECRYPTED bytes of a memory/code range, keyed on the
//! tool-neutral `(SO, offset)` coordinate. On disk a packed / VMP'd / otherwise
//! self-decrypting `.so` is ciphertext; a static disassembler can only show the
//! encrypted form. traceMiku reconstructs the real bytes as the program saw
//! them, from MemShadow's layered oracle (traced stores `w`, external/JNI/
//! syscall writes `x`, and the t=0 initial-memory snapshot `i`), so the result
//! can be pasted / loaded back into IDA / BN / Ghidra at the same offset.
//!
//! Output is a contiguous hex blob (universal paste format; `??` frontier bytes
//! emitted as `00` filler but tracked separately), a run-length provenance map
//! marking which sub-ranges are ground truth vs never-observed, a per-kind
//! histogram, and an overall completeness score. NEVER silently presents `??`
//! filler as real — completeness < 1.0 and the `??` runs make the gaps explicit.

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::routes::parse::parse_hex_u64;
use crate::state::AppState;

/// Bounded so a single export can't blow up the response. 256 KiB of bytes ->
/// ~512 KiB hex. Larger ranges report `truncated:true`.
const MAX_EXPORT_BYTES: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
pub struct MemExportQuery {
    pub addr: Option<String>,
    pub so: Option<String>,
    pub off: Option<String>,
    /// Number of bytes to export (hex or decimal, `d`-prefix for decimal).
    pub len: Option<String>,
    /// Time point (record idx); default = end of trace (latest known bytes).
    pub cursor: Option<u64>,
}

/// One `(kind, start_offset_into_range, length)` provenance run.
#[derive(Debug, Serialize)]
pub struct ProvRun {
    pub kind: &'static str,
    pub start: usize,
    pub len: usize,
}

fn resolve_start_pc(inner: &crate::state::AppStateInner, q: &MemExportQuery) -> Result<u64, Value> {
    if let Some(addr) = q.addr.as_ref() {
        return parse_hex_u64(addr)
            .ok_or_else(|| json!({ "status": "error", "error": format!("invalid addr: {addr}") }));
    }
    if let (Some(so), Some(off_raw)) = (q.so.as_ref(), q.off.as_ref()) {
        let off = parse_hex_u64(off_raw).ok_or_else(
            || json!({ "status": "error", "error": format!("invalid off: {off_raw}") }),
        )?;
        let candidates = inner.modules.resolve_offset_candidates(so, off);
        return match candidates.len() {
            0 => Err(json!({
                "status": "miss",
                "query": { "so": so, "off": format!("{off:#x}") },
                "reason": "no loaded module matched",
            })),
            1 => Ok(candidates[0].3),
            _ => Err(json!({
                "status": "ambiguous",
                "query": { "so": so, "off": format!("{off:#x}") },
                "candidates": candidates
                    .iter()
                    .map(|(name, base, _end, pc)| json!({
                        "module": name,
                        "module_base": format!("{base:#x}"),
                        "pc": format!("{pc:#x}"),
                    }))
                    .collect::<Vec<_>>(),
                "hint": "narrow `so` to a unique module name",
            })),
        };
    }
    Err(json!({
        "status": "error",
        "error": "provide addr=0x... or so=<name>&off=0x..., plus len=",
    }))
}

pub async fn mem_export_handler(
    State(state): State<AppState>,
    Query(q): Query<MemExportQuery>,
) -> Result<Json<Value>, crate::routes::WorkerFailure> {
    let inner = state.inner.clone();
    let value = tokio::task::spawn_blocking(move || mem_export_response(&inner, q))
        .await
        .map_err(|err| crate::routes::worker_panic_response("mem-export", &err))?;
    Ok(Json(value))
}

fn mem_export_response(inner: &crate::state::AppStateInner, q: MemExportQuery) -> Value {
    let start = match resolve_start_pc(inner, &q) {
        Ok(pc) => pc,
        Err(v) => return v,
    };
    let len_raw = match q.len.as_ref() {
        Some(l) => match parse_hex_u64(l) {
            Some(n) => n as usize,
            None => return json!({ "status": "error", "error": format!("invalid len: {l}") }),
        },
        None => return json!({ "status": "error", "error": "len= is required" }),
    };
    if len_raw == 0 {
        return json!({ "status": "error", "error": "len must be > 0" });
    }
    let truncated = len_raw > MAX_EXPORT_BYTES;
    let len = len_raw.min(MAX_EXPORT_BYTES);

    let mem = match inner.memshadow_ready_or_block_if_idle() {
        Ok(mem) => mem,
        Err(status) => {
            let status = status.status_str();
            return json!({ "status": status, "reason": "memshadow not ready" });
        }
    };

    let cursor = q.cursor.unwrap_or(u64::MAX);
    let mut hex = String::with_capacity(len * 2);
    let mut observed = 0usize;
    let mut hist: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    let mut runs: Vec<ProvRun> = Vec::new();

    for i in 0..len {
        let a = start.wrapping_add(i as u64);
        let (byte, kind, _src) = mem.byte_at(a, cursor);
        let b = byte.unwrap_or(0); // ?? frontier filled with 00, tracked via kind
        hex.push_str(&format!("{b:02x}"));
        if byte.is_some() {
            observed += 1;
        }
        *hist.entry(kind).or_insert(0) += 1;
        match runs.last_mut() {
            Some(run) if run.kind == kind => run.len += 1,
            _ => runs.push(ProvRun {
                kind,
                start: i,
                len: 1,
            }),
        }
    }

    let completeness = if len > 0 {
        observed as f64 / len as f64
    } else {
        1.0
    };
    let rel = inner.modules.resolve_relative(start);

    json!({
        "status": "ready",
        "start": {
            "pc": format!("{start:#x}"),
            "module": rel.as_ref().map(|(n, _)| n.clone()),
            "offset": rel.as_ref().map(|(_, o)| format!("{o:#x}")),
        },
        "len": len,
        "requested_len": len_raw,
        "truncated": truncated,
        "cursor": q.cursor,
        "observed_count": observed,
        "completeness": completeness,
        "histogram": hist,
        "provenance_runs": runs,
        "hex": hex,
        "note": "?? bytes are 00 filler (never observed this trace), NOT real zeros; see provenance_runs/completeness",
    })
}
