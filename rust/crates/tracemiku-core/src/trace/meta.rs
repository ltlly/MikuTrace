//! `meta.json` parser — both run-level and per-call.
//!
//! 数据契约见 `docs/PER_CALL_TRACE_DESIGN.md`。

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::trace::record::{FORMAT_VERSION, REC_SIZE};

/// ARM64 GPR + SP + PC names in canonical order (33 entries).
pub const REG_NAMES: &[&str] = &[
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "fp", "lr", "sp", "pc",
];

#[derive(Debug, Error)]
pub enum MetaError {
    #[error("per-call meta.json not found: {0}")]
    PerCallNotFound(String),
    #[allow(dead_code)]
    #[error("run-level meta.json not found: {0}")]
    RunNotFound(String),
    #[error("invalid JSON in {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid hex value {0:?} in field {1}")]
    BadHex(String, &'static str),
    #[error("call_dir {0} has no parent/parent (must be <run>/calls/<call_dir>)")]
    InvalidCallDirShape(String),
    #[error("unsupported trace format_version {found}; expected {expected}")]
    UnsupportedFormatVersion { found: u32, expected: u32 },
    #[error("unsupported trace record_size {found}; expected {expected}")]
    UnsupportedRecordSize { found: usize, expected: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: String, // hex with 0x prefix
    pub size: u64,
    /// Computed: hex(int(base, 16) + size).
    #[serde(default)]
    pub end: String,
}

impl ModuleInfo {
    fn fill_end(mut self) -> Result<Self, MetaError> {
        let base_int = parse_hex(&self.base, "module.base")?;
        let end_int = base_int.checked_add(self.size).ok_or_else(|| {
            MetaError::BadHex(
                format!("base={} + size={}", self.base, self.size),
                "module.end (overflow)",
            )
        })?;
        self.end = format!("{:#x}", end_int);
        Ok(self)
    }
}

/// Per-call meta.json fields we consume.
#[derive(Debug, Clone, Deserialize)]
struct PerCallMetaRaw {
    pub records: u64,
    #[serde(default)]
    pub format_version: Option<u32>,
    #[serde(default)]
    pub record_size: Option<usize>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub last_insn_is_ret: bool,
    #[serde(default)]
    pub fork_events: Vec<serde_json::Value>,
}

/// Run-level meta.json fields we consume.
#[derive(Debug, Clone, Deserialize)]
struct RunMetaRaw {
    pub method: Option<String>,
    pub cmd: Option<i64>,
    pub module: Option<ModuleInfoRaw>,
    pub modules: Option<Vec<ModuleInfoRaw>>,
    pub fn_addr: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ModuleInfoRaw {
    pub name: String,
    pub base: String,
    /// Some traces emit size as a number (preferred); some emit hex.
    pub size: serde_json::Value,
}

impl TryFrom<ModuleInfoRaw> for ModuleInfo {
    type Error = MetaError;
    fn try_from(raw: ModuleInfoRaw) -> Result<Self, MetaError> {
        let size = match raw.size {
            serde_json::Value::Number(n) => n
                .as_u64()
                .ok_or_else(|| MetaError::BadHex(format!("{n}"), "module.size"))?,
            serde_json::Value::String(s) => parse_hex(&s, "module.size")?,
            other => {
                return Err(MetaError::BadHex(other.to_string(), "module.size"));
            }
        };
        ModuleInfo {
            name: raw.name,
            base: raw.base,
            size,
            end: String::new(),
        }
        .fill_end()
    }
}

/// Helper: per-call info exposed in case downstream wants tid/retval/etc.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct CallInfo {
    pub records: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceMeta {
    pub path: String,
    pub records: u64,
    pub format_version: u32,
    pub record_size: usize,
    pub module: Option<ModuleInfo>,
    pub modules: Vec<ModuleInfo>,
    pub method: String,
    pub cmd: Option<i64>,
    pub fn_addr: Option<String>,
    pub regs: &'static [&'static str],
    pub truncated: bool,
    pub last_insn_is_ret: bool,
    pub fork_events: Vec<serde_json::Value>,
}

impl TraceMeta {
    pub fn load(call_dir: &Path) -> Result<Self, MetaError> {
        let per_call_path = call_dir.join("meta.json");
        if !per_call_path.exists() {
            return Err(MetaError::PerCallNotFound(
                per_call_path.display().to_string(),
            ));
        }
        let per_call_text = read_to_string(&per_call_path)?;
        let per_call: PerCallMetaRaw =
            serde_json::from_str(&per_call_text).map_err(|e| MetaError::Json {
                path: per_call_path.display().to_string(),
                source: e,
            })?;
        let format_version = per_call.format_version.unwrap_or(FORMAT_VERSION);
        if format_version != FORMAT_VERSION {
            return Err(MetaError::UnsupportedFormatVersion {
                found: format_version,
                expected: FORMAT_VERSION,
            });
        }
        let record_size = per_call.record_size.unwrap_or(REC_SIZE);
        if record_size != REC_SIZE {
            return Err(MetaError::UnsupportedRecordSize {
                found: record_size,
                expected: REC_SIZE,
            });
        }

        // Run-level meta lives 2 dirs up: <run>/calls/<call_dir>/meta.json
        let run_dir = call_dir
            .parent()
            .and_then(|p| p.parent())
            .ok_or_else(|| MetaError::InvalidCallDirShape(call_dir.display().to_string()))?;
        let run_path = run_dir.join("meta.json");
        let run: RunMetaRaw = if run_path.exists() {
            let text = read_to_string(&run_path)?;
            serde_json::from_str(&text).map_err(|e| MetaError::Json {
                path: run_path.display().to_string(),
                source: e,
            })?
        } else {
            // Acceptable: per-call traces are loadable without a run wrapper.
            RunMetaRaw {
                method: None,
                cmd: None,
                module: None,
                modules: None,
                fn_addr: None,
            }
        };

        let module = run.module.map(ModuleInfo::try_from).transpose()?;
        let modules: Vec<ModuleInfo> = match (run.modules, module.clone()) {
            (Some(list), _) => list
                .into_iter()
                .map(ModuleInfo::try_from)
                .collect::<Result<_, _>>()?,
            (None, Some(m)) => vec![m],
            (None, None) => vec![],
        };

        Ok(TraceMeta {
            path: call_dir.display().to_string(),
            records: per_call.records,
            format_version,
            record_size,
            module,
            modules,
            method: run.method.unwrap_or_default(),
            cmd: run.cmd,
            fn_addr: run.fn_addr,
            regs: REG_NAMES,
            truncated: per_call.truncated,
            last_insn_is_ret: per_call.last_insn_is_ret,
            fork_events: per_call.fork_events,
        })
    }
}

fn read_to_string(p: &Path) -> Result<String, MetaError> {
    fs::read_to_string(p).map_err(|e| MetaError::Io {
        path: p.display().to_string(),
        source: e,
    })
}

/// Parse "0x..." or plain hex. Rejects negative.
fn parse_hex(s: &str, field: &'static str) -> Result<u64, MetaError> {
    let t = s.trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|_| MetaError::BadHex(s.to_string(), field))
}
