//! Call/run 级元数据恢复（finalize 的唯一实现）。
//!
//! 采集侧把 trace 落在设备上，host 拉取可能失败；此时 `_pending_call_*` 目录里的
//! `meta.json` 只有事实的**一部分**（`records=0`、边界 PC 为 null）。本模块按已落盘的
//! `trace.bin` 重算派生字段并原子回填，同时把最终目录名统一为
//! `call_<序号>_tid<线程>_<记录数>r_<耗时>ms`。
//!
//! 语义边界：
//! - 只重算**派生**字段（`records` / `bytes` / `first_pc` / `last_pc` / `last_insn_is_ret`），
//!   其余字段原样保留（含 sidecar、events、known_offsets、device 侧记录数）。
//! - 没有本地 `trace.bin` 的 pending 保持 pending；离线恢复不假装已经拿到数据。
//! - 未知不折叠成 false：末指令状态缺失或 bin 为空时是 `None`。
//! - 幂等：重复执行结果一致；目标目录冲突时报错而不是覆盖数据。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use thiserror::Error;

use crate::prelude::decode;
use crate::trace::record::REC_SIZE;
use crate::trace::trace::Trace;

#[derive(Debug, Error)]
pub enum FinalizeError {
    #[error("run 目录不存在: {0}")]
    RunMissing(String),
    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: meta.json 不是合法 JSON: {source}")]
    Meta {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("目标目录已存在且内容不同，拒绝覆盖: {0}")]
    TargetConflict(String),
}

/// 单个 call 的恢复结果。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct CallRepair {
    /// 恢复前所在目录名（`call_003_...` 或 `_pending_call_003`）。
    pub from: String,
    /// 恢复后所在目录名；仍为 pending 时等于 `from`。
    pub to: String,
    pub repaired: bool,
    /// 目录里没有 `trace.bin`，无法离线恢复。
    pub pending: bool,
    pub records: u64,
    pub bytes: u64,
    pub first_pc: Option<String>,
    pub last_pc: Option<String>,
    pub last_insn_is_ret: Option<bool>,
    /// 本次是否重命名（截断的 call 也统一到 `call_*`）。
    pub renamed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// run 级恢复结果。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct RunRepair {
    pub run: String,
    pub calls: Vec<CallRepair>,
    pub repaired: usize,
    pub pending: usize,
    pub renamed: usize,
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> FinalizeError + '_ {
    move |source| FinalizeError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn read_meta(dir: &Path) -> Result<Map<String, Value>, FinalizeError> {
    let p = dir.join("meta.json");
    let text = fs::read_to_string(&p).map_err(io_err(&p))?;
    let v: Value = serde_json::from_str(&text).map_err(|source| FinalizeError::Meta {
        path: p.display().to_string(),
        source,
    })?;
    match v {
        Value::Object(m) => Ok(m),
        other => Err(FinalizeError::Meta {
            path: p.display().to_string(),
            source: serde::de::Error::custom(format!("期望 JSON 对象, 得到 {other}")),
        }),
    }
}

fn write_atomic(path: &Path, body: &str) -> Result<(), FinalizeError> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(io_err(&tmp))?;
        f.write_all(body.as_bytes()).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
    }
    fs::rename(&tmp, path).map_err(io_err(path))
}

/// 规范目录名：截断状态只由 meta 表达，目录名不再区分。
fn canonical_call_name(md: &Map<String, Value>, records: u64) -> Result<String, FinalizeError> {
    let idx = md
        .get("callIdx")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| FinalizeError::Meta {
            path: "callIdx".into(),
            source: serde::de::Error::custom("缺少 callIdx, 无法推导目录名"),
        })?;
    let tid = md
        .get("tid")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| FinalizeError::Meta {
            path: "tid".into(),
            source: serde::de::Error::custom("缺少 tid, 无法推导目录名"),
        })?;
    let ms = md.get("ms").and_then(|v| v.as_f64());
    let ms_str = match ms {
        Some(m) => format!("{}ms", m as i64),
        None => "?ms".to_string(),
    };
    Ok(format!("call_{idx:03}_tid{tid}_{records}r_{ms_str}"))
}

/// 从 trace.bin 重算出的派生字段。
type Derived = (u64, u64, Option<String>, Option<String>, Option<bool>);

fn derived_from_bin(call_dir: &Path) -> Result<Derived, FinalizeError> {
    let bin = call_dir.join("trace.bin");
    let bytes = fs::metadata(&bin).map_err(io_err(&bin))?.len();
    // Trace::load 允许尾部不足一条记录；完整记录仍参与分析。
    let trace = Trace::load(call_dir).map_err(|e| FinalizeError::Io {
        path: call_dir.join("trace.bin").display().to_string(),
        source: std::io::Error::other(e.to_string()),
    })?;
    let n = trace.len() as u64;
    if n == 0 {
        return Ok((0, bytes, None, None, None));
    }
    let first = trace.record(0);
    let last = trace.record(trace.len() - 1);
    let d = decode(last.pc, last.inst);
    Ok((
        n,
        bytes,
        Some(format!("{:#x}", first.pc)),
        Some(format!("{:#x}", last.pc)),
        Some(d.is_ret),
    ))
}

/// 恢复单个 call 目录：回填派生字段，必要时重命名。
pub fn repair_call(calls_dir: &Path, dir_name: &str) -> Result<CallRepair, FinalizeError> {
    let dir: PathBuf = calls_dir.join(dir_name);
    let mut md = read_meta(&dir)?;
    let from = dir_name.to_string();

    if !dir.join("trace.bin").exists() {
        md.entry("records".to_string()).or_insert(Value::Null);
        let body = serde_json::to_string_pretty(&Value::Object(md.clone())).map_err(|source| {
            FinalizeError::Meta {
                path: dir.join("meta.json").display().to_string(),
                source,
            }
        })?;
        write_atomic(&dir.join("meta.json"), &body)?;
        return Ok(CallRepair {
            from: from.clone(),
            to: from.clone(),
            repaired: false,
            pending: true,
            records: 0,
            bytes: 0,
            first_pc: None,
            last_pc: None,
            last_insn_is_ret: None,
            renamed: false,
            warnings: vec!["缺少本地 trace.bin, 保持 pending".to_string()],
        });
    }

    let (n, bytes, first_pc, last_pc, is_ret) = derived_from_bin(&dir)?;
    let mut warnings = Vec::new();

    // 记录一致性校验：agent 报告的记录数若与落盘字节不一致，说明拉取不完整。
    if let Some(dev_recs) = md.get("device_records").and_then(|v| v.as_u64()) {
        if dev_recs != n {
            warnings.push(format!(
                "agent 报告 {dev_recs} 条, 本地 trace.bin 为 {n} 条, 以本地为准"
            ));
        }
    }
    if bytes % REC_SIZE as u64 != 0 {
        warnings.push(format!(
            "trace.bin 长度 {bytes} 不是 {REC_SIZE} 的整数倍, 尾部残缺"
        ));
    }

    md.insert("records".into(), Value::from(n));
    md.insert("bytes".into(), Value::from(bytes));
    md.insert(
        "first_pc".into(),
        first_pc.clone().map(Value::from).unwrap_or(Value::Null),
    );
    md.insert(
        "last_pc".into(),
        last_pc.clone().map(Value::from).unwrap_or(Value::Null),
    );
    md.insert(
        "last_insn_is_ret".into(),
        is_ret.map(Value::from).unwrap_or(Value::Null),
    );

    let target = canonical_call_name(&md, n)?;
    let renamed = target != from;
    let final_dir = if renamed {
        calls_dir.join(&target)
    } else {
        dir.clone()
    };

    if renamed && final_dir.exists() {
        // 目标目录已存在: 一律报冲突, 绝不删除/覆盖/合并源目录。
        // 记录数相同不代表内容相同 (两个 8000 条的 trace 可以完全不同),
        // 按 records 判定相等会删掉别人的数据并让 trace 与 meta 错配。
        // 对已经是规范命名的同一目录重复执行 finalize 是天然幂等的,
        // 不需要靠删除另一个目录来实现。
        return Err(FinalizeError::TargetConflict(
            final_dir.display().to_string(),
        ));
    } else if renamed {
        fs::rename(&dir, &final_dir).map_err(io_err(&dir))?;
    }

    let body =
        serde_json::to_string_pretty(&Value::Object(md)).map_err(|source| FinalizeError::Meta {
            path: final_dir.join("meta.json").display().to_string(),
            source,
        })?;
    write_atomic(&final_dir.join("meta.json"), &body)?;

    Ok(CallRepair {
        from,
        to: target,
        repaired: true,
        pending: false,
        records: n,
        bytes,
        first_pc,
        last_pc,
        last_insn_is_ret: is_ret,
        renamed,
        warnings,
    })
}

fn run_summary_entry(dir_name: &str, md: &Map<String, Value>, n: Option<u64>) -> Value {
    let mut o = Map::new();
    o.insert(
        "callIdx".into(),
        md.get("callIdx").cloned().unwrap_or(Value::Null),
    );
    o.insert("tid".into(), md.get("tid").cloned().unwrap_or(Value::Null));
    // pending 没有本地事实: records 为 null, 不能用 0 冒充「已完成 0 条」
    o.insert("records".into(), n.map(Value::from).unwrap_or(Value::Null));
    o.insert("ms".into(), md.get("ms").cloned().unwrap_or(Value::Null));
    o.insert(
        "retval".into(),
        md.get("retval").cloned().unwrap_or(Value::Null),
    );
    o.insert(
        "truncated".into(),
        md.get("truncated").cloned().unwrap_or(Value::from(true)),
    );
    o.insert(
        "last_insn_is_ret".into(),
        md.get("last_insn_is_ret").cloned().unwrap_or(Value::Null),
    );
    o.insert("dir".into(), Value::from(dir_name));
    Value::Object(o)
}

/// 恢复整个 run：有 bin 的回填并统一命名，没有 bin 的保持 pending，
/// 然后重建 run 级 `meta.json` 的 `calls` 汇总。
pub fn finalize_run(run_dir: &Path) -> Result<RunRepair, FinalizeError> {
    if !run_dir.exists() {
        return Err(FinalizeError::RunMissing(run_dir.display().to_string()));
    }
    let calls_dir = run_dir.join("calls");
    let mut results: Vec<CallRepair> = Vec::new();
    if calls_dir.exists() {
        let mut names: Vec<String> = std::fs::read_dir(&calls_dir)
            .map_err(io_err(&calls_dir))?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n.starts_with("call_")
                    || n.starts_with("_pending_call_")
                    || n.starts_with("_truncated_call_")
            })
            .collect();
        // 先按最终名排序，保证同一 run 内重命名顺序稳定（幂等）。
        names.sort();
        for name in names {
            results.push(repair_call(&calls_dir, &name)?);
        }
    }

    // 重建 run 汇总。pending 用 pending=true 表达，不能以 records=0 冒充已完成。
    let run_meta_path = run_dir.join("meta.json");
    let mut run_md = if run_meta_path.exists() {
        read_meta(run_dir)?
    } else {
        Map::new()
    };
    let mut entries: Vec<Value> = Vec::new();
    for r in &results {
        let d = calls_dir.join(&r.to);
        let md = read_meta(&d)?;
        let mut e = run_summary_entry(&r.to, &md, if r.pending { None } else { Some(r.records) });
        if let Value::Object(o) = &mut e {
            if r.pending {
                o.insert("pending".into(), Value::from(true));
                o.insert(
                    "devicePath".into(),
                    md.get("devicePath").cloned().unwrap_or(Value::Null),
                );
            }
        }
        entries.push(e);
    }
    // 按 callIdx 升序，与采集顺序一致。
    entries.sort_by_key(|e| {
        e.get("callIdx")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX)
    });
    run_md.insert("calls".into(), Value::Array(entries));

    let body = serde_json::to_string_pretty(&Value::Object(run_md)).map_err(|source| {
        FinalizeError::Meta {
            path: run_meta_path.display().to_string(),
            source,
        }
    })?;
    write_atomic(&run_meta_path, &body)?;

    Ok(RunRepair {
        run: run_dir.display().to_string(),
        repaired: results.iter().filter(|r| r.repaired).count(),
        pending: results.iter().filter(|r| r.pending).count(),
        renamed: results.iter().filter(|r| r.renamed).count(),
        calls: results,
    })
}
