use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};
use axum::body::Body;
use base64::alphabet::STANDARD as BASE64_STANDARD_ALPHABET;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
use http_body_util::BodyExt;
use tower::ServiceExt;

mod cli_support;
use cli_support::*;
mod capabilities;
use capabilities::*;
mod args;
use args::*;
mod output_provenance;
use output_provenance::*;
mod output_types;
use output_types::*;
mod output_vm;
use output_vm::*;
mod output_lineage;
use output_lineage::*;
mod output_semantics;
use output_semantics::*;
mod trace_api;
use trace_api::*;
mod vm_backtrace;
use vm_backtrace::*;
mod vm_lineage;
use vm_lineage::*;
mod vm_ops;
use vm_ops::*;
mod vm_writer;
use vm_writer::*;

const GAP_SCAN_REGS: &str =
    "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28,sp";
const GAP_SCAN_CHUNK: usize = 500;
const GAP_SCAN_MAX_RECORDS: usize = 5000;
const GAP_SCAN_MAX_CANDIDATES: usize = 12;
const GAP_ARG_STRUCT_SPAN: u64 = 0x400;
const GAP_NEAR_REG_SPAN: u64 = 0x100;
const GAP_SMALL_LEN_MAX: u64 = 0x4000;
const BASE64_LOOKUP_TREE_DEPTH: usize = 8;
const BASE64_LOOKUP_TREE_MAX_NODES: usize = 220;

#[derive(Clone, Debug)]
struct VmProfile {
    ip_reg: String,
    state_reg: String,
    dispatch_reg: String,
    infra_regs: HashSet<String>,
}

impl VmProfile {
    fn new(ip_reg: String, state_reg: String, dispatch_reg: String, infra_regs: String) -> Self {
        let ip_reg = register_value_key(&ip_reg);
        let state_reg = register_value_key(&state_reg);
        let dispatch_reg = register_value_key(&dispatch_reg);
        let infra_regs = split_csv(&infra_regs)
            .into_iter()
            .map(|reg| register_value_key(&reg))
            .chain([
                "sp".to_string(),
                "fp".to_string(),
                "lr".to_string(),
                ip_reg.clone(),
                state_reg.clone(),
                dispatch_reg.clone(),
            ])
            .collect();
        Self {
            ip_reg,
            state_reg,
            dispatch_reg,
            infra_regs,
        }
    }

    fn default_profile() -> Self {
        Self::new(
            "x21".to_string(),
            "x25".to_string(),
            "x23".to_string(),
            "x27".to_string(),
        )
    }

    fn to_json(&self) -> serde_json::Value {
        let mut infra_regs = self.infra_regs.iter().cloned().collect::<Vec<_>>();
        infra_regs.sort();
        serde_json::json!({
            "ip_reg": self.ip_reg,
            "state_reg": self.state_reg,
            "dispatch_reg": self.dispatch_reg,
            "infra_regs": infra_regs,
        })
    }

    fn is_infrastructure_reg(&self, reg: &str) -> bool {
        self.infra_regs.contains(&register_value_key(reg))
    }
}

pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Capabilities) => print_pretty(&capabilities_json()),
        Some(Cmd::Completions { shell }) => {
            use clap::CommandFactory;
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(shell, &mut command, name, &mut std::io::stdout());
            Ok(())
        }
        Some(Cmd::Api {
            trace_dir,
            path,
            method,
            params,
            json_body,
        }) => cmd_api(trace_dir, path, method, params, json_body).await,
        Some(Cmd::Stats {
            trace_dir,
            all_modules,
            top_modules,
        }) => cmd_stats(trace_dir, all_modules, top_modules),
        Some(Cmd::Meta { trace_dir }) => route_get_json(trace_dir, "/api/meta".to_string()).await,
        Some(Cmd::List { path, dir, json }) => cmd_list(path, dir, json),
        Some(Cmd::Info { path, json }) => cmd_info(path, json),
        Some(Cmd::ResolveMapAddr { maps_file, addr }) => cmd_resolve_map_addr(maps_file, addr),
        Some(Cmd::ResolveTraceAddr { trace_dir, addr }) => cmd_resolve_trace_addr(trace_dir, addr),
        Some(Cmd::ResolveElfSymbol { elf_file, offset }) => {
            cmd_resolve_elf_symbol(elf_file, offset)
        }
        Some(Cmd::Records {
            trace_dir,
            start,
            count,
            regs,
            indices,
        }) => {
            if let Some(idx_str) = indices {
                let idxs: Vec<usize> = idx_str
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
                let mut results = Vec::new();
                for idx in &idxs {
                    let path = format!("/api/record/{idx}");
                    match route_get_json_value(trace_dir.clone(), path).await {
                        Ok(v) => results.push(v),
                        Err(_) => {
                            results.push(serde_json::json!({"idx": idx, "error": "not found"}))
                        }
                    }
                }
                print_pretty(&serde_json::Value::Array(results))?;
                return Ok(());
            }
            let mut params = vec![("start", start.to_string()), ("count", count.to_string())];
            if let Some(regs) = regs {
                params.push(("regs", regs));
            }
            route_get_json(trace_dir, route_path("/api/records", &params)).await
        }
        Some(Cmd::Record { trace_dir, idx }) => {
            route_get_json(trace_dir, format!("/api/record/{idx}")).await
        }
        Some(Cmd::BgStatus { trace_dir }) => {
            route_get_json(trace_dir, "/api/bg-status".to_string()).await
        }
        Some(Cmd::DecompStatus { trace_dir }) => {
            route_get_json(trace_dir, "/api/decomp-status".to_string()).await
        }
        Some(Cmd::IdxsForPc {
            trace_dir,
            pc,
            cursor,
            limit,
        }) => {
            let params = vec![
                ("pc", pc),
                ("cursor", cursor.to_string()),
                ("limit", limit.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/idxs-for-pc", &params)).await
        }
        Some(Cmd::SearchPc {
            trace_dir,
            pc,
            limit,
        }) => {
            let params = vec![("pc", pc), ("limit", limit.to_string())];
            route_get_json(trace_dir, route_path("/api/search-pc", &params)).await
        }
        Some(Cmd::Search {
            trace_dir,
            pattern,
            max_results,
            cursor,
        })
        | Some(Cmd::SearchAsm {
            trace_dir,
            pattern,
            max_results,
            cursor,
        }) => {
            let mut params = vec![
                ("pattern", pattern),
                ("max_results", max_results.to_string()),
            ];
            if let Some(cursor) = cursor {
                params.push(("cursor", cursor.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/search", &params)).await
        }
        Some(Cmd::Query {
            trace_dir,
            kind,
            q,
            idx,
            reg,
            addr,
            len,
            limit,
        }) => {
            let mut params = vec![
                ("kind", kind),
                ("q", q),
                ("len", len.to_string()),
                ("limit", limit.to_string()),
            ];
            if let Some(idx) = idx {
                params.push(("idx", idx.to_string()));
            }
            if let Some(reg) = reg {
                params.push(("reg", reg));
            }
            if let Some(addr) = addr {
                params.push(("addr", addr));
            }
            route_get_json(trace_dir, route_path("/api/query", &params)).await
        }
        Some(Cmd::SoStats {
            trace_dir,
            top,
            all,
        }) => {
            let params = vec![("top", top.to_string()), ("all", all.to_string())];
            route_get_json(trace_dir, route_path("/api/so-stats", &params)).await
        }
        Some(Cmd::Resolve {
            trace_dir,
            addr,
            so,
            off,
        }) => {
            let mut params: Vec<(&str, String)> = Vec::new();
            if let Some(addr) = addr {
                params.push(("addr", addr));
            }
            if let Some(so) = so {
                params.push(("so", so));
            }
            if let Some(off) = off {
                params.push(("off", off));
            }
            route_get_json(trace_dir, route_path("/api/resolve", &params)).await
        }
        Some(Cmd::IndirectTargets {
            trace_dir,
            addr,
            so,
            off,
            min_count,
        }) => {
            let mut params: Vec<(&str, String)> = Vec::new();
            if let Some(addr) = addr {
                params.push(("addr", addr));
            }
            if let Some(so) = so {
                params.push(("so", so));
            }
            if let Some(off) = off {
                params.push(("off", off));
            }
            if let Some(min_count) = min_count {
                params.push(("min_count", min_count.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/indirect-targets", &params)).await
        }
        Some(Cmd::RegAt {
            trace_dir,
            reg,
            addr,
            so,
            off,
            max,
        }) => {
            let mut params: Vec<(&str, String)> = vec![("reg", reg)];
            if let Some(addr) = addr {
                params.push(("addr", addr));
            }
            if let Some(so) = so {
                params.push(("so", so));
            }
            if let Some(off) = off {
                params.push(("off", off));
            }
            if let Some(max) = max {
                params.push(("max", max.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/reg-at", &params)).await
        }
        Some(Cmd::RegValueAt {
            trace_dir,
            idx,
            reg,
        })
        | Some(Cmd::RegAtIdx {
            trace_dir,
            idx,
            reg,
        }) => {
            let params = vec![("idx", idx.to_string()), ("reg", reg)];
            route_get_json(trace_dir, route_path("/api/reg-value-at", &params)).await
        }
        Some(Cmd::LastWriteOfReg {
            trace_dir,
            reg,
            before,
            cursor,
        }) => {
            let mut params = vec![("reg", reg)];
            if let Some(before) = before {
                params.push(("before", before.to_string()));
            }
            if let Some(cursor) = cursor {
                params.push(("cursor", cursor.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/last-write-of-reg", &params)).await
        }
        Some(Cmd::NextUseOfReg {
            trace_dir,
            reg,
            after,
        }) => {
            let mut params = vec![("reg", reg)];
            if let Some(after) = after {
                params.push(("after", after.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/next-use-of-reg", &params)).await
        }
        Some(Cmd::Watch {
            trace_dir,
            kind,
            reg,
            addr,
            value,
            size,
            cursor,
            limit,
        }) => {
            let mut params = vec![
                ("kind", kind),
                ("size", size.to_string()),
                ("cursor", cursor.to_string()),
                ("limit", limit.to_string()),
            ];
            if let Some(reg) = reg {
                params.push(("reg", reg));
            }
            if let Some(addr) = addr {
                params.push(("addr", addr));
            }
            if let Some(value) = value {
                params.push(("value", value));
            }
            route_get_json(trace_dir, route_path("/api/watchpoints", &params)).await
        }
        Some(Cmd::Functions { trace_dir }) => {
            route_get_json(trace_dir, "/api/functions".to_string()).await
        }
        Some(Cmd::ForkEvents {
            trace_dir,
            status,
            is_fork_like,
            limit,
        }) => {
            let mut params = vec![("limit", limit.to_string())];
            if let Some(status) = status {
                params.push(("status", status));
            }
            if let Some(is_fork_like) = is_fork_like {
                params.push(("is_fork_like", is_fork_like.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/fork-events", &params)).await
        }
        Some(Cmd::Cfg { trace_dir, fn_name }) => {
            let mut params = Vec::new();
            if let Some(name) = fn_name {
                params.push(("fn", name));
            }
            route_get_json(trace_dir, route_path("/api/cfg", &params)).await
        }
        Some(Cmd::CfgSvg {
            trace_dir,
            fn_name,
            pc,
            local_depth,
            timeout,
            force,
        }) => {
            let mut params = vec![
                ("timeout", timeout.to_string()),
                ("local_depth", local_depth.to_string()),
                ("force", force.to_string()),
            ];
            if let Some(name) = fn_name {
                params.push(("fn", name));
            }
            if let Some(pc) = pc {
                params.push(("pc", pc));
            }
            route_get_json(trace_dir, route_path("/api/cfg-svg", &params)).await
        }
        Some(Cmd::IdxsForBlock {
            trace_dir,
            pc,
            max_count,
            near,
        }) => {
            let params = vec![
                ("pc", pc),
                ("max_count", max_count.to_string()),
                ("near", near.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/idxs-for-block", &params)).await
        }
        Some(Cmd::BlockForPc { trace_dir, pc }) => {
            route_get_json(trace_dir, route_path("/api/block-for-pc", &[("pc", pc)])).await
        }
        Some(Cmd::Block { trace_dir, pc }) => {
            route_get_json(trace_dir, route_path("/api/block", &[("pc", pc)])).await
        }
        Some(Cmd::Loops { trace_dir }) => route_get_json(trace_dir, "/api/loops".to_string()).await,
        Some(Cmd::Coverage {
            trace_dir,
            addr,
            so,
            off,
            fn_name,
        }) => {
            let mut params: Vec<(&str, String)> = Vec::new();
            if let Some(addr) = addr {
                params.push(("addr", addr));
            }
            if let Some(so) = so {
                params.push(("so", so));
            }
            if let Some(off) = off {
                params.push(("off", off));
            }
            if let Some(fn_name) = fn_name {
                params.push(("fn", fn_name));
            }
            route_get_json(trace_dir, route_path("/api/coverage", &params)).await
        }
        Some(Cmd::Backtrace {
            trace_dir,
            idx,
            limit,
        }) => {
            let params = vec![("idx", idx.to_string()), ("limit", limit.to_string())];
            route_get_json(trace_dir, route_path("/api/backtrace", &params)).await
        }
        Some(Cmd::CallTree {
            trace_dir,
            max_depth,
        }) => {
            let mut params = Vec::new();
            if let Some(depth) = max_depth {
                params.push(("max_depth", depth.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/call-tree", &params)).await
        }
        Some(Cmd::CallChain {
            trace_dir,
            idx,
            depth,
        }) => {
            let params = vec![("idx", idx.to_string()), ("depth", depth.to_string())];
            route_get_json(trace_dir, route_path("/api/call-chain", &params)).await
        }
        Some(Cmd::Strings {
            trace_dir,
            min_len,
            q,
            cursor,
            limit,
        }) => {
            let params = vec![
                ("min_len", min_len.to_string()),
                ("q", q),
                ("cursor", cursor.to_string()),
                ("limit", limit.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/strings", &params)).await
        }
        Some(Cmd::StringProvenance {
            trace_dir,
            addr,
            length,
        }) => {
            let params = vec![("addr", addr), ("length", length.to_string())];
            route_get_json(trace_dir, route_path("/api/string-provenance", &params)).await
        }
        Some(Cmd::MemDump {
            trace_dir,
            addr,
            count,
            cursor,
            summary,
            cstr,
        }) => {
            let mut params = vec![("addr", addr), ("count", count.to_string())];
            if let Some(cursor) = cursor {
                params.push(("cursor", cursor.to_string()));
            }
            let path = route_path("/api/mem-dump", &params);
            if summary || cstr {
                let value = route_get_json_value(trace_dir, path).await?;
                print_pretty(&mem_dump_summary(&value, cstr))
            } else {
                route_get_json(trace_dir, path).await
            }
        }
        Some(Cmd::MemExport {
            trace_dir,
            addr,
            so,
            off,
            len,
            cursor,
            out,
        }) => {
            let mut params: Vec<(&str, String)> = vec![("len", len)];
            if let Some(addr) = addr {
                params.push(("addr", addr));
            }
            if let Some(so) = so {
                params.push(("so", so));
            }
            if let Some(off) = off {
                params.push(("off", off));
            }
            if let Some(cursor) = cursor {
                params.push(("cursor", cursor.to_string()));
            }
            let path = route_path("/api/mem-export", &params);
            let value = route_get_json_value(trace_dir, path).await?;
            if let Some(out_path) = out {
                cmd_mem_export_write(&value, &out_path)
            } else {
                print_pretty(&value)
            }
        }
        Some(Cmd::LastWriteOfAddr {
            trace_dir,
            addr,
            before_idx,
            with_external,
        }) => {
            let params = vec![
                ("addr", addr),
                ("before_idx", before_idx.to_string()),
                ("with_external", with_external.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/last-write-of-addr", &params)).await
        }
        Some(Cmd::IdxsTouchingAddr {
            trace_dir,
            addr,
            cursor,
            limit,
            with_bytes,
        }) => {
            let params = vec![
                ("addr", addr),
                ("cursor", cursor.to_string()),
                ("limit", limit.to_string()),
                ("with_bytes", with_bytes.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/idxs-touching-addr", &params)).await
        }
        Some(Cmd::IdxsTouchingRange {
            trace_dir,
            addr,
            size,
            cursor,
            limit,
        }) => {
            let params = vec![
                ("addr", addr),
                ("size", size.to_string()),
                ("cursor", cursor.to_string()),
                ("limit", limit.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/idxs-touching-range", &params)).await
        }
        Some(Cmd::FindMemPattern {
            trace_dir,
            bytes_hex,
            since,
            max,
            idx_lo,
            idx_hi,
        }) => {
            let mut params = vec![
                ("bytes_hex", bytes_hex),
                ("since", since.to_string()),
                ("max", max.to_string()),
            ];
            if let Some(idx_lo) = idx_lo {
                params.push(("idx_lo", idx_lo.to_string()));
            }
            if let Some(idx_hi) = idx_hi {
                params.push(("idx_hi", idx_hi.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/find-mem-pattern", &params)).await
        }
        Some(Cmd::TaintFwd {
            trace_dir,
            start,
            reg,
            max_count,
            through_mem,
            data_only,
            cross_fn_call,
            scan_limit,
        }) => {
            let params = taint_params(
                start,
                reg,
                max_count,
                through_mem,
                data_only,
                cross_fn_call,
                scan_limit,
            );
            route_get_json(trace_dir, route_path("/api/forward-taint", &params)).await
        }
        Some(Cmd::TaintBwd {
            trace_dir,
            start,
            so,
            off,
            occurrence,
            reg,
            max_count,
            through_mem,
            data_only,
            cross_fn_call,
            scan_limit,
        }) => {
            let path_hint = "/api/backward-taint";
            let app = build_cli_router(trace_dir, path_hint, None)?;
            let start = match (start, so.as_ref(), off.as_ref()) {
                (Some(s), _, _) => s,
                (None, Some(so), Some(off)) => {
                    let (idx, _pc) = resolve_offset_to_idx(&app, so, off, occurrence).await?;
                    idx
                }
                (None, _, _) => {
                    bail!("taint-bwd needs --start <idx> or (--so <name> --off <offset>)")
                }
            };
            let params = taint_params(
                start,
                reg,
                max_count,
                through_mem,
                data_only,
                cross_fn_call,
                scan_limit,
            );
            let value = route_get_json_value_on(&app, route_path(path_hint, &params)).await?;
            print_pretty(&value)
        }
        Some(Cmd::DataChase {
            trace_dir,
            start,
            reg,
            max_steps,
            exclude_regs,
        }) => {
            let params = vec![
                ("start", start.to_string()),
                ("reg", reg),
                ("max_steps", max_steps.to_string()),
                ("exclude_regs", exclude_regs),
            ];
            route_get_json(trace_dir, route_path("/api/data-chase", &params)).await
        }
        Some(Cmd::DepGraph {
            trace_dir,
            idx,
            reg,
            addr,
            before,
            depth,
            limit,
        }) => {
            let mut params = vec![("depth", depth.to_string()), ("limit", limit.to_string())];
            if let Some(idx) = idx {
                params.push(("idx", idx.to_string()));
            }
            if let Some(reg) = reg {
                params.push(("reg", reg));
            }
            if let Some(addr) = addr {
                params.push(("addr", addr));
            }
            if let Some(before) = before {
                params.push(("before", before.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/dep-graph", &params)).await
        }
        Some(Cmd::BfsSlice {
            trace_dir,
            idx,
            idxs,
            reg,
            regs,
            addr,
            addrs,
            before,
            data_only,
            limit,
            mode,
            so,
            off,
            occurrence,
        }) => {
            let path_hint = "/api/bfs-slice";
            let app = build_cli_router(trace_dir, path_hint, None)?;
            // (SO,offset) seed resolves to a concrete idx, joining the existing
            // idx/reg/addr seed family without touching the server route.
            let resolved_idx = match (so.as_ref(), off.as_ref()) {
                (Some(so), Some(off)) => {
                    let (i, _pc) = resolve_offset_to_idx(&app, so, off, occurrence).await?;
                    Some(i)
                }
                (Some(_), None) | (None, Some(_)) => {
                    bail!("bfs-slice --so and --off must be given together")
                }
                (None, None) => None,
            };
            let mut params = vec![
                ("limit", limit.to_string()),
                ("data_only", data_only.to_string()),
                ("mode", mode),
            ];
            if let Some(v) = resolved_idx.or(idx) {
                params.push(("idx", v.to_string()));
            }
            if let Some(v) = idxs {
                params.push(("idxs", v));
            }
            if let Some(v) = reg {
                params.push(("reg", v));
            }
            if let Some(v) = regs {
                params.push(("regs", v));
            }
            if let Some(v) = addr {
                params.push(("addr", v));
            }
            if let Some(v) = addrs {
                params.push(("addrs", v));
            }
            if let Some(v) = before {
                params.push(("before", v.to_string()));
            }
            let value = route_get_json_value_on(&app, route_path(path_hint, &params)).await?;
            print_pretty(&value)
        }
        Some(Cmd::ForwardDepTree {
            trace_dir,
            idx,
            reg,
            addr,
            before,
            depth,
            limit,
            data_only,
            so,
            off,
            occurrence,
        }) => {
            let path_hint = "/api/forward-dep-tree";
            let app = build_cli_router(trace_dir, path_hint, None)?;
            let resolved_idx = match (so.as_ref(), off.as_ref()) {
                (Some(so), Some(off)) => {
                    let (i, _pc) = resolve_offset_to_idx(&app, so, off, occurrence).await?;
                    Some(i)
                }
                (Some(_), None) | (None, Some(_)) => {
                    bail!("forward-dep-tree --so and --off must be given together")
                }
                (None, None) => None,
            };
            let mut params = vec![
                ("depth", depth.to_string()),
                ("limit", limit.to_string()),
                ("data_only", data_only.to_string()),
            ];
            if let Some(v) = resolved_idx.or(idx) {
                params.push(("idx", v.to_string()));
            }
            if let Some(v) = reg {
                params.push(("reg", v));
            }
            if let Some(v) = addr {
                params.push(("addr", v));
            }
            if let Some(v) = before {
                params.push(("before", v.to_string()));
            }
            let value = route_get_json_value_on(&app, route_path(path_hint, &params)).await?;
            print_pretty(&value)
        }
        Some(Cmd::RegTimeline {
            trace_dir,
            reg,
            start,
            end,
            max_points,
        }) => {
            let params = vec![
                ("reg", reg),
                ("start", start.to_string()),
                ("end", end.to_string()),
                ("max_points", max_points.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/reg-timeline", &params)).await
        }
        Some(Cmd::MemDiff {
            trace_dir,
            idx,
            addr,
            size,
        }) => {
            let params = vec![
                ("idx", idx.to_string()),
                ("addr", addr),
                ("size", size.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/mem-diff", &params)).await
        }
        Some(Cmd::MemFlow {
            trace_dir,
            addr,
            count,
            idx_lo,
            idx_hi,
            events_per_byte,
            writers_only,
            readers_only,
        }) => {
            let mut params = vec![
                ("addr", addr),
                ("count", count.to_string()),
                ("events_per_byte", events_per_byte.to_string()),
                ("writers_only", writers_only.to_string()),
                ("readers_only", readers_only.to_string()),
            ];
            if let Some(idx_lo) = idx_lo {
                params.push(("idx_lo", idx_lo.to_string()));
            }
            if let Some(idx_hi) = idx_hi {
                params.push(("idx_hi", idx_hi.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/mem-flow", &params)).await
        }
        Some(Cmd::MemWritesInRange {
            trace_dir,
            idx_lo,
            idx_hi,
            addr_lo,
            addr_hi,
            src_byte,
            with_external,
            max,
        }) => {
            let mut params = vec![
                ("idx_lo", idx_lo.to_string()),
                ("idx_hi", idx_hi.to_string()),
                ("max", max.to_string()),
                ("with_external", with_external.to_string()),
            ];
            if let Some(addr_lo) = addr_lo {
                params.push(("addr_lo", addr_lo));
            }
            if let Some(addr_hi) = addr_hi {
                params.push(("addr_hi", addr_hi));
            }
            if let Some(src_byte) = src_byte {
                params.push(("src_byte", src_byte));
            }
            route_get_json(trace_dir, route_path("/api/mem-writes-in-range", &params)).await
        }
        Some(Cmd::ByteWriterMap {
            trace_dir,
            addr,
            size,
            idx_lo,
            idx_hi,
            max,
            vm_chain_steps,
            vm_chain_runs,
            vm_chain_lookback,
            vm_chain_follow_frontier,
            summary,
            vm_ip_reg,
            vm_state_reg,
            vm_dispatch_reg,
            vm_infra_regs,
        }) => {
            let profile = VmProfile::new(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs);
            cmd_byte_writer_map(
                trace_dir,
                addr,
                size,
                idx_lo,
                idx_hi,
                max,
                vm_chain_steps,
                vm_chain_runs,
                vm_chain_lookback,
                vm_chain_follow_frontier,
                summary,
                profile,
            )
            .await
        }
        Some(Cmd::OllvmDetectVm {
            trace_dir,
            min_entries,
            threshold,
        }) => {
            let params = vec![
                ("min_entries", min_entries.to_string()),
                ("threshold", threshold.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/ollvm-detect-vm", &params)).await
        }
        Some(Cmd::FnSummary {
            trace_dir,
            fn_name,
            top_blocks,
        }) => {
            let params = vec![("fn", fn_name), ("top_blocks", top_blocks.to_string())];
            route_get_json(trace_dir, route_path("/api/fn-summary", &params)).await
        }
        Some(Cmd::CryptoScan { trace_dir }) => {
            route_get_json(trace_dir, "/api/crypto-scan".to_string()).await
        }
        Some(Cmd::Crypto { trace_dir }) => {
            let mut value =
                route_get_json_value(trace_dir, "/api/crypto-analysis".to_string()).await?;
            if let Some(obj) = value.as_object_mut() {
                let has_findings = obj.iter().any(|(k, v)| {
                    (k.contains("findings") || k.contains("hits") || k.contains("instructions"))
                        && v.as_array().map_or(false, |a| !a.is_empty())
                });
                if !has_findings {
                    obj.insert(
                        "note".to_string(),
                        serde_json::json!(
                            "No crypto constants, byte patterns, or ARM CE instructions detected. \
                         This may mean: (1) the function doesn't use crypto, (2) crypto is in a \
                         different call, or (3) constants are obfuscated."
                        ),
                    );
                }
            }
            print_pretty(&value)?;
            Ok(())
        }
        Some(Cmd::HashFinalizeDetect {
            trace_dir,
            window,
            min_size,
            limit,
            map_bytes,
            map_candidates,
            nonzero_only,
            target_bytes,
        }) => {
            cmd_hash_finalize_detect(
                trace_dir,
                window,
                min_size,
                limit,
                map_bytes,
                map_candidates,
                nonzero_only,
                target_bytes,
            )
            .await
        }
        Some(Cmd::HashInputSearch {
            trace_dir,
            target_bytes,
            inputs,
            keys,
            algos,
            combos,
            prefix_bytes,
            search_in_mem,
        }) => {
            let body = serde_json::json!({
                "target_bytes": target_bytes,
                "inputs": split_csv(&inputs),
                "keys": split_csv_allow_empty(&keys),
                "algos": split_csv(&algos),
                "combos": split_csv(&combos),
                "prefix_bytes": prefix_bytes,
                "search_in_mem": search_in_mem,
            });
            route_post_json(trace_dir, "/api/hash-input-search".to_string(), body).await
        }
        Some(Cmd::DiffTraces {
            traces,
            keys,
            show_offsets,
            show_per_byte,
        }) => {
            if traces.len() < 2 {
                bail!("need >= 2 traces for diff");
            }
            let trace_dir = traces[0].clone();
            let body = serde_json::json!({
                "traces": traces
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>(),
                "keys": keys,
                "show_offsets": show_offsets,
                "show_per_byte": show_per_byte,
            });
            route_post_json(trace_dir, "/api/diff-traces".to_string(), body).await
        }
        Some(Cmd::FieldAt {
            trace_dir,
            pc,
            reg,
            offset,
            so,
            backend,
        }) => {
            let mut params = vec![("pc", pc), ("reg", reg), ("offset", offset)];
            if let Some(so) = so {
                params.push(("so", so.display().to_string()));
            }
            if let Some(backend) = backend {
                params.push(("backend", backend));
            }
            route_get_json(trace_dir, route_path("/api/field-at", &params)).await
        }
        Some(Cmd::AsmTokensForPcs { trace_dir, pcs }) => {
            route_get_json(
                trace_dir,
                route_path("/api/asm-tokens-for-pcs", &[("pcs", pcs)]),
            )
            .await
        }
        Some(Cmd::BnSidecarStatus { trace_dir }) => {
            route_get_json(trace_dir, "/api/bn-sidecar/status".to_string()).await
        }
        Some(Cmd::HlilForPc { trace_dir, pc }) => {
            route_get_json(trace_dir, route_path("/api/hlil-for-pc", &[("pc", pc)])).await
        }
        Some(Cmd::HlilForFn { trace_dir, fn_id }) => {
            route_get_json(
                trace_dir,
                route_path("/api/hlil-for-fn", &[("fn_id", fn_id)]),
            )
            .await
        }
        Some(Cmd::BnCfgForPc {
            trace_dir,
            pc,
            mode,
        }) => {
            let params = vec![("pc", pc), ("mode", mode)];
            route_get_json(trace_dir, route_path("/api/bn-cfg-for-pc", &params)).await
        }
        Some(Cmd::BnCfgSvgForPc {
            trace_dir,
            pc,
            mode,
            timeout,
        }) => {
            let mut params = vec![("pc", pc), ("mode", mode)];
            if let Some(timeout) = timeout {
                params.push(("timeout", timeout.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/bn-cfg-svg-for-pc", &params)).await
        }
        Some(Cmd::AutoPhaseDetect {
            trace_dir,
            detect_byte_streams,
            max_phases,
        }) => {
            let params = vec![
                ("detect_byte_streams", detect_byte_streams.to_string()),
                ("max_phases", max_phases.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/auto-phase-detect", &params)).await
        }
        Some(Cmd::JniCalls {
            trace_dir,
            in_fn,
            max,
        }) => {
            let mut params = vec![("max", max.to_string())];
            if let Some(in_fn) = in_fn {
                params.push(("in_fn", in_fn));
            }
            route_get_json(trace_dir, route_path("/api/jni-calls", &params)).await
        }
        Some(Cmd::JniEvents {
            trace_dir,
            id,
            idx_lo,
            idx_hi,
            limit,
        }) => {
            let mut params = vec![("limit", limit.to_string())];
            if let Some(id) = id {
                params.push(("id", id));
            }
            if let Some(idx_lo) = idx_lo {
                params.push(("idx_lo", idx_lo.to_string()));
            }
            if let Some(idx_hi) = idx_hi {
                params.push(("idx_hi", idx_hi.to_string()));
            }
            route_get_json(trace_dir, route_path("/api/jni-events", &params)).await
        }
        Some(Cmd::JniOutputStrings {
            trace_dir,
            key,
            contains,
            limit,
        }) => cmd_jni_output_strings(trace_dir, key, contains, limit).await,
        Some(Cmd::ScanJniOutputStrings {
            path,
            key,
            contains,
            limit,
            decode_url,
            decode_base64,
            decode_base64_full,
            diff_base64,
            base64_tail_start,
            base64_tail_align_prefix,
            base64_tail_drop,
            prior_inputs,
        }) => cmd_scan_jni_output_strings(
            path,
            key,
            contains,
            limit,
            decode_url,
            decode_base64,
            decode_base64_full,
            diff_base64,
            base64_tail_start,
            base64_tail_align_prefix,
            base64_tail_drop,
            prior_inputs,
        ),
        Some(Cmd::OutputBacktrace {
            trace_dir,
            key,
            value,
            bytes_hex,
            jni_limit,
            max_mem_hits,
            writes_per_hit,
            taint_seeds,
            taint_max_count,
            vm_chain_steps,
            vm_chain_runs,
            vm_chain_lookback,
            vm_chain_follow_frontier,
            vm_ip_reg,
            vm_state_reg,
            vm_dispatch_reg,
            vm_infra_regs,
            skip_taint,
            no_url_decode,
            no_base64_decode,
        }) => {
            let vm_profile =
                VmProfile::new(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs);
            let opts = OutputBacktraceOpts {
                key,
                value,
                bytes_hex,
                jni_limit,
                max_mem_hits,
                writes_per_hit,
                taint_seeds,
                taint_max_count,
                vm_chain_steps,
                vm_chain_runs,
                vm_chain_lookback,
                vm_chain_follow_frontier,
                vm_profile,
                skip_taint,
                url_decode: !no_url_decode,
                base64_decode: !no_base64_decode,
            };
            cmd_output_backtrace(trace_dir, opts).await
        }
        Some(Cmd::OutputMap {
            trace_dir,
            key,
            value,
            jni_limit,
            max_mem_hits,
            hit_rank,
            hit_order,
            group_start,
            groups,
            semantic_offset,
            semantic_count,
            tree_depth,
            tree_max_nodes,
            index_tree_depth,
            index_tree_max_nodes,
            tree_frontier_with_next,
            lookback,
            no_url_decode,
            base64_tail_start,
            base64_tail_align_prefix,
            base64_tail_drop,
            semantic_writer_map,
            semantic_writer_map_idx_hi,
            semantic_writer_map_max,
            semantic_writer_map_vm_chain_steps,
            semantic_writer_map_vm_chain_runs,
            semantic_writer_map_vm_chain_bytes,
            semantic_writer_map_vm_chain_lookback,
            semantic_writer_map_vm_chain_follow_frontier,
            vm_ip_reg,
            vm_state_reg,
            vm_dispatch_reg,
            vm_infra_regs,
            summary,
        }) => {
            let vm_profile =
                VmProfile::new(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs);
            let opts = OutputMapOpts {
                key,
                value,
                jni_limit,
                max_mem_hits,
                hit_rank,
                hit_order,
                group_start,
                groups,
                semantic_offset,
                semantic_count,
                tree_depth,
                tree_max_nodes,
                index_tree_depth,
                index_tree_max_nodes,
                tree_frontier_with_next,
                lookback,
                url_decode: !no_url_decode,
                base64_tail_start,
                base64_tail_align_prefix,
                base64_tail_drop,
                semantic_writer_map,
                semantic_writer_map_idx_hi,
                semantic_writer_map_max,
                semantic_writer_map_vm_chain_steps,
                semantic_writer_map_vm_chain_runs,
                semantic_writer_map_vm_chain_bytes,
                semantic_writer_map_vm_chain_lookback,
                semantic_writer_map_vm_chain_follow_frontier,
                vm_profile,
                summary,
            };
            cmd_output_map(trace_dir, opts).await
        }
        Some(Cmd::VmSlice {
            trace_dir,
            start,
            end,
            count,
            regs,
            only_vm,
            vm_ip_reg,
            vm_state_reg,
            vm_dispatch_reg,
            vm_infra_regs,
            base_ip,
        }) => {
            let profile = VmProfile::new(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs);
            cmd_vm_slice(
                trace_dir, start, end, count, regs, only_vm, base_ip, profile,
            )
            .await
        }
        Some(Cmd::VmOps {
            trace_dir,
            start,
            end,
            count,
            regs,
            vm_ip_reg,
            vm_state_reg,
            vm_dispatch_reg,
            vm_infra_regs,
            base_ip,
            max_ops,
            chunk_size,
            summary,
            effects_only,
            compact,
            replay_plan,
        }) => {
            let profile = VmProfile::new(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs);
            cmd_vm_ops(
                trace_dir,
                start,
                end,
                count,
                regs,
                base_ip,
                max_ops,
                chunk_size,
                summary,
                effects_only,
                compact,
                replay_plan,
                profile,
            )
            .await
        }
        Some(Cmd::ByteLineage {
            trace_dir,
            addr,
            before_idx,
            count,
            depth,
            context,
            lookback,
            max_writes,
            regs,
            summary,
            compact,
        }) => {
            cmd_byte_lineage(
                trace_dir, addr, before_idx, count, depth, context, lookback, max_writes, regs,
                summary, compact,
            )
            .await
        }
        Some(Cmd::VmBackstep {
            trace_dir,
            idx,
            reg,
            context,
            lookback,
            max_writes,
            regs,
            vm_ip_reg,
            vm_state_reg,
            vm_dispatch_reg,
            vm_infra_regs,
        }) => {
            let profile = VmProfile::new(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs);
            cmd_vm_backstep(
                trace_dir, idx, reg, context, lookback, max_writes, regs, profile,
            )
            .await
        }
        Some(Cmd::VmBackchain {
            trace_dir,
            idx,
            reg,
            steps,
            context,
            lookback,
            max_writes,
            follow_frontier,
            byte_lane,
            summary,
            regs,
            vm_ip_reg,
            vm_state_reg,
            vm_dispatch_reg,
            vm_infra_regs,
        }) => {
            let profile = VmProfile::new(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs);
            cmd_vm_backchain(
                trace_dir,
                idx,
                reg,
                steps,
                context,
                lookback,
                max_writes,
                follow_frontier,
                byte_lane,
                regs,
                summary,
                profile,
            )
            .await
        }
        Some(Cmd::VmBacktree {
            trace_dir,
            idx,
            reg,
            depth,
            max_nodes,
            context,
            lookback,
            max_writes,
            frontier_with_next,
            summary,
            regs,
            vm_ip_reg,
            vm_state_reg,
            vm_dispatch_reg,
            vm_infra_regs,
        }) => {
            let profile = VmProfile::new(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs);
            cmd_vm_backtree(
                trace_dir,
                idx,
                reg,
                depth,
                max_nodes,
                context,
                lookback,
                max_writes,
                frontier_with_next,
                summary,
                regs,
                profile,
            )
            .await
        }
        Some(Cmd::JobjHistory {
            trace_dir,
            jobject,
            start,
            end,
            max,
        }) => {
            let params = vec![
                ("jobject", jobject),
                ("start", start.to_string()),
                ("end", end.to_string()),
                ("max", max.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/jobj-history", &params)).await
        }
        Some(Cmd::JniStrings {
            trace_dir,
            max,
            max_len,
        }) => {
            let params = vec![("max", max.to_string()), ("max_len", max_len.to_string())];
            route_get_json(trace_dir, route_path("/api/jni-strings", &params)).await
        }
        Some(Cmd::DecSummary { trace_dir }) => {
            route_get_json(trace_dir, "/api/dec/summary".to_string()).await
        }
        Some(Cmd::DecFn {
            trace_dir,
            fn_id,
            tier,
        }) => {
            let path = format!(
                "/api/dec/fn/{}?tier={}",
                pct_encode(&fn_id),
                pct_encode(&tier)
            );
            route_get_json(trace_dir, path).await
        }
        Some(Cmd::DecModels { trace_dir }) => {
            route_get_json(trace_dir, "/api/dec/models".to_string()).await
        }
        Some(Cmd::LlilPipeline {
            trace_dir,
            fn_id,
            max_records,
            include_text,
            include_call_analysis,
            json: _json,
        }) => {
            let body = serde_json::json!({
                "fn_id": fn_id,
                "max_records": max_records,
                "include_text": include_text,
                "include_call_analysis": include_call_analysis,
            });
            route_post_json(trace_dir, "/api/llil/pipeline".to_string(), body).await
        }
        Some(Cmd::LlilRender {
            trace_dir,
            fn_id,
            max_records,
            no_ssa,
            no_constfold,
            no_flag_elim,
            dce,
        }) => {
            let body = serde_json::json!({
                "fn_id": fn_id,
                "max_records": max_records,
                "ssa": !no_ssa,
                "constfold": !no_constfold,
                "flag_elim": !no_flag_elim,
                "dce": dce,
            });
            route_post_json(trace_dir, "/api/llil/render".to_string(), body).await
        }
        None => {
            eprintln!("run with --help to list Rust v2 CLI commands");
            Ok(())
        }
    }
}

async fn route_post_json(
    trace_dir: PathBuf,
    path: String,
    body: serde_json::Value,
) -> anyhow::Result<()> {
    let app = build_cli_router(trace_dir, &path, Some(&body))?;
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .method(axum::http::Method::POST)
                .uri(&path)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        bail!(
            "{} returned {}: {}",
            path,
            status,
            String::from_utf8_lossy(&body)
        );
    }
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    print_pretty(&value)
}

fn build_cli_router(
    trace_dir: PathBuf,
    path: &str,
    body: Option<&serde_json::Value>,
) -> anyhow::Result<axum::Router> {
    if route_needs_memshadow(path, body) {
        tracemiku_server::build_router_with_memshadow(trace_dir)
    } else {
        tracemiku_server::build_router(trace_dir)
    }
}

fn route_needs_memshadow(path: &str, body: Option<&serde_json::Value>) -> bool {
    let endpoint = path.split('?').next().unwrap_or(path);
    if matches!(endpoint, "/api/backward-taint" | "/api/forward-taint") {
        return path.contains("through_mem=true");
    }
    if endpoint == "/api/mem-writes-in-range" {
        return path.contains("src_byte=");
    }
    if matches!(
        endpoint,
        "/api/auto-phase-detect"
            | "/api/crypto-analysis"
            | "/api/crypto-scan"
            | "/api/find-mem-pattern"
            | "/api/hash-finalize-detect"
            | "/api/jni-strings"
            | "/api/mem-diff"
            | "/api/mem-dump"
            | "/api/mem-flow"
            | "/api/string-provenance"
            | "/api/strings"
    ) {
        return true;
    }
    if endpoint == "/api/hash-input-search" {
        return body
            .and_then(|v| v.get("search_in_mem"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
    }
    endpoint == "/api/query"
        && [
            "kind=mem",
            "kind=memory",
            "kind=read",
            "kind=reads",
            "kind=reader",
            "kind=readers",
            "kind=write",
            "kind=writes",
            "kind=writer",
            "kind=writers",
            "kind=string",
            "kind=strings",
            "kind=provenance",
            "kind=prov",
        ]
        .iter()
        .any(|needle| path.contains(needle))
}

#[cfg(test)]
mod tests;

fn print_pretty(value: &serde_json::Value) -> anyhow::Result<()> {
    use std::io::IsTerminal;
    let s = if std::io::stdout().is_terminal() {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    println!("{s}");
    Ok(())
}
