use std::path::{Path, PathBuf};
use tracemiku_core::analysis::{AnalysisContext, Query};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand, ValueEnum};

use tracemiku_core::analysis::reports::{
    self as core_reports, list_calls, list_runs, mem_dump_summary, resolve_offset_to_idx,
    split_csv, split_csv_allow_empty, OutputBacktraceOpts, OutputMapOpts, VmProfile,
};
mod reports;
use reports::*;
mod cli_support;
use cli_support::*;
mod capabilities;
use capabilities::*;
mod args;
use args::*;
mod query;
mod replay_command;
use query::*;

pub fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::TraceReplay { args }) => replay_command::run(args),
        Some(Cmd::Capabilities) => print_pretty(&capabilities_json()),
        Some(Cmd::Completions { shell }) => {
            use clap::CommandFactory;
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            clap_complete::generate(shell, &mut command, name, &mut std::io::stdout());
            Ok(())
        }
        Some(Cmd::Stats {
            trace_dir,
            all_modules,
            top_modules,
        }) => cmd_stats(trace_dir, all_modules, top_modules),
        Some(Cmd::Meta { trace_dir }) => query_json(trace_dir, Query::Meta),
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
                if !idxs.is_empty() {
                    // 批量查询复用同一个分析上下文，避免逐条重读 trace 与索引。
                    let context = AnalysisContext::load(trace_dir)?;
                    for idx in &idxs {
                        let path = Query::Record(*idx);
                        match query_value_on(&context, path) {
                            Ok(v) => results.push(v),
                            Err(_) => {
                                results.push(serde_json::json!({"idx": idx, "error": "not found"}))
                            }
                        }
                    }
                }
                print_pretty(&serde_json::Value::Array(results))?;
                return Ok(());
            }
            let mut params = tracemiku_core::analysis::records::RecordsQuery {
                start,
                count,
                ..Default::default()
            };
            if let Some(regs) = regs {
                params.regs = regs;
            }
            query_json(trace_dir, Query::Records(params))
        }
        Some(Cmd::Record { trace_dir, idx }) => query_json(trace_dir, Query::Record(idx)),
        Some(Cmd::IdxsForPc {
            trace_dir,
            pc,
            cursor,
            limit,
        }) => {
            let params =
                tracemiku_core::analysis::idxs_for_pc::IdxsForPcQuery { pc, cursor, limit };
            query_json(trace_dir, Query::IdxsForPc(params))
        }
        Some(Cmd::Search {
            trace_dir,
            pattern,
            max_results,
            cursor,
        }) => {
            let mut params = tracemiku_core::analysis::search::SearchQuery {
                pattern,
                max_results,
                ..Default::default()
            };
            if let Some(cursor) = cursor {
                params.cursor = Some(cursor);
            }
            query_json(trace_dir, Query::Search(params))
        }
        Some(Cmd::SoStats {
            trace_dir,
            top,
            all,
        }) => {
            let params = tracemiku_core::analysis::so_stats::SoStatsQuery { top, all };
            query_json(trace_dir, Query::SoStats(params))
        }
        Some(Cmd::Resolve {
            trace_dir,
            addr,
            so,
            off,
        }) => {
            let mut params = tracemiku_core::analysis::resolve::ResolveQuery {
                ..Default::default()
            };
            if let Some(addr) = addr {
                params.addr = Some(addr);
            }
            if let Some(so) = so {
                params.so = Some(so);
            }
            if let Some(off) = off {
                params.off = Some(off);
            }
            query_json(trace_dir, Query::Resolve(params))
        }
        Some(Cmd::IndirectTargets {
            trace_dir,
            addr,
            so,
            off,
            min_count,
        }) => {
            let mut params = tracemiku_core::analysis::indirect_targets::IndirectTargetsQuery {
                ..Default::default()
            };
            if let Some(addr) = addr {
                params.addr = Some(addr);
            }
            if let Some(so) = so {
                params.so = Some(so);
            }
            if let Some(off) = off {
                params.off = Some(off);
            }
            if let Some(min_count) = min_count {
                params.min_count = min_count;
            }
            query_json(trace_dir, Query::IndirectTargets(params))
        }
        Some(Cmd::RegAt {
            trace_dir,
            reg,
            addr,
            so,
            off,
            max,
        }) => {
            let mut params = tracemiku_core::analysis::reg_at::RegAtQuery {
                reg,
                ..Default::default()
            };
            if let Some(addr) = addr {
                params.addr = Some(addr);
            }
            if let Some(so) = so {
                params.so = Some(so);
            }
            if let Some(off) = off {
                params.off = Some(off);
            }
            if let Some(max) = max {
                params.max = max;
            }
            query_json(trace_dir, Query::RegAt(params))
        }
        Some(Cmd::RegValueAt {
            trace_dir,
            idx,
            reg,
        }) => {
            let params = tracemiku_core::analysis::reg_value_at::RegValueAtQuery { idx, reg };
            query_json(trace_dir, Query::RegValueAt(params))
        }
        Some(Cmd::LastWriteOfReg {
            trace_dir,
            reg,
            before,
            cursor,
        }) => {
            let mut params = tracemiku_core::analysis::last_write_of_reg::LastWriteQuery {
                reg,
                ..Default::default()
            };
            if let Some(before) = before {
                params.before = Some(before);
            }
            if let Some(cursor) = cursor {
                params.cursor = Some(cursor);
            }
            query_json(trace_dir, Query::LastWriteOfReg(params))
        }
        Some(Cmd::NextUseOfReg {
            trace_dir,
            reg,
            after,
        }) => {
            let mut params = tracemiku_core::analysis::next_use_of_reg::NextUseQuery {
                reg,
                ..Default::default()
            };
            if let Some(after) = after {
                params.after = Some(after);
            }
            query_json(trace_dir, Query::NextUseOfReg(params))
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
            let mut params = tracemiku_core::analysis::watchpoints::WatchpointsQuery {
                kind,
                size,
                cursor,
                limit,
                ..Default::default()
            };
            if let Some(reg) = reg {
                params.reg = Some(reg);
            }
            if let Some(addr) = addr {
                params.addr = Some(addr);
            }
            if let Some(value) = value {
                params.value = Some(value);
            }
            query_json(trace_dir, Query::Watchpoints(params))
        }
        Some(Cmd::Functions { trace_dir }) => query_json(trace_dir, Query::Functions),
        Some(Cmd::ForkEvents {
            trace_dir,
            status,
            is_fork_like,
            limit,
        }) => {
            let mut params = tracemiku_core::analysis::fork_events::ForkEventsQuery {
                limit,
                ..Default::default()
            };
            if let Some(status) = status {
                params.status = Some(status);
            }
            if let Some(is_fork_like) = is_fork_like {
                params.is_fork_like = Some(is_fork_like);
            }
            query_json(trace_dir, Query::ForkEvents(params))
        }
        Some(Cmd::Cfg { trace_dir, fn_name }) => {
            let mut params = tracemiku_core::analysis::cfg::CfgQuery {
                ..Default::default()
            };
            if let Some(name) = fn_name {
                params.fn_name = name;
            }
            query_json(trace_dir, Query::Cfg(params))
        }
        Some(Cmd::IdxsForBlock {
            trace_dir,
            pc,
            max_count,
            near,
        }) => {
            let params = tracemiku_core::analysis::idxs_for_block::IdxsForBlockQuery {
                pc,
                max_count,
                near,
            };
            query_json(trace_dir, Query::IdxsForBlock(params))
        }
        Some(Cmd::BlockForPc { trace_dir, pc }) => query_json(
            trace_dir,
            Query::BlockForPc(tracemiku_core::analysis::navigation::PcQuery { pc }),
        ),
        Some(Cmd::Block { trace_dir, pc }) => query_json(
            trace_dir,
            Query::Block(tracemiku_core::analysis::navigation::PcQuery { pc }),
        ),
        Some(Cmd::Loops { trace_dir }) => query_json(trace_dir, Query::Loops),
        Some(Cmd::Coverage {
            trace_dir,
            addr,
            so,
            off,
            fn_name,
        }) => {
            let mut params = tracemiku_core::analysis::coverage::CoverageQuery {
                ..Default::default()
            };
            if let Some(addr) = addr {
                params.addr = Some(addr);
            }
            if let Some(so) = so {
                params.so = Some(so);
            }
            if let Some(off) = off {
                params.off = Some(off);
            }
            if let Some(fn_name) = fn_name {
                params.fn_name = fn_name;
            }
            query_json(trace_dir, Query::Coverage(params))
        }
        Some(Cmd::Backtrace {
            trace_dir,
            idx,
            limit,
        }) => {
            let params = tracemiku_core::analysis::navigation::BacktraceQuery { idx, limit };
            query_json(trace_dir, Query::Backtrace(params))
        }
        Some(Cmd::CallTree {
            trace_dir,
            max_depth,
        }) => {
            let mut params = tracemiku_core::analysis::call_tree::CallTreeQuery {
                ..Default::default()
            };
            if let Some(depth) = max_depth {
                params.max_depth = Some(depth);
            }
            query_json(trace_dir, Query::CallTree(params))
        }
        Some(Cmd::CallChain {
            trace_dir,
            idx,
            depth,
        }) => {
            let params = tracemiku_core::analysis::navigation::CallChainQuery { idx, depth };
            query_json(trace_dir, Query::CallChain(params))
        }
        Some(Cmd::Strings {
            trace_dir,
            min_len,
            q,
            cursor,
            limit,
        }) => {
            let params = tracemiku_core::analysis::strings::StringsQuery {
                min_len,
                q,
                cursor,
                limit,
            };
            query_json(trace_dir, Query::Strings(params))
        }
        Some(Cmd::StringProvenance {
            trace_dir,
            addr,
            length,
        }) => {
            let params =
                tracemiku_core::analysis::string_provenance::StringProvenanceQuery { addr, length };
            query_json(trace_dir, Query::StringProvenance(params))
        }
        Some(Cmd::MemDump {
            trace_dir,
            addr,
            count,
            cursor,
            summary,
            cstr,
        }) => {
            let mut params = tracemiku_core::analysis::mem_dump::MemDumpQuery {
                addr,
                count,
                ..Default::default()
            };
            if let Some(cursor) = cursor {
                params.cursor = Some(cursor);
            }
            let path = Query::MemDump(params);
            if summary || cstr {
                let value = query_value(trace_dir, path)?;
                print_pretty(&mem_dump_summary(&value, cstr))
            } else {
                query_json(trace_dir, path)
            }
        }
        Some(Cmd::MemTenet {
            trace_dir,
            addr,
            length,
        }) => cmd_mem_tenet(trace_dir, addr, length),
        Some(Cmd::MemExport {
            trace_dir,
            addr,
            so,
            off,
            len,
            cursor,
            out,
        }) => {
            let mut params = tracemiku_core::analysis::mem_export::MemExportQuery {
                len: Some(len),
                ..Default::default()
            };
            if let Some(addr) = addr {
                params.addr = Some(addr);
            }
            if let Some(so) = so {
                params.so = Some(so);
            }
            if let Some(off) = off {
                params.off = Some(off);
            }
            if let Some(cursor) = cursor {
                params.cursor = Some(cursor);
            }
            let path = Query::MemExport(params);
            let value = query_value(trace_dir, path)?;
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
            let params = tracemiku_core::analysis::memory_query::LastWriteOfAddrQuery {
                addr,
                before_idx,
                with_external,
            };
            query_json(trace_dir, Query::LastWriteOfAddr(params))
        }
        Some(Cmd::IdxsTouchingAddr {
            trace_dir,
            addr,
            cursor,
            limit,
            with_bytes,
        }) => {
            let params = tracemiku_core::analysis::memory_query::TouchingAddrQuery {
                addr,
                cursor,
                limit,
                with_bytes,
            };
            query_json(trace_dir, Query::IdxsTouchingAddr(params))
        }
        Some(Cmd::IdxsTouchingRange {
            trace_dir,
            addr,
            size,
            cursor,
            limit,
        }) => {
            let params = tracemiku_core::analysis::memory_query::TouchingRangeQuery {
                addr,
                size,
                cursor,
                limit,
            };
            query_json(trace_dir, Query::IdxsTouchingRange(params))
        }
        Some(Cmd::FindMemPattern {
            trace_dir,
            bytes_hex,
            since,
            max,
            idx_lo,
            idx_hi,
        }) => {
            let mut params = tracemiku_core::analysis::memory_query::FindMemPatternQuery {
                bytes_hex,
                since,
                max,
                ..Default::default()
            };
            if let Some(idx_lo) = idx_lo {
                params.idx_lo = Some(idx_lo);
            }
            if let Some(idx_hi) = idx_hi {
                params.idx_hi = Some(idx_hi);
            }
            query_json(trace_dir, Query::FindMemPattern(params))
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
            let params = tracemiku_core::analysis::forward_taint::ForwardTaintQuery {
                start,
                reg,
                max_count,
                through_mem,
                data_only,
                cross_fn_call,
                scan_limit,
            };
            query_json(trace_dir, Query::ForwardTaint(params))
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
            let context = AnalysisContext::load(trace_dir)?;
            let start = match (start, so.as_ref(), off.as_ref()) {
                (Some(s), _, _) => s,
                (None, Some(so), Some(off)) => {
                    let (idx, _pc) = resolve_offset_to_idx(&context, so, off, occurrence)?;
                    idx
                }
                (None, _, _) => {
                    bail!("taint-bwd needs --start <idx> or (--so <name> --off <offset>)")
                }
            };
            let params = tracemiku_core::analysis::backward_taint::BackwardTaintQuery {
                start,
                reg,
                max_count,
                through_mem,
                data_only,
                cross_fn_call,
                scan_limit,
            };
            let value = query_value_on(&context, Query::BackwardTaint(params))?;
            print_pretty(&value)
        }
        Some(Cmd::DataChase {
            trace_dir,
            start,
            reg,
            max_steps,
            exclude_regs,
        }) => {
            let params = tracemiku_core::analysis::data_chase::DataChaseQuery {
                start,
                reg,
                max_steps,
                exclude_regs,
            };
            query_json(trace_dir, Query::DataChase(params))
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
            let mut params = tracemiku_core::analysis::dep_graph::DepGraphQuery {
                depth,
                limit,
                ..Default::default()
            };
            if let Some(idx) = idx {
                params.idx = Some(idx);
            }
            if let Some(reg) = reg {
                params.reg = Some(reg);
            }
            if let Some(addr) = addr {
                params.addr = Some(addr);
            }
            if let Some(before) = before {
                params.before = Some(before);
            }
            query_json(trace_dir, Query::DepGraph(params))
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
            let context = AnalysisContext::load(trace_dir)?;
            // (SO,offset) seed resolves to a concrete idx, joining the existing
            // idx/reg/addr seed family without touching the server route.
            let resolved_idx = match (so.as_ref(), off.as_ref()) {
                (Some(so), Some(off)) => {
                    let (i, _pc) = resolve_offset_to_idx(&context, so, off, occurrence)?;
                    Some(i)
                }
                (Some(_), None) | (None, Some(_)) => {
                    bail!("bfs-slice --so and --off must be given together")
                }
                (None, None) => None,
            };
            let mut params = tracemiku_core::analysis::bfs_slice::BfsSliceQuery {
                limit,
                data_only,
                mode: Some(mode),
                ..Default::default()
            };
            if let Some(v) = resolved_idx.or(idx) {
                params.idx = Some(v);
            }
            if let Some(v) = idxs {
                params.idxs = Some(v);
            }
            if let Some(v) = reg {
                params.reg = Some(v);
            }
            if let Some(v) = regs {
                params.regs = Some(v);
            }
            if let Some(v) = addr {
                params.addr = Some(v);
            }
            if let Some(v) = addrs {
                params.addrs = Some(v);
            }
            if let Some(v) = before {
                params.before = Some(v);
            }
            let value = query_value_on(&context, Query::BfsSlice(params))?;
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
            let context = AnalysisContext::load(trace_dir)?;
            let resolved_idx = match (so.as_ref(), off.as_ref()) {
                (Some(so), Some(off)) => {
                    let (i, _pc) = resolve_offset_to_idx(&context, so, off, occurrence)?;
                    Some(i)
                }
                (Some(_), None) | (None, Some(_)) => {
                    bail!("forward-dep-tree --so and --off must be given together")
                }
                (None, None) => None,
            };
            let mut params = tracemiku_core::analysis::forward_dep_tree::ForwardDepTreeQuery {
                depth,
                limit,
                data_only,
                ..Default::default()
            };
            if let Some(v) = resolved_idx.or(idx) {
                params.idx = Some(v);
            }
            if let Some(v) = reg {
                params.reg = Some(v);
            }
            if let Some(v) = addr {
                params.addr = Some(v);
            }
            if let Some(v) = before {
                params.before = Some(v);
            }
            let value = query_value_on(&context, Query::ForwardDepTree(params))?;
            print_pretty(&value)
        }
        Some(Cmd::RegTimeline {
            trace_dir,
            reg,
            start,
            end,
            max_points,
        }) => {
            let params = tracemiku_core::analysis::timeline_diff::RegTimelineQuery {
                reg,
                start,
                end,
                max_points,
            };
            query_json(trace_dir, Query::RegTimeline(params))
        }
        Some(Cmd::MemDiff {
            trace_dir,
            idx,
            addr,
            size,
        }) => {
            let params = tracemiku_core::analysis::timeline_diff::MemDiffQuery { idx, addr, size };
            query_json(trace_dir, Query::MemDiff(params))
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
            let mut params = tracemiku_core::analysis::mem_flow::MemFlowQuery {
                addr,
                count,
                events_per_byte,
                writers_only,
                readers_only,
                ..Default::default()
            };
            if let Some(idx_lo) = idx_lo {
                params.idx_lo = Some(idx_lo);
            }
            if let Some(idx_hi) = idx_hi {
                params.idx_hi = Some(idx_hi);
            }
            query_json(trace_dir, Query::MemFlow(params))
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
            let mut params = tracemiku_core::analysis::memory_query::MemWritesInRangeQuery {
                idx_lo,
                idx_hi,
                max,
                with_external,
                ..Default::default()
            };
            if let Some(addr_lo) = addr_lo {
                params.addr_lo = Some(addr_lo);
            }
            if let Some(addr_hi) = addr_hi {
                params.addr_hi = Some(addr_hi);
            }
            if let Some(src_byte) = src_byte {
                params.src_byte = Some(src_byte);
            }
            query_json(trace_dir, Query::MemWritesInRange(params))
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
            let profile = if vm_chain_steps > 0 && vm_chain_runs > 0 {
                parse_vm_profile(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs)?
            } else {
                VmProfile::disabled()
            };
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
        }
        Some(Cmd::OllvmDetectVm {
            trace_dir,
            min_entries,
            threshold,
        }) => {
            let params = tracemiku_core::analysis::ollvm_detect_vm::OllvmDetectVmQuery {
                min_entries,
                threshold,
            };
            query_json(trace_dir, Query::OllvmDetectVm(params))
        }
        Some(Cmd::FnSummary {
            trace_dir,
            fn_name,
            top_blocks,
        }) => {
            let params = tracemiku_core::analysis::fn_summary::FnSummaryQuery {
                fn_name,
                top_blocks,
            };
            query_json(trace_dir, Query::FnSummary(params))
        }
        Some(Cmd::CryptoScan { trace_dir }) => query_json(trace_dir, Query::CryptoScan),
        // crypto 只输出 core 的分析响应；空结果的
        // note 由 server 侧统一补充，CLI 不再修补分析结果。
        Some(Cmd::Crypto { trace_dir }) => query_json(trace_dir, Query::CryptoAnalysis),
        Some(Cmd::HashFinalizeDetect {
            trace_dir,
            window,
            min_size,
            limit,
            map_bytes,
            map_candidates,
            nonzero_only,
            target_bytes,
        }) => cmd_hash_finalize_detect(
            trace_dir,
            window,
            min_size,
            limit,
            map_bytes,
            map_candidates,
            nonzero_only,
            target_bytes,
        ),
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
            let request = tracemiku_core::analysis::hash_input_search::HashInputSearchRequest {
                target_bytes,
                inputs: split_csv(&inputs),
                keys: split_csv_allow_empty(&keys),
                algos: split_csv(&algos),
                combos: split_csv(&combos),
                prefix_bytes,
                search_in_mem,
            };
            query_json(trace_dir, Query::HashInputSearch(request))
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
            let request = tracemiku_core::analysis::diff_traces::DiffTracesRequest {
                traces: traces
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>(),
                keys,
                show_offsets,
                show_per_byte,
            };
            query_json(trace_dir, Query::DiffTraces(request))
        }
        Some(Cmd::AutoPhaseDetect {
            trace_dir,
            detect_byte_streams,
            max_phases,
        }) => {
            let params = tracemiku_core::analysis::auto_phase::AutoPhaseQuery {
                detect_byte_streams,
                max_phases,
            };
            query_json(trace_dir, Query::AutoPhaseDetect(params))
        }
        Some(Cmd::JniCalls {
            trace_dir,
            in_fn,
            max,
        }) => {
            let mut params = tracemiku_core::analysis::jni_calls::JniCallsQuery {
                max,
                ..Default::default()
            };
            if let Some(in_fn) = in_fn {
                params.in_fn = Some(in_fn);
            }
            query_json(trace_dir, Query::JniCalls(params))
        }
        Some(Cmd::JniEvents {
            trace_dir,
            id,
            idx_lo,
            idx_hi,
            limit,
        }) => {
            let mut params = tracemiku_core::analysis::jni_events::JniEventsQuery {
                limit,
                ..Default::default()
            };
            if let Some(id) = id {
                params.id = Some(id);
            }
            if let Some(idx_lo) = idx_lo {
                params.idx_lo = Some(idx_lo);
            }
            if let Some(idx_hi) = idx_hi {
                params.idx_hi = Some(idx_hi);
            }
            query_json(trace_dir, Query::JniEvents(params))
        }
        Some(Cmd::JniOutputStrings {
            trace_dir,
            key,
            contains,
            limit,
        }) => cmd_jni_output_strings(trace_dir, key, contains, limit),
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
            let vm_profile = if vm_chain_steps > 0 && vm_chain_runs > 0 {
                parse_vm_profile(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs)?
            } else {
                VmProfile::disabled()
            };
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
            cmd_output_backtrace(trace_dir, opts)
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
            let needs_vm_profile = tree_depth > 0
                || index_tree_depth > 0
                || (semantic_writer_map_vm_chain_steps > 0
                    && semantic_writer_map_vm_chain_runs > 0);
            let vm_profile = if needs_vm_profile {
                parse_vm_profile(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs)?
            } else {
                VmProfile::disabled()
            };
            let opts = OutputMapOpts {
                key,
                value,
                jni_limit,
                max_mem_hits,
                hit_rank,
                hit_order: hit_order.into(),
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
            cmd_output_map(trace_dir, opts)
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
            let profile =
                parse_vm_profile(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs)?;
            cmd_vm_slice(
                trace_dir, start, end, count, regs, only_vm, base_ip, profile,
            )
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
            let profile =
                parse_vm_profile(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs)?;
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
        }) => cmd_byte_lineage(
            trace_dir, addr, before_idx, count, depth, context, lookback, max_writes, regs,
            summary, compact,
        ),
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
            let profile =
                parse_vm_profile(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs)?;
            cmd_vm_backstep(
                trace_dir, idx, reg, context, lookback, max_writes, regs, profile,
            )
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
            let profile =
                parse_vm_profile(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs)?;
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
            let profile =
                parse_vm_profile(vm_ip_reg, vm_state_reg, vm_dispatch_reg, vm_infra_regs)?;
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
        }
        Some(Cmd::JobjHistory {
            trace_dir,
            jobject,
            start,
            end,
            max,
        }) => {
            let params = tracemiku_core::analysis::jobj_history::JobjHistoryQuery {
                jobject,
                start,
                end,
                max,
            };
            query_json(trace_dir, Query::JobjHistory(params))
        }
        Some(Cmd::JniStrings {
            trace_dir,
            max,
            max_len,
        }) => {
            let params = tracemiku_core::analysis::jni_strings::JniStringsQuery { max, max_len };
            query_json(trace_dir, Query::JniStrings(params))
        }
        Some(Cmd::Finalize { path }) => cmd_finalize(&path),
        None => {
            eprintln!("run with --help to list Rust v2 CLI commands");
            Ok(())
        }
    }
}

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

/// `finalize` 的唯一语义实现来自 core；CLI 只做参数解析与序列化。
fn cmd_finalize(path: &std::path::Path) -> anyhow::Result<()> {
    use tracemiku_core::trace::finalize::finalize_run;
    let report = finalize_run(path)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.pending > 0 {
        eprintln!(
            "[!] {} 个 call 缺少本地 trace.bin, 保持 pending; 设备数据就绪后重跑 finalize",
            report.pending
        );
    }
    Ok(())
}
