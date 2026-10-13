use std::path::PathBuf;
use tracemiku_core::analysis::{AnalysisContext, Query};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};

use tracemiku_core::analysis::reports::{
    self as core_reports, list_calls, list_runs, resolve_offset_to_idx, OutputBacktraceOpts,
    VmProfile,
};
mod reports;
use reports::*;
mod cli_support;
use cli_support::*;
mod capabilities;
use capabilities::*;
mod args;
use args::*;
mod experimental;
mod query;
mod replay_command;
mod vm_args;
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
        Some(Cmd::List { path, dir, json }) => cmd_list(path, dir, json),
        Some(Cmd::Info { path }) => cmd_info(path),
        Some(Cmd::Records {
            trace_dir,
            start,
            count,
            regs,
            indices,
            detail,
        }) => query_json(
            trace_dir,
            Query::Records(tracemiku_core::analysis::records::RecordsQuery {
                start,
                count,
                regs,
                indices,
                detail,
            }),
        ),
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
            maps,
            addr,
            so,
            off,
        }) => {
            if let Some(maps) = maps {
                print_pretty(&core_reports::resolve_map_addr(
                    maps,
                    addr.context("--maps requires --addr")?,
                )?)
            } else {
                query_json(
                    trace_dir.context("provide a call directory or --maps")?,
                    Query::Resolve(tracemiku_core::analysis::resolve::ResolveQuery {
                        addr,
                        so,
                        off,
                    }),
                )
            }
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
        Some(Cmd::LastWriteOfReg {
            trace_dir,
            reg,
            before,
        }) => {
            let mut params = tracemiku_core::analysis::last_write_of_reg::LastWriteQuery {
                reg,
                ..Default::default()
            };
            if let Some(before) = before {
                params.before = Some(before);
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
        Some(Cmd::Functions { trace_dir, fn_id }) => query_json(
            trace_dir,
            Query::FunctionsInspect(tracemiku_core::analysis::functions::FunctionsQuery {
                fn_name: fn_id,
            }),
        ),
        Some(Cmd::Cfg {
            trace_dir,
            fn_name,
            pc,
            hits,
            coverage,
            cursor,
            limit,
        }) => query_json(
            trace_dir,
            Query::CfgInspect(tracemiku_core::analysis::cfg::CfgInspectQuery {
                fn_name: fn_name.unwrap_or_default(),
                pc,
                hits,
                coverage,
                cursor,
                limit,
            }),
        ),
        Some(Cmd::Loops { trace_dir }) => query_json(trace_dir, Query::Loops),
        Some(Cmd::Backtrace {
            trace_dir,
            idx,
            limit,
            lr_clues,
        }) => query_json(
            trace_dir,
            Query::BacktraceInspect(
                tracemiku_core::analysis::navigation::BacktraceInspectQuery {
                    idx,
                    limit,
                    lr_clues,
                },
            ),
        ),
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
        Some(Cmd::MemDump {
            trace_dir,
            addr,
            so,
            off,
            count,
            at,
            compare_at,
            out,
        }) => {
            let context = AnalysisContext::load(trace_dir)?;
            let dump = tracemiku_core::analysis::mem_dump::mem_dump(
                &context,
                tracemiku_core::analysis::mem_dump::MemDumpQuery {
                    addr: addr.unwrap_or_default(),
                    so,
                    off,
                    count,
                    at,
                    compare_at,
                },
            )?;
            if let Some(path) = out {
                let bytes = tracemiku_core::analysis::mem_dump::export_bytes(&dump)?;
                std::fs::write(&path, bytes)
                    .with_context(|| format!("write {}", path.display()))?;
            }
            print_pretty(&serde_json::to_value(dump)?)
        }

        Some(Cmd::MemTenet {
            trace_dir,
            addr,
            count,
            at,
        }) => query_json(
            trace_dir,
            Query::MemProvenance(
                tracemiku_core::analysis::mem_provenance::MemProvenanceQuery { addr, count, at },
            ),
        ),
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
            size,
            start,
            end,
            kind,
            limit,
            cursor,
        }) => query_json(
            trace_dir,
            Query::MemAccesses(tracemiku_core::analysis::mem_accesses::MemAccessesQuery {
                addr,
                size,
                start,
                end,
                kind,
                limit,
                cursor,
            }),
        ),
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
        Some(Cmd::BfsSlice {
            trace_dir,
            direction,
            view,
            depth,
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
            let mut params = tracemiku_core::analysis::dependency_seeds::DependencySeeds {
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
            let value = query_value_on(
                &context,
                Query::Dependencies(
                    tracemiku_core::analysis::dependency_query::DependencyQuery {
                        seeds: params,
                        direction,
                        view,
                        depth,
                    },
                ),
            )?;
            print_pretty(&value)
        }
        Some(Cmd::RegTimeline {
            trace_dir,
            reg,
            start,
            end,
            max_points,
            equals,
        }) => query_json(
            trace_dir,
            Query::RegInspect(tracemiku_core::analysis::timeline_diff::RegInspectQuery {
                reg,
                start,
                end,
                max_points,
                equals,
            }),
        ),
        Some(Cmd::Crypto { trace_dir }) => query_json(trace_dir, Query::CryptoAnalysis),
        Some(Cmd::JniCalls {
            trace_dir,
            in_fn,
            name,
            jobject,
            start,
            end,
            cursor,
            limit,
            strings,
            max_len,
        }) => query_json(
            trace_dir,
            Query::JniInspect(tracemiku_core::analysis::jni_calls::JniInspectQuery {
                in_fn,
                name,
                jobject,
                start,
                end,
                cursor,
                limit,
                strings,
                max_len,
            }),
        ),
        Some(Cmd::OutputBacktrace {
            trace_dir,
            value,
            bytes_hex,
            at_idx,
            max_mem_hits,
            writes_per_hit,
            taint_seeds,
            taint_max_count,

            skip_taint,
            no_url_decode,
            no_base64_decode,
        }) => {
            let opts = OutputBacktraceOpts {
                value,
                bytes_hex,
                at_idx,
                max_mem_hits,
                writes_per_hit,
                taint_seeds,
                taint_max_count,

                skip_taint,
                url_decode: !no_url_decode,
                base64_decode: !no_base64_decode,
            };
            cmd_output_backtrace(trace_dir, opts)
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
        Some(Cmd::Finalize { path }) => cmd_finalize(&path),
        Some(Cmd::Events {
            trace_dir,
            source,
            id,
            status,
            is_fork_like,
            start,
            end,
            cursor,
            limit,
        }) => {
            let result = tracemiku_core::analysis::events::read_events(
                &trace_dir,
                tracemiku_core::analysis::events::EventsQuery {
                    source,
                    id,
                    status,
                    is_fork_like,
                    start,
                    end,
                    cursor,
                    limit,
                },
            )?;
            print_pretty(&serde_json::to_value(result)?)
        }
        Some(Cmd::Experimental { command }) => experimental::run(command),
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
