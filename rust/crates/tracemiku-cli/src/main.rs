use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use axum::body::Body;
use clap::{Parser, Subcommand};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[derive(Parser, Debug)]
#[command(
    name = "tracemiku-cli",
    about = "traceMiku v2 CLI (Rust analysis + JSON route wrappers)",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Invoke any JSON web API route in-process.
    Api {
        /// Per-call trace directory.
        trace_dir: PathBuf,
        /// Route path such as /api/backtrace or /api/llil/render.
        path: String,
        /// HTTP method. Supports GET and POST. Default GET.
        #[arg(long, default_value = "GET")]
        method: String,
        /// Query parameter key=value. Can be repeated.
        #[arg(long = "param", short = 'p')]
        params: Vec<String>,
        /// JSON request body for POST routes.
        #[arg(long = "json-body")]
        json_body: Option<String>,
    },
    /// Print trace metadata as JSON.
    Stats {
        /// Per-call trace directory.
        trace_dir: PathBuf,
        /// Show ALL modules (overrides --top-modules).
        #[arg(long)]
        all_modules: bool,
        /// Limit modules list to top-N by size. Default 10.
        #[arg(long, default_value_t = 10)]
        top_modules: usize,
    },
    /// GET /api/meta.
    Meta { trace_dir: PathBuf },
    /// List runs under a trace root or calls under one run.
    List {
        /// Trace root or run dir. Defaults to ./traces.
        path: Option<PathBuf>,
        /// Base trace dir when path is omitted.
        #[arg(long, default_value = "traces")]
        dir: PathBuf,
        /// Emit JSON instead of a compact table.
        #[arg(long)]
        json: bool,
    },
    /// Inspect one run or per-call trace directory.
    Info {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// GET /api/records.
    Records {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 0)]
        start: usize,
        #[arg(long, default_value_t = 100)]
        count: usize,
        #[arg(long)]
        regs: Option<String>,
    },
    /// GET /api/record/{idx}.
    Record { trace_dir: PathBuf, idx: usize },
    /// GET /api/bg-status.
    BgStatus { trace_dir: PathBuf },
    /// GET /api/decomp-status.
    DecompStatus { trace_dir: PathBuf },
    /// GET /api/idxs-for-pc.
    IdxsForPc {
        trace_dir: PathBuf,
        pc: String,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// GET /api/search-pc.
    SearchPc {
        trace_dir: PathBuf,
        pc: String,
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
    /// GET /api/search.
    Search {
        trace_dir: PathBuf,
        pattern: String,
        #[arg(long, default_value_t = 2000)]
        max_results: usize,
        #[arg(long)]
        cursor: Option<usize>,
    },
    /// Alias for GET /api/search, matching the legacy command name.
    SearchAsm {
        trace_dir: PathBuf,
        pattern: String,
        #[arg(long, default_value_t = 2000)]
        max_results: usize,
        #[arg(long)]
        cursor: Option<usize>,
    },
    /// GET /api/query.
    Query {
        trace_dir: PathBuf,
        #[arg(long, default_value = "records")]
        kind: String,
        #[arg(long = "q", default_value = "")]
        q: String,
        #[arg(long)]
        idx: Option<usize>,
        #[arg(long)]
        reg: Option<String>,
        #[arg(long)]
        addr: Option<String>,
        #[arg(long, default_value_t = 1)]
        len: u64,
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// GET /api/so-stats.
    SoStats {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 50)]
        top: usize,
        #[arg(long)]
        all: bool,
    },
    /// GET /api/reg-value-at.
    RegValueAt {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long)]
        reg: String,
    },
    /// Alias for GET /api/reg-value-at.
    RegAtIdx {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long)]
        reg: String,
    },
    /// GET /api/last-write-of-reg.
    LastWriteOfReg {
        trace_dir: PathBuf,
        #[arg(long)]
        reg: String,
        #[arg(long)]
        before: Option<usize>,
        #[arg(long)]
        cursor: Option<usize>,
    },
    /// GET /api/functions.
    Functions { trace_dir: PathBuf },
    /// GET /api/fork-events.
    ForkEvents {
        trace_dir: PathBuf,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        is_fork_like: Option<bool>,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// GET /api/cfg.
    Cfg {
        trace_dir: PathBuf,
        #[arg(long = "fn")]
        fn_name: Option<String>,
    },
    /// GET /api/cfg-svg.
    CfgSvg {
        trace_dir: PathBuf,
        #[arg(long = "fn")]
        fn_name: Option<String>,
        #[arg(long)]
        pc: Option<String>,
        #[arg(long, default_value_t = 2)]
        local_depth: usize,
        #[arg(long, default_value_t = 60)]
        timeout: u64,
        #[arg(long)]
        force: bool,
    },
    /// GET /api/idxs-for-block.
    IdxsForBlock {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
        #[arg(long, default_value_t = 200)]
        max_count: usize,
        #[arg(long, default_value_t = -1)]
        near: isize,
    },
    /// GET /api/block-for-pc.
    BlockForPc {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
    },
    /// GET /api/block.
    Block {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
    },
    /// GET /api/loops.
    Loops { trace_dir: PathBuf },
    /// GET /api/backtrace.
    Backtrace {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long, default_value_t = 256)]
        limit: usize,
    },
    /// GET /api/call-tree.
    CallTree {
        trace_dir: PathBuf,
        #[arg(long)]
        max_depth: Option<usize>,
    },
    /// GET /api/call-chain.
    CallChain {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long, default_value_t = 5)]
        depth: usize,
    },
    /// GET /api/strings.
    Strings {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 4)]
        min_len: usize,
        #[arg(long, default_value = "")]
        q: String,
        #[arg(long, default_value_t = -1)]
        cursor: i64,
        #[arg(long, default_value_t = 0)]
        limit: usize,
    },
    /// GET /api/string-provenance.
    StringProvenance {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 32)]
        length: usize,
    },
    /// GET /api/mem-dump.
    MemDump {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 256)]
        count: usize,
    },
    /// GET /api/last-write-of-addr.
    LastWriteOfAddr {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = -1)]
        before_idx: isize,
    },
    /// GET /api/idxs-touching-addr.
    IdxsTouchingAddr {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        #[arg(long, default_value_t = 30)]
        limit: usize,
    },
    /// GET /api/idxs-touching-range.
    IdxsTouchingRange {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 1)]
        size: u64,
        #[arg(long, default_value_t = 0)]
        cursor: usize,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// GET /api/find-mem-pattern.
    FindMemPattern {
        trace_dir: PathBuf,
        #[arg(long = "bytes-hex")]
        bytes_hex: String,
        #[arg(long, default_value_t = -1)]
        since: isize,
        #[arg(long, default_value_t = 100)]
        max: usize,
        #[arg(long)]
        idx_lo: Option<usize>,
        #[arg(long)]
        idx_hi: Option<usize>,
    },
    /// GET /api/forward-taint.
    TaintFwd {
        trace_dir: PathBuf,
        #[arg(long)]
        start: usize,
        #[arg(long)]
        reg: String,
        #[arg(long)]
        max_count: Option<usize>,
        #[arg(long)]
        through_mem: bool,
        #[arg(long)]
        data_only: bool,
        #[arg(long)]
        cross_fn_call: bool,
    },
    /// GET /api/backward-taint.
    TaintBwd {
        trace_dir: PathBuf,
        #[arg(long)]
        start: usize,
        #[arg(long)]
        reg: String,
        #[arg(long)]
        max_count: Option<usize>,
        #[arg(long)]
        through_mem: bool,
        #[arg(long)]
        data_only: bool,
        #[arg(long)]
        cross_fn_call: bool,
    },
    /// GET /api/data-chase.
    DataChase {
        trace_dir: PathBuf,
        #[arg(long)]
        start: usize,
        #[arg(long)]
        reg: String,
        #[arg(long, default_value_t = 50)]
        max_steps: usize,
        #[arg(long, default_value = "sp,fp,lr")]
        exclude_regs: String,
    },
    /// GET /api/reg-timeline.
    RegTimeline {
        trace_dir: PathBuf,
        #[arg(long)]
        reg: String,
        #[arg(long, default_value_t = 0)]
        start: usize,
        #[arg(long, default_value_t = -1)]
        end: isize,
        #[arg(long, default_value_t = 1000)]
        max_points: usize,
    },
    /// GET /api/mem-diff.
    MemDiff {
        trace_dir: PathBuf,
        #[arg(long)]
        idx: usize,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 16)]
        size: usize,
    },
    /// GET /api/mem-flow.
    MemFlow {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = 8)]
        count: usize,
        #[arg(long)]
        idx_lo: Option<usize>,
        #[arg(long)]
        idx_hi: Option<usize>,
        #[arg(long, default_value_t = 10)]
        events_per_byte: usize,
        #[arg(long)]
        writers_only: bool,
        #[arg(long)]
        readers_only: bool,
    },
    /// GET /api/mem-writes-in-range.
    MemWritesInRange {
        trace_dir: PathBuf,
        #[arg(long)]
        idx_lo: usize,
        #[arg(long, default_value_t = -1)]
        idx_hi: isize,
        #[arg(long)]
        addr_lo: Option<String>,
        #[arg(long)]
        addr_hi: Option<String>,
        #[arg(long)]
        src_byte: Option<String>,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// GET /api/ollvm-detect-vm.
    OllvmDetectVm {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 10)]
        min_entries: usize,
        #[arg(long, default_value_t = 0.5)]
        threshold: f64,
    },
    /// GET /api/fn-summary.
    FnSummary {
        trace_dir: PathBuf,
        #[arg(long = "fn")]
        fn_name: String,
        #[arg(long, default_value_t = 5)]
        top_blocks: usize,
    },
    /// GET /api/crypto-scan.
    CryptoScan { trace_dir: PathBuf },
    /// GET /api/hash-finalize-detect.
    HashFinalizeDetect {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 500)]
        window: usize,
        #[arg(long, default_value_t = 16)]
        min_size: u64,
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    /// POST /api/hash-input-search.
    HashInputSearch {
        trace_dir: PathBuf,
        #[arg(long = "target-bytes")]
        target_bytes: String,
        #[arg(long)]
        inputs: String,
        #[arg(long, default_value = "")]
        keys: String,
        #[arg(long, default_value = "sha1,md5,sha256,hmac-sha1,hmac-md5,hmac-sha256")]
        algos: String,
        #[arg(long, default_value = "plain,prefix_key,suffix_key,key_prefix_input")]
        combos: String,
        #[arg(long, default_value_t = 8)]
        prefix_bytes: usize,
        #[arg(long, default_value_t = false)]
        search_in_mem: bool,
    },
    /// POST /api/diff-traces.
    DiffTraces {
        traces: Vec<PathBuf>,
        #[arg(long, default_value_t = false)]
        show_offsets: bool,
        #[arg(long, default_value_t = false)]
        show_per_byte: bool,
    },
    /// GET /api/field-at.
    FieldAt {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
        #[arg(long)]
        reg: String,
        #[arg(long, default_value = "0")]
        offset: String,
        #[arg(long)]
        so: Option<PathBuf>,
        #[arg(long)]
        backend: Option<String>,
    },
    /// GET /api/asm-tokens-for-pcs.
    AsmTokensForPcs {
        trace_dir: PathBuf,
        /// Comma-separated PCs.
        #[arg(long)]
        pcs: String,
    },
    /// GET /api/bn-sidecar/status.
    BnSidecarStatus { trace_dir: PathBuf },
    /// GET /api/hlil-for-pc.
    HlilForPc {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
    },
    /// GET /api/hlil-for-fn.
    HlilForFn {
        trace_dir: PathBuf,
        #[arg(long = "fn-id")]
        fn_id: String,
    },
    /// GET /api/bn-cfg-for-pc.
    BnCfgForPc {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
        #[arg(long, default_value = "asm")]
        mode: String,
    },
    /// GET /api/bn-cfg-svg-for-pc.
    BnCfgSvgForPc {
        trace_dir: PathBuf,
        #[arg(long)]
        pc: String,
        #[arg(long, default_value = "asm")]
        mode: String,
        #[arg(long)]
        timeout: Option<u64>,
    },
    /// GET /api/auto-phase-detect.
    AutoPhaseDetect {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = true)]
        detect_byte_streams: bool,
        #[arg(long, default_value_t = 2000)]
        max_phases: usize,
    },
    /// GET /api/jni-calls.
    JniCalls {
        trace_dir: PathBuf,
        #[arg(long)]
        in_fn: Option<String>,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// GET /api/jni-events.
    JniEvents {
        trace_dir: PathBuf,
        #[arg(long, alias = "kind")]
        id: Option<String>,
        #[arg(long)]
        idx_lo: Option<usize>,
        #[arg(long)]
        idx_hi: Option<usize>,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    /// List NewStringUTF output key/value pairs.
    JniOutputStrings {
        trace_dir: PathBuf,
        /// Keep only pairs with this key, for example x-sign.
        #[arg(long)]
        key: Option<String>,
        /// Keep pairs whose key or value contains this text.
        #[arg(long)]
        contains: Option<String>,
        #[arg(long, default_value_t = 2000)]
        limit: usize,
    },
    /// Build an output-to-input backward trace report for a known output.
    OutputBacktrace {
        trace_dir: PathBuf,
        /// Start from a JNI NewStringUTF key/value pair, for example x-sign.
        #[arg(long)]
        key: Option<String>,
        /// Start from an observed UTF-8 output string directly.
        #[arg(long)]
        value: Option<String>,
        /// Start from raw bytes as hex instead of a UTF-8 string.
        #[arg(long = "bytes-hex")]
        bytes_hex: Option<String>,
        /// Max NewStringUTF events to scan when --key is used.
        #[arg(long, default_value_t = 2000)]
        jni_limit: usize,
        /// Max memory locations to report for each byte pattern.
        #[arg(long, default_value_t = 20)]
        max_mem_hits: usize,
        /// Max memory writes to report for each memory hit.
        #[arg(long, default_value_t = 20)]
        writes_per_hit: usize,
        /// Max backward-taint seeds to run from discovered writers.
        #[arg(long, default_value_t = 8)]
        taint_seeds: usize,
        /// Max rows per backward-taint seed.
        #[arg(long, default_value_t = 1000)]
        taint_max_count: usize,
        /// Skip backward-taint expansion and only report output/memory writers.
        #[arg(long)]
        skip_taint: bool,
        /// Do not add a percent-decoded pattern for URL-encoded strings.
        #[arg(long = "no-url-decode")]
        no_url_decode: bool,
    },
    /// GET /api/jobj-history.
    JobjHistory {
        trace_dir: PathBuf,
        #[arg(long)]
        jobject: String,
        #[arg(long, default_value_t = 0)]
        start: usize,
        #[arg(long, default_value_t = -1)]
        end: isize,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// GET /api/jni-strings.
    JniStrings {
        trace_dir: PathBuf,
        #[arg(long, default_value_t = 200)]
        max: usize,
        #[arg(long, default_value_t = 128)]
        max_len: usize,
    },
    /// GET /api/dec/summary.
    DecSummary { trace_dir: PathBuf },
    /// GET /api/dec/fn/{id}.
    DecFn {
        trace_dir: PathBuf,
        fn_id: String,
        #[arg(long, default_value = "hot")]
        tier: String,
    },
    /// GET /api/dec/models.
    DecModels { trace_dir: PathBuf },
    /// POST /api/llil/render.
    LlilRender {
        trace_dir: PathBuf,
        #[arg(long = "fn-id", default_value = "trace:F0")]
        fn_id: String,
        #[arg(long, default_value_t = 300)]
        max_records: usize,
        #[arg(long)]
        no_ssa: bool,
        #[arg(long)]
        no_constfold: bool,
        #[arg(long)]
        no_flag_elim: bool,
        #[arg(long)]
        dce: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
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
        Some(Cmd::Records {
            trace_dir,
            start,
            count,
            regs,
        }) => {
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
        }) => {
            let params = vec![("addr", addr), ("count", count.to_string())];
            route_get_json(trace_dir, route_path("/api/mem-dump", &params)).await
        }
        Some(Cmd::LastWriteOfAddr {
            trace_dir,
            addr,
            before_idx,
        }) => {
            let params = vec![("addr", addr), ("before_idx", before_idx.to_string())];
            route_get_json(trace_dir, route_path("/api/last-write-of-addr", &params)).await
        }
        Some(Cmd::IdxsTouchingAddr {
            trace_dir,
            addr,
            cursor,
            limit,
        }) => {
            let params = vec![
                ("addr", addr),
                ("cursor", cursor.to_string()),
                ("limit", limit.to_string()),
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
        }) => {
            let params = taint_params(start, reg, max_count, through_mem, data_only, cross_fn_call);
            route_get_json(trace_dir, route_path("/api/forward-taint", &params)).await
        }
        Some(Cmd::TaintBwd {
            trace_dir,
            start,
            reg,
            max_count,
            through_mem,
            data_only,
            cross_fn_call,
        }) => {
            let params = taint_params(start, reg, max_count, through_mem, data_only, cross_fn_call);
            route_get_json(trace_dir, route_path("/api/backward-taint", &params)).await
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
            max,
        }) => {
            let mut params = vec![
                ("idx_lo", idx_lo.to_string()),
                ("idx_hi", idx_hi.to_string()),
                ("max", max.to_string()),
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
        Some(Cmd::HashFinalizeDetect {
            trace_dir,
            window,
            min_size,
            limit,
        }) => {
            let params = vec![
                ("window", window.to_string()),
                ("min_size", min_size.to_string()),
                ("limit", limit.to_string()),
            ];
            route_get_json(trace_dir, route_path("/api/hash-finalize-detect", &params)).await
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
            skip_taint,
            no_url_decode,
        }) => {
            let opts = OutputBacktraceOpts {
                key,
                value,
                bytes_hex,
                jni_limit,
                max_mem_hits,
                writes_per_hit,
                taint_seeds,
                taint_max_count,
                skip_taint,
                url_decode: !no_url_decode,
            };
            cmd_output_backtrace(trace_dir, opts).await
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

fn cmd_stats(trace_dir: PathBuf, all_modules: bool, top_modules: usize) -> anyhow::Result<()> {
    let meta = tracemiku_core::prelude::TraceMeta::load(&trace_dir)?;
    let trace = tracemiku_core::prelude::Trace::load(&trace_dir)?;

    let modules_sorted: Vec<&tracemiku_core::prelude::ModuleInfo> = {
        let mut m: Vec<_> = meta.modules.iter().collect();
        m.sort_by_key(|x| std::cmp::Reverse(x.size));
        m
    };

    let target_name = meta.module.as_ref().map(|m| m.name.as_str());
    let modules_total = modules_sorted.len();
    let modules_out: Vec<&tracemiku_core::prelude::ModuleInfo> = if all_modules {
        modules_sorted.clone()
    } else {
        let n = top_modules.max(1);
        let mut kept: Vec<_> = if let Some(tn) = target_name {
            modules_sorted
                .iter()
                .copied()
                .filter(|m| m.name == tn)
                .take(1)
                .collect()
        } else {
            Vec::new()
        };
        let already = kept.iter().map(|m| m.name.as_str()).collect::<HashSet<_>>();
        let need = n.saturating_sub(kept.len());
        kept.extend(
            modules_sorted
                .iter()
                .copied()
                .filter(|m| !already.contains(m.name.as_str()))
                .take(need),
        );
        kept
    };

    print_pretty(&serde_json::json!({
        "path": trace_dir.display().to_string(),
        "records": trace.len(),
        "method": meta.method,
        "cmd": meta.cmd,
        "fn_addr": meta.fn_addr,
        "module": meta.module,
        "modules": modules_out,
        "modules_total": modules_total,
        "modules_truncated": modules_out.len() < modules_total,
    }))
}

async fn route_get_json(trace_dir: PathBuf, path: String) -> anyhow::Result<()> {
    let value = route_get_json_value(trace_dir, path).await?;
    print_pretty(&value)
}

async fn route_get_json_value(
    trace_dir: PathBuf,
    path: String,
) -> anyhow::Result<serde_json::Value> {
    let app = build_cli_router(trace_dir, &path, None)?;
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri(&path)
                .body(Body::empty())?,
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
    Ok(value)
}

async fn cmd_api(
    trace_dir: PathBuf,
    path: String,
    method: String,
    params: Vec<String>,
    json_body: Option<String>,
) -> anyhow::Result<()> {
    let path = route_path(&normalize_api_path(&path)?, &parse_key_values(params)?);
    match method.trim().to_ascii_uppercase().as_str() {
        "GET" => {
            if json_body.is_some() {
                bail!("--json-body is only valid for POST");
            }
            route_get_json(trace_dir, path).await
        }
        "POST" => {
            let body = match json_body {
                Some(raw) => serde_json::from_str(&raw).context("parse --json-body")?,
                None => serde_json::json!({}),
            };
            route_post_json(trace_dir, path, body).await
        }
        other => bail!("unsupported --method {other}; expected GET or POST"),
    }
}

async fn cmd_jni_output_strings(
    trace_dir: PathBuf,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    let report = jni_output_string_pairs(trace_dir, key, contains, limit).await?;
    print_pretty(&report)
}

async fn jni_output_string_pairs(
    trace_dir: PathBuf,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
) -> anyhow::Result<serde_json::Value> {
    let params = vec![
        ("limit", limit.to_string()),
        ("id", "NewStringUTF".to_string()),
    ];
    let value = route_get_json_value(trace_dir, route_path("/api/jni-events", &params)).await?;
    let events = value
        .get("events")
        .and_then(|v| v.as_array())
        .context("/api/jni-events response missing events[]")?;

    let mut strings = Vec::new();
    for event in events {
        if event.get("id").and_then(|v| v.as_str()) != Some("NewStringUTF") {
            continue;
        }
        let Some(text) = event
            .get("args")
            .and_then(|v| v.get("bytes"))
            .and_then(|v| v.as_str())
        else {
            continue;
        };
        strings.push(serde_json::json!({
            "idx": event.get("trace_idx").cloned().unwrap_or(serde_json::Value::Null),
            "ret": event.get("ret").cloned().unwrap_or(serde_json::Value::Null),
            "text": text,
            "text_len": text.len(),
        }));
    }

    let key_filter = key.as_deref();
    let contains_filter = contains.as_deref();
    let mut pairs = Vec::new();
    let mut iter = strings.chunks_exact(2);
    for pair in &mut iter {
        let key_text = pair[0].get("text").and_then(|v| v.as_str()).unwrap_or("");
        let value_text = pair[1].get("text").and_then(|v| v.as_str()).unwrap_or("");
        if key_filter.is_some_and(|needle| key_text != needle) {
            continue;
        }
        if contains_filter
            .is_some_and(|needle| !key_text.contains(needle) && !value_text.contains(needle))
        {
            continue;
        }
        pairs.push(serde_json::json!({
            "key_idx": pair[0].get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "key_ret": pair[0].get("ret").cloned().unwrap_or(serde_json::Value::Null),
            "key": key_text,
            "value_idx": pair[1].get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "value_ret": pair[1].get("ret").cloned().unwrap_or(serde_json::Value::Null),
            "value": value_text,
            "value_len": value_text.len(),
        }));
    }

    let unpaired = iter
        .remainder()
        .first()
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    Ok(serde_json::json!({
        "count": pairs.len(),
        "pairs": pairs,
        "source_events": strings.len(),
        "source_truncated": value.get("truncated").cloned().unwrap_or(serde_json::Value::Bool(false)),
        "unpaired": unpaired,
    }))
}

#[derive(Debug)]
struct OutputBacktraceOpts {
    key: Option<String>,
    value: Option<String>,
    bytes_hex: Option<String>,
    jni_limit: usize,
    max_mem_hits: usize,
    writes_per_hit: usize,
    taint_seeds: usize,
    taint_max_count: usize,
    skip_taint: bool,
    url_decode: bool,
}

#[derive(Debug)]
struct OutputSource {
    json: serde_json::Value,
    primary_bytes: Vec<u8>,
    text: Option<String>,
    value_idx: Option<usize>,
}

async fn cmd_output_backtrace(trace_dir: PathBuf, opts: OutputBacktraceOpts) -> anyhow::Result<()> {
    let source = resolve_output_source(trace_dir.clone(), &opts).await?;
    let mut patterns: Vec<(&'static str, Vec<u8>)> =
        vec![("observed", source.primary_bytes.clone())];
    if opts.url_decode {
        if let Some(text) = source.text.as_deref() {
            let decoded = percent_decode_bytes(text.as_bytes());
            if decoded != source.primary_bytes {
                patterns.push(("percent_decoded", decoded));
            }
        }
    }

    let mut seen_patterns = HashSet::new();
    let mut pattern_reports = Vec::new();
    let mut taint_seed_seen = HashSet::new();
    let mut taint_seed_queue: Vec<serde_json::Value> = Vec::new();

    if let Some(value_idx) = source.value_idx {
        if value_idx > 0 {
            push_taint_seed(
                &mut taint_seed_seen,
                &mut taint_seed_queue,
                serde_json::json!({
                    "kind": "jni_new_string_utf_callsite",
                    "start": value_idx - 1,
                    "reg": "x1",
                    "reason": "NewStringUTF callsite; x1 normally points at the C string bytes on ARM64",
                }),
            );
        }
    }

    for (kind, bytes) in patterns {
        if bytes.is_empty() {
            continue;
        }
        let hex = bytes_to_hex(&bytes);
        if !seen_patterns.insert(hex.clone()) {
            continue;
        }
        let mut hit_reports = Vec::new();
        let find = if opts.max_mem_hits > 0 {
            let params = vec![
                ("bytes_hex", hex.clone()),
                ("max", opts.max_mem_hits.to_string()),
            ];
            route_get_json_value(
                trace_dir.clone(),
                route_path("/api/find-mem-pattern", &params),
            )
            .await?
        } else {
            serde_json::json!({
                "status": "skipped",
                "pattern": hex,
                "count": 0,
                "returned": 0,
                "truncated": false,
                "hits": [],
            })
        };

        if opts.writes_per_hit > 0 {
            if let Some(hits) = find.get("hits").and_then(|v| v.as_array()) {
                for hit in hits {
                    let Some(addr) = hit
                        .get("addr")
                        .and_then(|v| v.as_str())
                        .and_then(parse_u64_str)
                    else {
                        continue;
                    };
                    let addr_hi = addr.saturating_add(bytes.len() as u64);
                    let provenance_params = vec![
                        ("addr", format!("{addr:#x}")),
                        ("length", bytes.len().to_string()),
                    ];
                    let provenance = route_get_json_value(
                        trace_dir.clone(),
                        route_path("/api/string-provenance", &provenance_params),
                    )
                    .await?;
                    let top_writers = provenance_writer_counts(&provenance, opts.writes_per_hit);
                    let mut writer_details = Vec::new();
                    for writer in &top_writers {
                        let Some(idx) = writer.get("idx").and_then(|v| v.as_u64()) else {
                            continue;
                        };
                        let params = vec![
                            ("idx_lo", idx.to_string()),
                            ("idx_hi", (idx + 1).to_string()),
                            ("addr_lo", format!("{addr:#x}")),
                            ("addr_hi", format!("{addr_hi:#x}")),
                            ("max", "20".to_string()),
                        ];
                        let writes = route_get_json_value(
                            trace_dir.clone(),
                            route_path("/api/mem-writes-in-range", &params),
                        )
                        .await?;
                        let writer_seeds = writer_taint_seeds(&writes);
                        for seed in &writer_seeds {
                            push_taint_seed(
                                &mut taint_seed_seen,
                                &mut taint_seed_queue,
                                seed.clone(),
                            );
                        }
                        writer_details.push(serde_json::json!({
                            "writer": writer,
                            "writes": writes,
                            "writer_seeds": writer_seeds,
                        }));
                    }
                    hit_reports.push(serde_json::json!({
                        "hit": hit,
                        "range": {
                            "addr_lo": format!("{addr:#x}"),
                            "addr_hi": format!("{addr_hi:#x}"),
                            "length": bytes.len(),
                        },
                        "provenance": provenance,
                        "top_provenance_writers": top_writers,
                        "writer_details": writer_details,
                    }));
                }
            }
        }

        pattern_reports.push(serde_json::json!({
            "kind": kind,
            "length": bytes.len(),
            "bytes_hex": hex,
            "text_preview": utf8_preview(&bytes, 160),
            "find_mem_pattern": find,
            "hit_reports": hit_reports,
        }));
    }

    let taint_reports = if opts.skip_taint {
        serde_json::json!({
            "skipped": true,
            "reason": "--skip-taint was set",
            "queued": taint_seed_queue,
        })
    } else {
        run_backward_taint_summaries(
            trace_dir,
            &taint_seed_queue,
            opts.taint_seeds,
            opts.taint_max_count,
        )
        .await?
    };

    print_pretty(&serde_json::json!({
        "status": "ready",
        "strategy": "output_to_input_backward_trace",
        "source": source.json,
        "patterns": pattern_reports,
        "taint": taint_reports,
        "notes": [
            "This report intentionally starts at the observed output and walks upward through memory writers and register taint.",
            "For JNI NewStringUTF outputs, the hooked bytes are treated as ground truth; memory dumps can show object/runtime layout noise.",
            "Continue with patterns[].hit_reports[].writer_seeds or taint.runs[].summary.function_counts to choose the next function to decompile."
        ],
    }))
}

async fn resolve_output_source(
    trace_dir: PathBuf,
    opts: &OutputBacktraceOpts,
) -> anyhow::Result<OutputSource> {
    let source_count = opts.key.is_some() as usize
        + opts.value.is_some() as usize
        + opts.bytes_hex.is_some() as usize;
    if source_count != 1 {
        bail!("choose exactly one of --key, --value, or --bytes-hex");
    }

    if let Some(raw) = opts.bytes_hex.as_deref() {
        let bytes = parse_hex_bytes_cli(raw)?;
        return Ok(OutputSource {
            json: serde_json::json!({
                "kind": "bytes_hex",
                "bytes_hex": bytes_to_hex(&bytes),
                "length": bytes.len(),
            }),
            primary_bytes: bytes,
            text: None,
            value_idx: None,
        });
    }

    if let Some(value) = opts.value.as_deref() {
        return Ok(OutputSource {
            json: serde_json::json!({
                "kind": "value",
                "value": value,
                "value_len": value.len(),
            }),
            primary_bytes: value.as_bytes().to_vec(),
            text: Some(value.to_string()),
            value_idx: None,
        });
    }

    let key = opts.key.as_deref().unwrap_or_default();
    let pairs =
        jni_output_string_pairs(trace_dir, Some(key.to_string()), None, opts.jni_limit).await?;
    let pair = pairs
        .get("pairs")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .cloned()
        .with_context(|| format!("no NewStringUTF key/value pair matched key {key:?}"))?;
    let value = pair
        .get("value")
        .and_then(|v| v.as_str())
        .context("matched pair missing value")?;
    let value_idx = pair
        .get("value_idx")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    Ok(OutputSource {
        json: serde_json::json!({
            "kind": "jni_output_string_pair",
            "key": key,
            "pair": pair,
            "source_events": pairs.get("source_events").cloned().unwrap_or(serde_json::Value::Null),
            "source_truncated": pairs.get("source_truncated").cloned().unwrap_or(serde_json::Value::Null),
        }),
        primary_bytes: value.as_bytes().to_vec(),
        text: Some(value.to_string()),
        value_idx,
    })
}

fn writer_taint_seeds(writes: &serde_json::Value) -> Vec<serde_json::Value> {
    writes
        .get("writes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|write| {
            let idx = write.get("idx").and_then(|v| v.as_u64())? as usize;
            let reg = write.get("src_reg").and_then(|v| v.as_str())?;
            Some(serde_json::json!({
                "kind": "memory_writer_src_reg",
                "start": idx,
                "reg": reg,
                "writer": write,
            }))
        })
        .collect()
}

fn provenance_writer_counts(
    provenance: &serde_json::Value,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    if let Some(bytes) = provenance.get("bytes").and_then(|v| v.as_array()) {
        for byte in bytes {
            if let Some(idx) = byte.get("current_writer_idx").and_then(|v| v.as_u64()) {
                *counts.entry(idx as usize).or_default() += 1;
            }
        }
    }
    if counts.is_empty() {
        if let Some(bytes) = provenance.get("bytes").and_then(|v| v.as_array()) {
            for byte in bytes {
                if let Some(writers) = byte.get("writers").and_then(|v| v.as_array()) {
                    for writer in writers {
                        if let Some(idx) = writer.as_u64() {
                            *counts.entry(idx as usize).or_default() += 1;
                        }
                    }
                }
            }
        }
    }
    let mut rows: Vec<_> = counts
        .into_iter()
        .map(|(idx, byte_count)| serde_json::json!({ "idx": idx, "byte_count": byte_count }))
        .collect();
    rows.sort_by(|a, b| {
        let ac = a.get("byte_count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bc = b.get("byte_count").and_then(|v| v.as_u64()).unwrap_or(0);
        bc.cmp(&ac).then_with(|| {
            a.get("idx")
                .and_then(|v| v.as_u64())
                .cmp(&b.get("idx").and_then(|v| v.as_u64()))
        })
    });
    rows.into_iter().take(limit).collect()
}

fn push_taint_seed(
    seen: &mut HashSet<String>,
    queue: &mut Vec<serde_json::Value>,
    seed: serde_json::Value,
) {
    let Some(start) = seed.get("start").and_then(|v| v.as_u64()) else {
        return;
    };
    let Some(reg) = seed.get("reg").and_then(|v| v.as_str()) else {
        return;
    };
    if seen.insert(format!("{start}:{reg}")) {
        queue.push(seed);
    }
}

async fn run_backward_taint_summaries(
    trace_dir: PathBuf,
    seeds: &[serde_json::Value],
    max_seeds: usize,
    max_count: usize,
) -> anyhow::Result<serde_json::Value> {
    let mut runs = Vec::new();
    for seed in seeds.iter().take(max_seeds) {
        let Some(start) = seed.get("start").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(reg) = seed.get("reg").and_then(|v| v.as_str()) else {
            continue;
        };
        let params = vec![
            ("start", start.to_string()),
            ("reg", reg.to_string()),
            ("through_mem", "true".to_string()),
            ("data_only", "false".to_string()),
            ("cross_fn_call", "true".to_string()),
            ("max_count", max_count.to_string()),
        ];
        let response = route_get_json_value(
            trace_dir.clone(),
            route_path("/api/backward-taint", &params),
        )
        .await?;
        runs.push(serde_json::json!({
            "seed": seed,
            "summary": summarize_backward_taint(&response),
        }));
    }
    Ok(serde_json::json!({
        "skipped": false,
        "queued": seeds.len(),
        "returned": runs.len(),
        "truncated_seed_list": seeds.len() > runs.len(),
        "runs": runs,
    }))
}

fn summarize_backward_taint(response: &serde_json::Value) -> serde_json::Value {
    let rows = response
        .get("chain")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for row in &rows {
        let func = row
            .get("func")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        *counts.entry(func.to_string()).or_default() += 1;
    }
    let mut function_counts: Vec<_> = counts
        .into_iter()
        .map(|(func, count)| serde_json::json!({ "func": func, "count": count }))
        .collect();
    function_counts.sort_by(|a, b| {
        let ac = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let bc = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        bc.cmp(&ac).then_with(|| {
            a.get("func")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("func").and_then(|v| v.as_str()).unwrap_or(""))
        })
    });

    let sample_chain: Vec<_> = rows
        .iter()
        .take(40)
        .map(|row| {
            serde_json::json!({
                "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "pc": row.get("pc").cloned().unwrap_or(serde_json::Value::Null),
                "func": row.get("func").cloned().unwrap_or(serde_json::Value::Null),
                "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "via": row.get("via").cloned().unwrap_or(serde_json::Value::Null),
                "taint_depth": row.get("taint_depth").cloned().unwrap_or(serde_json::Value::Null),
                "parent_idxs": row.get("parent_idxs").cloned().unwrap_or(serde_json::json!([])),
            })
        })
        .collect();

    serde_json::json!({
        "status": response.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "from": response.get("from").cloned().unwrap_or(serde_json::Value::Null),
        "reg": response.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "count": response.get("count").cloned().unwrap_or(serde_json::Value::Null),
        "stopped_at_max": response.get("stopped_at_max").cloned().unwrap_or(serde_json::Value::Null),
        "max_count_used": response.get("max_count_used").cloned().unwrap_or(serde_json::Value::Null),
        "function_counts": function_counts.into_iter().take(30).collect::<Vec<_>>(),
        "sample_chain": sample_chain,
    })
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

fn normalize_api_path(path: &str) -> anyhow::Result<String> {
    let path = path.trim();
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if path.starts_with("/api/") || path == "/openapi.json" {
        Ok(path)
    } else {
        bail!("api path must start with /api/ or be /openapi.json: {path}")
    }
}

fn parse_key_values(raw: Vec<String>) -> anyhow::Result<Vec<(&'static str, String)>> {
    let mut out = Vec::new();
    for item in raw {
        let Some((k, v)) = item.split_once('=') else {
            bail!("--param must be key=value, got {item:?}");
        };
        let key = k.trim();
        if key.is_empty() {
            bail!("--param key must not be empty");
        }
        let key: &'static str = Box::leak(key.to_string().into_boxed_str());
        out.push((key, v.to_string()));
    }
    Ok(out)
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_csv_allow_empty(s: &str) -> Vec<String> {
    if s.is_empty() {
        return vec![String::new()];
    }
    split_csv(s)
}

fn cmd_list(path: Option<PathBuf>, dir: PathBuf, json: bool) -> anyhow::Result<()> {
    let target = path.unwrap_or(dir);
    if !target.exists() {
        bail!("path does not exist: {}", target.display());
    }
    let rows = if target.join("calls").is_dir() {
        list_calls(&target)?
    } else {
        list_runs(&target)?
    };
    if json {
        print_pretty(&serde_json::Value::Array(rows))
    } else {
        for row in rows {
            println!(
                "{}",
                serde_json::to_string(&row).context("serialize list row")?
            );
        }
        Ok(())
    }
}

fn list_runs(base: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut rows = Vec::new();
    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let top = read_json_opt(&p.join("meta.json"));
        let calls_dir = p.join("calls");
        if calls_dir.is_dir() {
            let calls = list_calls(&p)?;
            let records = calls
                .iter()
                .filter_map(|c| c.get("records").and_then(|v| v.as_u64()))
                .sum::<u64>();
            let max_records = calls
                .iter()
                .filter_map(|c| c.get("records").and_then(|v| v.as_u64()))
                .max()
                .unwrap_or(0);
            rows.push(serde_json::json!({
                "name": entry.file_name().to_string_lossy(),
                "method": top.get("method").cloned().unwrap_or(serde_json::Value::Null),
                "cmd": top.get("cmd").cloned().unwrap_or(serde_json::Value::Null),
                "calls": calls.len(),
                "records": records,
                "max_records": max_records,
                "kind": "per-call",
            }));
        }
    }
    rows.sort_by_key(|r| {
        r.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    });
    Ok(rows)
}

fn list_calls(run_dir: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
    let calls_dir = run_dir.join("calls");
    let mut rows = Vec::new();
    if !calls_dir.is_dir() {
        return Ok(rows);
    }
    for entry in std::fs::read_dir(calls_dir)? {
        let entry = entry?;
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        let meta_path = p.join("meta.json");
        if !meta_path.exists() {
            continue;
        }
        let mut row = read_json_opt(&meta_path);
        row["dir"] = serde_json::Value::String(entry.file_name().to_string_lossy().to_string());
        rows.push(row);
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.get("records").and_then(|v| v.as_u64()).unwrap_or(0)));
    Ok(rows)
}

fn cmd_info(path: PathBuf, json: bool) -> anyhow::Result<()> {
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    let out = if path.join("trace.bin").is_file() {
        info_call(&path)?
    } else if path.join("calls").is_dir() {
        let top = read_json_opt(&path.join("meta.json"));
        let calls = list_calls(&path)?;
        serde_json::json!({
            "path": path.display().to_string(),
            "pkg": top.get("pkg").cloned().unwrap_or(serde_json::Value::Null),
            "so": top.get("so").cloned().unwrap_or(serde_json::Value::Null),
            "method": top.get("method").cloned().unwrap_or(serde_json::Value::Null),
            "cmd": top.get("cmd").cloned().unwrap_or(serde_json::Value::Null),
            "fn_offset": top.get("fn_offset").cloned().unwrap_or(serde_json::Value::Null),
            "fn_addr": top.get("fn_addr").cloned().unwrap_or(serde_json::Value::Null),
            "module": top.get("module").cloned().unwrap_or(serde_json::Value::Null),
            "calls_count": calls.len(),
            "total_records": calls.iter().filter_map(|c| c.get("records").and_then(|v| v.as_u64())).sum::<u64>(),
            "max_records": calls.iter().filter_map(|c| c.get("records").and_then(|v| v.as_u64())).max().unwrap_or(0),
            "calls": calls,
        })
    } else {
        bail!("unsupported info path: {}", path.display());
    };
    if json {
        print_pretty(&out)
    } else {
        println!("{}", serde_json::to_string_pretty(&out)?);
        Ok(())
    }
}

fn info_call(path: &Path) -> anyhow::Result<serde_json::Value> {
    let meta = read_json_opt(&path.join("meta.json"));
    let trace = tracemiku_core::prelude::Trace::load(path)?;
    let n = trace.len();
    let mut first_pc = None;
    let mut last_pc = None;
    let mut last_asm = None;
    let mut last_insn_is_ret = None;
    if n > 0 {
        let first = trace.record(0);
        let last = trace.record(n - 1);
        let d = tracemiku_core::prelude::decode(last.pc, last.inst);
        first_pc = Some(format!("{:#x}", first.pc));
        last_pc = Some(format!("{:#x}", last.pc));
        last_asm = Some(format!("{} {}", d.mnemonic, d.op_str).trim().to_string());
        last_insn_is_ret = Some(d.is_ret);
    }
    let truncated = meta
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let complete = !truncated && last_insn_is_ret.unwrap_or(false);
    let ms = meta.get("ms").and_then(|v| v.as_f64());
    let rec_per_sec = ms
        .filter(|ms| *ms > 0.0)
        .map(|ms| (n as f64 / (ms / 1000.0)) as u64);
    Ok(serde_json::json!({
        "path": path.display().to_string(),
        "callIdx": meta.get("callIdx").cloned().unwrap_or(serde_json::Value::Null),
        "tid": meta.get("tid").cloned().unwrap_or(serde_json::Value::Null),
        "records": n,
        "ms": meta.get("ms").cloned().unwrap_or(serde_json::Value::Null),
        "retval": meta.get("retval").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": truncated,
        "last_insn_is_ret": last_insn_is_ret,
        "first_pc": first_pc,
        "last_pc": last_pc,
        "last_asm": last_asm,
        "is_complete": complete,
        "rec_per_sec": rec_per_sec,
    }))
}

fn read_json_opt(path: &Path) -> serde_json::Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}

fn taint_params(
    start: usize,
    reg: String,
    max_count: Option<usize>,
    through_mem: bool,
    data_only: bool,
    cross_fn_call: bool,
) -> Vec<(&'static str, String)> {
    let mut params = vec![
        ("start", start.to_string()),
        ("reg", reg),
        ("through_mem", through_mem.to_string()),
        ("data_only", data_only.to_string()),
        ("cross_fn_call", cross_fn_call.to_string()),
    ];
    if let Some(max) = max_count {
        params.push(("max_count", max.to_string()));
    }
    params
}

fn route_path(base: &str, params: &[(&str, String)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let qs = params
        .iter()
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{qs}")
}

fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex_bytes_cli(raw: &str) -> anyhow::Result<Vec<u8>> {
    let mut s = raw.trim().to_string();
    if s.starts_with("0x") || s.starts_with("0X") {
        s = s[2..].to_string();
    }
    s.retain(|ch| !ch.is_ascii_whitespace() && ch != '_' && ch != ':');
    if s.is_empty() {
        bail!("empty hex byte string");
    }
    if s.len() % 2 != 0 {
        bail!("hex byte string must contain an even number of nybbles");
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(
            u8::from_str_radix(&s[i..i + 2], 16)
                .with_context(|| format!("invalid hex byte {:?}", &s[i..i + 2]))?,
        );
    }
    Ok(out)
}

fn parse_u64_str(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

fn percent_decode_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(hi), Some(lo)) = (hex_nybble(input[i + 1]), hex_nybble(input[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

fn hex_nybble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn utf8_preview(bytes: &[u8], max: usize) -> String {
    let take = bytes.len().min(max);
    let mut s = String::from_utf8_lossy(&bytes[..take]).into_owned();
    if bytes.len() > take {
        s.push_str("...");
    }
    s
}

fn print_pretty(value: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
