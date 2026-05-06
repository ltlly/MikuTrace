use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use axum::body::Body;
use base64::alphabet::STANDARD as BASE64_STANDARD_ALPHABET;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::Engine;
use clap::{Parser, Subcommand, ValueEnum};
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
    /// Resolve an address against a saved /proc/<pid>/maps file.
    ResolveMapAddr { maps_file: PathBuf, addr: String },
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
    /// Recursively scan jni_hooks.jsonl files for NewStringUTF key/value pairs.
    ScanJniOutputStrings {
        /// Trace root, run dir, or call dir. Defaults to ./traces.
        #[arg(default_value = "traces")]
        path: PathBuf,
        /// Keep only pairs with this key, for example x-sign.
        #[arg(long)]
        key: Option<String>,
        /// Keep pairs whose key or value contains this text.
        #[arg(long)]
        contains: Option<String>,
        /// Stop after this many returned pairs. 0 means no cap.
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// Include percent-decoded value fields when the value is URL-encoded.
        #[arg(long)]
        decode_url: bool,
        /// Include best-effort base64 decoded length and prefix/suffix hex.
        #[arg(long)]
        decode_base64: bool,
        /// Include full base64 decoded hex. Useful for small signature payload diffing.
        #[arg(long)]
        decode_base64_full: bool,
        /// Include byte-level diff across decoded Base64 outputs.
        #[arg(long)]
        diff_base64: bool,
        /// Include this many recent GetStringUTFChars strings before each output.
        #[arg(long, default_value_t = 0)]
        prior_inputs: usize,
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
        /// Attach VM backchains for this many steps per selected writer run. 0 disables.
        #[arg(long, default_value_t = 0)]
        vm_chain_steps: usize,
        /// Max writer runs per memory hit to expand with VM backchains.
        #[arg(long, default_value_t = 6)]
        vm_chain_runs: usize,
        /// Lookback window for each VM backchain step.
        #[arg(long, default_value_t = 200000)]
        vm_chain_lookback: usize,
        /// Let attached VM chains continue through frontier source regs when a table/ALU step has no upstream writer.
        #[arg(long)]
        vm_chain_follow_frontier: bool,
        /// Skip backward-taint expansion and only report output/memory writers.
        #[arg(long)]
        skip_taint: bool,
        /// Do not add a percent-decoded pattern for URL-encoded strings.
        #[arg(long = "no-url-decode")]
        no_url_decode: bool,
        /// Do not add a best-effort Base64-decoded byte pattern for textual outputs.
        #[arg(long = "no-base64-decode")]
        no_base64_decode: bool,
    },
    /// Compact map from textual output/Base64 groups to writer runs.
    OutputMap {
        trace_dir: PathBuf,
        /// Start from a JNI NewStringUTF key/value pair, for example x-sign.
        #[arg(long)]
        key: Option<String>,
        /// Start from an observed UTF-8 output string directly.
        #[arg(long)]
        value: Option<String>,
        /// Max NewStringUTF events to scan when --key is used.
        #[arg(long, default_value_t = 2000)]
        jni_limit: usize,
        /// Max memory locations to consider for the observed output bytes.
        #[arg(long, default_value_t = 8)]
        max_mem_hits: usize,
        /// Ranked memory hit to use after --hit-order sorting.
        #[arg(long, default_value_t = 0)]
        hit_rank: usize,
        /// Memory-hit ordering before applying --hit-rank.
        ///
        /// earliest is best for reversing generation; nearest follows the final JNI handoff.
        #[arg(long, value_enum, default_value_t = HitOrder::Earliest)]
        hit_order: HitOrder,
        /// First Base64 group offset to return.
        #[arg(long, default_value_t = 0)]
        group_start: usize,
        /// Number of Base64 groups to return. 0 means all groups.
        #[arg(long, default_value_t = 0)]
        groups: usize,
        /// Attach VM backtrees for this depth per group. 0 disables.
        #[arg(long, default_value_t = 0)]
        tree_depth: usize,
        /// Max nodes per attached VM backtree.
        #[arg(long, default_value_t = 120)]
        tree_max_nodes: usize,
        /// Attach VM backtrees to matched Base64 alphabet index registers. 0 disables.
        #[arg(long, default_value_t = 0)]
        index_tree_depth: usize,
        /// Max nodes per attached Base64 index VM backtree.
        #[arg(long, default_value_t = 80)]
        index_tree_max_nodes: usize,
        /// Include frontier source-reg branches even when a tree node has an upstream memory edge.
        #[arg(long = "tree-frontier-with-next")]
        tree_frontier_with_next: bool,
        /// Lookback window for each VM backtree step.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Do not percent-decode the textual output before Base64 grouping.
        #[arg(long = "no-url-decode")]
        no_url_decode: bool,
    },
    /// Compact dynamic VM-oriented record slice.
    VmSlice {
        trace_dir: PathBuf,
        /// First trace index to include.
        #[arg(long)]
        start: usize,
        /// End trace index, exclusive. Overrides --count.
        #[arg(long)]
        end: Option<usize>,
        /// Number of records when --end is not set.
        #[arg(long, default_value_t = 300)]
        count: usize,
        /// Comma-separated registers to request from /api/records.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28"
        )]
        regs: String,
        /// Drop records that do not look VM-related.
        #[arg(long)]
        only_vm: bool,
        /// Base VM IP for vm_off. Defaults to the first row's x21.
        #[arg(long)]
        base_ip: Option<String>,
    },
    /// Group dynamic VM-oriented records into compact virtual instruction slices.
    VmOps {
        trace_dir: PathBuf,
        /// First trace index to include.
        #[arg(long)]
        start: usize,
        /// End trace index, exclusive. Overrides --count.
        #[arg(long)]
        end: Option<usize>,
        /// Number of records when --end is not set.
        #[arg(long, default_value_t = 300)]
        count: usize,
        /// Comma-separated registers to request from /api/records.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28"
        )]
        regs: String,
        /// Base VM IP for vm_off. Defaults to the first row's x21.
        #[arg(long)]
        base_ip: Option<String>,
        /// Max VM op groups to return.
        #[arg(long, default_value_t = 80)]
        max_ops: usize,
    },
    /// Follow a single byte backward through memory writes and VM source registers.
    ByteLineage {
        trace_dir: PathBuf,
        /// Memory byte address to start from.
        #[arg(long)]
        addr: String,
        /// Find the last write strictly before this trace index.
        #[arg(long)]
        before_idx: usize,
        /// Max lineage steps.
        #[arg(long, default_value_t = 12)]
        depth: usize,
        /// Local records to inspect before each writer idx.
        #[arg(long, default_value_t = 120)]
        context: usize,
        /// How far back to scan memory writers for each discovered source.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Max memory writes to collect while looking for the last one.
        #[arg(long, default_value_t = 5000)]
        max_writes: usize,
        /// Comma-separated registers to request from /api/records.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28"
        )]
        regs: String,
        /// Emit a compact AI-readable summary instead of the full step payload.
        #[arg(long)]
        summary: bool,
    },
    /// One backward step through a dynamic VM store/load chain.
    VmBackstep {
        trace_dir: PathBuf,
        /// Writer/load trace index to explain.
        #[arg(long)]
        idx: usize,
        /// Source register to chase. Defaults to the first store source reg.
        #[arg(long)]
        reg: Option<String>,
        /// Local records to inspect before idx.
        #[arg(long, default_value_t = 120)]
        context: usize,
        /// How far back to scan memory writers for the discovered source.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Max memory writes to collect while looking for the last one.
        #[arg(long, default_value_t = 5000)]
        max_writes: usize,
        /// Comma-separated registers to request from /api/records.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28"
        )]
        regs: String,
    },
    /// Iterate vm-backstep and emit a compact backward chain.
    VmBackchain {
        trace_dir: PathBuf,
        /// Initial writer/load trace index.
        #[arg(long)]
        idx: usize,
        /// Initial source register. Defaults to the first store source reg.
        #[arg(long)]
        reg: Option<String>,
        /// Max backward steps.
        #[arg(long, default_value_t = 8)]
        steps: usize,
        /// Local records to inspect before each idx.
        #[arg(long, default_value_t = 120)]
        context: usize,
        /// How far back to scan memory writers for each discovered source.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Max memory writes to collect while looking for the last one.
        #[arg(long, default_value_t = 5000)]
        max_writes: usize,
        /// Continue through a chosen frontier source reg when upstream.next is unavailable.
        #[arg(long)]
        follow_frontier: bool,
        /// Emit a compact AI-readable summary instead of the full step payload.
        #[arg(long)]
        summary: bool,
        /// Comma-separated registers to request from /api/records.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28"
        )]
        regs: String,
    },
    /// Branching backward tree through dynamic VM upstream/frontier links.
    VmBacktree {
        trace_dir: PathBuf,
        /// Initial writer/load trace index.
        #[arg(long)]
        idx: usize,
        /// Initial source register. Defaults to the first store source reg.
        #[arg(long)]
        reg: Option<String>,
        /// Max tree depth.
        #[arg(long, default_value_t = 6)]
        depth: usize,
        /// Max returned tree nodes.
        #[arg(long, default_value_t = 64)]
        max_nodes: usize,
        /// Local records to inspect before each idx.
        #[arg(long, default_value_t = 120)]
        context: usize,
        /// How far back to scan memory writers for each discovered source.
        #[arg(long, default_value_t = 200000)]
        lookback: usize,
        /// Max memory writes to collect while looking for the last one.
        #[arg(long, default_value_t = 5000)]
        max_writes: usize,
        /// Also enqueue frontier branches when upstream.next exists.
        #[arg(long)]
        frontier_with_next: bool,
        /// Emit a compact AI-readable summary instead of the full node tree.
        #[arg(long)]
        summary: bool,
        /// Comma-separated registers to request from /api/records.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28"
        )]
        regs: String,
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
        Some(Cmd::ResolveMapAddr { maps_file, addr }) => cmd_resolve_map_addr(maps_file, addr),
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
        Some(Cmd::ScanJniOutputStrings {
            path,
            key,
            contains,
            limit,
            decode_url,
            decode_base64,
            decode_base64_full,
            diff_base64,
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
            skip_taint,
            no_url_decode,
            no_base64_decode,
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
                vm_chain_steps,
                vm_chain_runs,
                vm_chain_lookback,
                vm_chain_follow_frontier,
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
            tree_depth,
            tree_max_nodes,
            index_tree_depth,
            index_tree_max_nodes,
            tree_frontier_with_next,
            lookback,
            no_url_decode,
        }) => {
            let opts = OutputMapOpts {
                key,
                value,
                jni_limit,
                max_mem_hits,
                hit_rank,
                hit_order,
                group_start,
                groups,
                tree_depth,
                tree_max_nodes,
                index_tree_depth,
                index_tree_max_nodes,
                tree_frontier_with_next,
                lookback,
                url_decode: !no_url_decode,
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
            base_ip,
        }) => cmd_vm_slice(trace_dir, start, end, count, regs, only_vm, base_ip).await,
        Some(Cmd::VmOps {
            trace_dir,
            start,
            end,
            count,
            regs,
            base_ip,
            max_ops,
        }) => cmd_vm_ops(trace_dir, start, end, count, regs, base_ip, max_ops).await,
        Some(Cmd::ByteLineage {
            trace_dir,
            addr,
            before_idx,
            depth,
            context,
            lookback,
            max_writes,
            regs,
            summary,
        }) => {
            cmd_byte_lineage(
                trace_dir, addr, before_idx, depth, context, lookback, max_writes, regs, summary,
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
        }) => cmd_vm_backstep(trace_dir, idx, reg, context, lookback, max_writes, regs).await,
        Some(Cmd::VmBackchain {
            trace_dir,
            idx,
            reg,
            steps,
            context,
            lookback,
            max_writes,
            follow_frontier,
            summary,
            regs,
        }) => {
            cmd_vm_backchain(
                trace_dir,
                idx,
                reg,
                steps,
                context,
                lookback,
                max_writes,
                follow_frontier,
                regs,
                summary,
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
        }) => {
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
    route_get_json_value_on(&app, path).await
}

async fn route_get_json_value_on(
    app: &axum::Router,
    path: String,
) -> anyhow::Result<serde_json::Value> {
    let resp = app
        .clone()
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
    let path = route_path("/api/jni-events", &params);
    let app = build_cli_router(trace_dir, &path, None)?;
    jni_output_string_pairs_on(&app, key, contains, limit).await
}

async fn jni_output_string_pairs_on(
    app: &axum::Router,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
) -> anyhow::Result<serde_json::Value> {
    let params = vec![
        ("limit", limit.to_string()),
        ("id", "NewStringUTF".to_string()),
    ];
    let value = route_get_json_value_on(app, route_path("/api/jni-events", &params)).await?;
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

fn cmd_scan_jni_output_strings(
    path: PathBuf,
    key: Option<String>,
    contains: Option<String>,
    limit: usize,
    decode_url: bool,
    decode_base64: bool,
    decode_base64_full: bool,
    diff_base64: bool,
    prior_inputs: usize,
) -> anyhow::Result<()> {
    let hook_files = find_jni_hook_files(&path)?;
    let mut pairs = Vec::new();
    let mut scanned_events = 0usize;
    for file in &hook_files {
        let all_events = read_jni_string_events(file)?;
        scanned_events += all_events.len();
        let events = all_events
            .iter()
            .filter(|event| event.get("id").and_then(|v| v.as_str()) == Some("NewStringUTF"))
            .cloned()
            .collect::<Vec<_>>();
        let mut iter = events.chunks_exact(2);
        for pair in &mut iter {
            let key_text = pair[0].get("text").and_then(|v| v.as_str()).unwrap_or("");
            let value_text = pair[1].get("text").and_then(|v| v.as_str()).unwrap_or("");
            if key.as_deref().is_some_and(|needle| key_text != needle) {
                continue;
            }
            if contains
                .as_deref()
                .is_some_and(|needle| !key_text.contains(needle) && !value_text.contains(needle))
            {
                continue;
            }
            let mut row = serde_json::json!({
                "call_dir": file.parent().map(|p| p.display().to_string()).unwrap_or_default(),
                "hook_file": file.display().to_string(),
                "key_idx": pair[0].get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "key_ret": pair[0].get("ret").cloned().unwrap_or(serde_json::Value::Null),
                "key": key_text,
                "value_idx": pair[1].get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "value_ret": pair[1].get("ret").cloned().unwrap_or(serde_json::Value::Null),
                "value": value_text,
                "value_len": value_text.len(),
            });
            if decode_url {
                let decoded = percent_decode_bytes(value_text.as_bytes());
                if decoded != value_text.as_bytes() {
                    row["url_decoded"] =
                        serde_json::Value::String(String::from_utf8_lossy(&decoded).into_owned());
                    row["url_decoded_len"] = serde_json::json!(decoded.len());
                }
            }
            if decode_base64 || diff_base64 {
                let base64_text = row
                    .get("url_decoded")
                    .and_then(|v| v.as_str())
                    .unwrap_or(value_text);
                row["base64"] = base64_summary(base64_text, decode_base64_full || diff_base64);
            }
            if prior_inputs > 0 {
                let value_idx = pair[1].get("idx").and_then(|v| v.as_u64());
                row["prior_inputs"] = serde_json::Value::Array(prior_get_string_inputs(
                    &all_events,
                    value_idx,
                    prior_inputs,
                ));
            }
            pairs.push(row);
            if limit != 0 && pairs.len() >= limit {
                break;
            }
        }
        if limit != 0 && pairs.len() >= limit {
            break;
        }
    }
    let base64_diff = diff_base64.then(|| decoded_base64_diff(&pairs));
    let mut out = serde_json::json!({
        "status": "ready",
        "path": path.display().to_string(),
        "hook_files": hook_files.len(),
        "source_events": scanned_events,
        "count": pairs.len(),
        "truncated": limit != 0 && pairs.len() >= limit,
        "pairs": pairs,
    });
    if let Some(diff) = base64_diff {
        out["base64_diff"] = diff;
    }
    print_pretty(&out)
}

fn find_jni_hook_files(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if path.is_file() {
        if path.file_name().and_then(|v| v.to_str()) == Some("jni_hooks.jsonl") {
            out.push(path.to_path_buf());
        }
        return Ok(out);
    }
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    collect_jni_hook_files(path, &mut out)?;
    out.sort();
    Ok(out)
}

fn collect_jni_hook_files(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_jni_hook_files(&path, out)?;
        } else if path.file_name().and_then(|v| v.to_str()) == Some("jni_hooks.jsonl") {
            out.push(path);
        }
    }
    Ok(())
}

fn read_jni_string_events(path: &Path) -> anyhow::Result<Vec<serde_json::Value>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut events = Vec::new();
    for line in raw.lines() {
        if !line.contains("StringUTF") {
            continue;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(id) = event.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let text = match id {
            "NewStringUTF" => event
                .get("args")
                .and_then(|v| v.get("bytes"))
                .and_then(|v| v.as_str()),
            "GetStringUTFChars" => event.get("ret").and_then(|v| v.as_str()),
            _ => None,
        };
        let Some(text) = text else {
            continue;
        };
        events.push(serde_json::json!({
            "id": id,
            "idx": event.get("trace_idx").cloned().unwrap_or(serde_json::Value::Null),
            "ret": event.get("ret").cloned().unwrap_or(serde_json::Value::Null),
            "text": text,
            "text_len": text.len(),
        }));
    }
    Ok(events)
}

fn prior_get_string_inputs(
    events: &[serde_json::Value],
    before_idx: Option<u64>,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for event in events.iter().rev() {
        if event.get("id").and_then(|v| v.as_str()) != Some("GetStringUTFChars") {
            continue;
        }
        let idx = event.get("idx").and_then(|v| v.as_u64());
        if let (Some(idx), Some(before_idx)) = (idx, before_idx) {
            if idx >= before_idx {
                continue;
            }
        }
        let Some(text) = event.get("text").and_then(|v| v.as_str()) else {
            continue;
        };
        if !seen.insert(text.to_string()) {
            continue;
        }
        out.push(serde_json::json!({
            "idx": event.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "text": text,
            "text_len": text.len(),
        }));
        if out.len() >= limit {
            break;
        }
    }
    out.reverse();
    out
}

fn base64_summary(raw: &str, include_full_hex: bool) -> serde_json::Value {
    match base64_decoded_bytes(raw) {
        Ok(bytes) => {
            let mut summary = serde_json::json!({
                "ok": true,
                "decoded_len": bytes.len(),
                "prefix_hex": bytes_to_hex(&bytes[..bytes.len().min(16)]),
                "suffix_hex": bytes_to_hex(&bytes[bytes.len().saturating_sub(16)..]),
            });
            if include_full_hex {
                summary["decoded_hex"] = serde_json::Value::String(bytes_to_hex(&bytes));
            }
            summary
        }
        Err(err) => serde_json::json!({
            "ok": false,
            "error": err.to_string(),
        }),
    }
}

fn decoded_base64_diff(pairs: &[serde_json::Value]) -> serde_json::Value {
    let samples = pairs
        .iter()
        .enumerate()
        .filter_map(|(sample, pair)| {
            let decoded_hex = pair
                .get("base64")
                .and_then(|v| v.get("decoded_hex"))
                .and_then(|v| v.as_str())?;
            let bytes = parse_hex_bytes_cli(decoded_hex).ok()?;
            Some((sample, pair, bytes))
        })
        .collect::<Vec<_>>();
    if samples.is_empty() {
        return serde_json::json!({
            "status": "no-decoded-samples",
            "sample_count": 0,
        });
    }
    let min_len = samples
        .iter()
        .map(|(_, _, bytes)| bytes.len())
        .min()
        .unwrap_or(0);
    let max_len = samples
        .iter()
        .map(|(_, _, bytes)| bytes.len())
        .max()
        .unwrap_or(0);
    let mut per_byte = Vec::new();
    let mut stable_offsets = Vec::new();
    let mut variable_offsets = Vec::new();
    for off in 0..min_len {
        let mut values = samples
            .iter()
            .map(|(_, _, bytes)| bytes[off])
            .collect::<Vec<_>>();
        values.sort_unstable();
        values.dedup();
        if values.len() == 1 {
            stable_offsets.push(off);
            per_byte.push(serde_json::json!({
                "off": off,
                "kind": "STABLE",
                "value": format!("{:#x}", values[0]),
            }));
        } else {
            variable_offsets.push(off);
            per_byte.push(serde_json::json!({
                "off": off,
                "kind": "VARIABLE",
                "values": values.iter().map(|v| format!("{v:#x}")).collect::<Vec<_>>(),
            }));
        }
    }
    let stable_range_rows = stable_ranges(&stable_offsets)
        .into_iter()
        .map(|(start, end)| {
            let bytes = &samples[0].2[start..end];
            serde_json::json!({
                "start": start,
                "end": end,
                "length": end - start,
                "hex": bytes_to_hex(bytes),
            })
        })
        .collect::<Vec<_>>();
    let variable_ranges = stable_ranges(&variable_offsets)
        .into_iter()
        .map(|(start, end)| {
            let group_start = start / 3;
            let group_end = end.div_ceil(3);
            serde_json::json!({
                "start": start,
                "end": end,
                "length": end - start,
                "base64_group_start": group_start,
                "base64_group_end": group_end,
                "base64_groups": group_end.saturating_sub(group_start),
                "base64_char_start": group_start * 4,
                "base64_char_end": group_end * 4,
            })
        })
        .collect::<Vec<_>>();
    let first_variable = variable_offsets.first().map(|off| {
        let group = off / 3;
        serde_json::json!({
            "off": off,
            "base64_group": group,
            "base64_char_start": group * 4,
            "base64_char_end": (group + 1) * 4,
            "output_map_args": {
                "group_start": group,
                "groups": 1,
            },
        })
    });
    let sample_rows = samples
        .iter()
        .map(|(sample, pair, bytes)| {
            serde_json::json!({
                "sample": sample,
                "call_dir": pair.get("call_dir").cloned().unwrap_or(serde_json::Value::Null),
                "value_idx": pair.get("value_idx").cloned().unwrap_or(serde_json::Value::Null),
                "decoded_len": bytes.len(),
                "decoded_hex": bytes_to_hex(bytes),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": "ready",
        "sample_count": samples.len(),
        "min_len": min_len,
        "max_len": max_len,
        "compared_len": min_len,
        "length_variable": min_len != max_len,
        "range_semantics": "[start,end)",
        "stable_count": stable_offsets.len(),
        "variable_count": min_len.saturating_sub(stable_offsets.len()),
        "stable_ranges": stable_range_rows,
        "variable_ranges": variable_ranges,
        "first_variable": first_variable,
        "per_byte": per_byte,
        "samples": sample_rows,
    })
}

fn stable_ranges(offsets: &[usize]) -> Vec<(usize, usize)> {
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut ranges = Vec::new();
    let mut start = offsets[0];
    let mut prev = offsets[0];
    for &off in offsets.iter().skip(1) {
        if off != prev + 1 {
            ranges.push((start, prev + 1));
            start = off;
        }
        prev = off;
    }
    ranges.push((start, prev + 1));
    ranges
}

fn base64_decoded_bytes(raw: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut padded = trimmed.replace('-', "+").replace('_', "/");
    let rem = padded.len() % 4;
    if rem != 0 {
        padded.push_str(&"=".repeat(4 - rem));
    }
    let engine = GeneralPurpose::new(
        &BASE64_STANDARD_ALPHABET,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    engine.decode(padded.as_bytes())
}

fn base64_group_analysis(raw: &str) -> serde_json::Value {
    let chars = raw.as_bytes();
    let indices = chars
        .iter()
        .enumerate()
        .map(|(pos, &byte)| {
            let index = base64_char_index(byte);
            serde_json::json!({
                "pos": pos,
                "char": char::from(byte).to_string(),
                "index": index,
                "index_hex": index.map(|idx| format!("{idx:#x}")),
            })
        })
        .collect::<Vec<_>>();
    let values = chars
        .iter()
        .filter_map(|&byte| base64_char_index(byte))
        .collect::<Vec<_>>();
    let mut decoded = Vec::new();
    if values.len() >= 2 {
        decoded.push(serde_json::json!({
            "byte": 0,
            "value_hex": format!("{:02x}", (values[0] << 2) | (values[1] >> 4)),
            "formula": "(i0 << 2) | (i1 >> 4)",
            "indices": [0, 1],
        }));
    }
    if values.len() >= 3 && chars.get(2) != Some(&b'=') {
        decoded.push(serde_json::json!({
            "byte": 1,
            "value_hex": format!("{:02x}", ((values[1] & 0x0f) << 4) | (values[2] >> 2)),
            "formula": "((i1 & 0x0f) << 4) | (i2 >> 2)",
            "indices": [1, 2],
        }));
    }
    if values.len() >= 4 && chars.get(3) != Some(&b'=') {
        decoded.push(serde_json::json!({
            "byte": 2,
            "value_hex": format!("{:02x}", ((values[2] & 0x03) << 6) | values[3]),
            "formula": "((i2 & 0x03) << 6) | i3",
            "indices": [2, 3],
        }));
    }
    serde_json::json!({
        "indices": indices,
        "decoded_bytes": decoded,
    })
}

fn base64_lookup_matches(
    base64: &serde_json::Value,
    trees: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let lookups = trees
        .iter()
        .flat_map(|tree| {
            tree.get("tree")
                .and_then(|v| v.get("highlights"))
                .and_then(|v| v.get("table_lookups"))
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
        })
        .collect::<Vec<_>>();
    base64
        .get("indices")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|index| {
            let ch = index.get("char").and_then(|v| v.as_str()).unwrap_or("");
            let index_hex = index
                .get("index_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let matches = lookups
                .iter()
                .filter(|lookup| {
                    lookup.get("char").and_then(|v| v.as_str()) == Some(ch)
                        && lookup.get("index_value").and_then(|v| v.as_str()) == Some(index_hex)
                })
                .map(|lookup| {
                    serde_json::json!({
                        "idx": lookup.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                        "reg": lookup.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                        "index_reg": lookup.get("index_reg").cloned().unwrap_or(serde_json::Value::Null),
                        "base_value": lookup.get("base_value").cloned().unwrap_or(serde_json::Value::Null),
                        "node": lookup.get("node").cloned().unwrap_or(serde_json::Value::Null),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "pos": index.get("pos").cloned().unwrap_or(serde_json::Value::Null),
                "char": ch,
                "index": index.get("index").cloned().unwrap_or(serde_json::Value::Null),
                "index_hex": index_hex,
                "matches": matches,
            })
        })
        .collect()
}

async fn attach_base64_index_trees_on(
    app: &axum::Router,
    lookup_matches: &mut [serde_json::Value],
    opts: &OutputMapOpts,
) -> anyhow::Result<()> {
    for row in lookup_matches {
        let Some(matches) = row.get_mut("matches").and_then(|v| v.as_array_mut()) else {
            continue;
        };
        for lookup in matches {
            let Some(idx) = lookup.get("idx").and_then(|v| v.as_u64()) else {
                continue;
            };
            let Some(reg) = lookup.get("index_reg").and_then(|v| v.as_str()) else {
                continue;
            };
            let tree = vm_backtree_value_on(
                app,
                idx as usize,
                Some(reg.to_string()),
                opts.index_tree_depth,
                opts.index_tree_max_nodes,
                120,
                opts.lookback,
                5000,
                opts.tree_frontier_with_next,
                "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x23,x25,x27".to_string(),
            )
            .await?;
            let summary = index_tree_summary(&tree);
            if let Some(obj) = lookup.as_object_mut() {
                obj.insert("index_summary".to_string(), summary);
                obj.insert("index_tree".to_string(), tree);
            }
        }
    }
    Ok(())
}

fn index_tree_summary(tree: &serde_json::Value) -> serde_json::Value {
    let formulas = tree
        .get("highlights")
        .and_then(|v| v.get("alu_formulas"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    let interesting_formulas = tree
        .get("highlights")
        .and_then(|v| v.get("alu_formulas"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter(|formula| {
            formula
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)
                .is_some_and(|value| value <= 0x3f)
                && formula_operands_below(formula, 0xfff)
                && !formula_is_low_signal(formula)
        })
        .take(16)
        .cloned()
        .collect::<Vec<_>>();
    let semantic_formulas = formulas
        .iter()
        .filter(|formula| {
            formula.get("semantic").is_some()
                || formula.get("op").and_then(|v| v.as_str()) == Some("udiv")
        })
        .take(16)
        .cloned()
        .collect::<Vec<_>>();
    serde_json::json!({
        "interesting_formulas": interesting_formulas,
        "semantic_formulas": semantic_formulas,
    })
}

fn formula_is_low_signal(formula: &serde_json::Value) -> bool {
    let op = formula.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let value = formula
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str);
    let operands = formula
        .get("operands")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|operand| {
            operand
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)
        })
        .collect::<Vec<_>>();
    match op {
        "ubfx" => formula
            .get("expression")
            .and_then(|v| v.as_str())
            .is_some_and(|expr| expr.contains(", 0x0, 0x20)")),
        "lsl" | "lsr" => operands.get(1).copied() == Some(0),
        "orr" | "add" => operands
            .iter()
            .enumerate()
            .any(|(idx, &operand)| operand == 0 && operands.get(1 - idx).copied() == value),
        _ => value == Some(0),
    }
}

fn formula_operands_below(formula: &serde_json::Value, max_value: u64) -> bool {
    formula
        .get("operands")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|operand| {
            operand
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)
        })
        .all(|value| value <= max_value)
}

fn base64_char_index(byte: u8) -> Option<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ALPHABET
        .iter()
        .position(|&item| item == byte)
        .map(|idx| idx as u8)
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
    vm_chain_steps: usize,
    vm_chain_runs: usize,
    vm_chain_lookback: usize,
    vm_chain_follow_frontier: bool,
    skip_taint: bool,
    url_decode: bool,
    base64_decode: bool,
}

#[derive(Debug)]
struct OutputMapOpts {
    key: Option<String>,
    value: Option<String>,
    jni_limit: usize,
    max_mem_hits: usize,
    hit_rank: usize,
    hit_order: HitOrder,
    group_start: usize,
    groups: usize,
    tree_depth: usize,
    tree_max_nodes: usize,
    index_tree_depth: usize,
    index_tree_max_nodes: usize,
    tree_frontier_with_next: bool,
    lookback: usize,
    url_decode: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HitOrder {
    /// Earliest first write of a full output buffer. Best for walking generation backward.
    Earliest,
    /// Closest full output buffer to the JNI value trace index.
    Nearest,
    /// Latest first write of a full output buffer.
    Latest,
}

impl HitOrder {
    fn as_str(self) -> &'static str {
        match self {
            HitOrder::Earliest => "earliest",
            HitOrder::Nearest => "nearest",
            HitOrder::Latest => "latest",
        }
    }
}

#[derive(Debug)]
struct OutputSource {
    json: serde_json::Value,
    primary_bytes: Vec<u8>,
    text: Option<String>,
    value_idx: Option<usize>,
}

async fn cmd_output_backtrace(trace_dir: PathBuf, opts: OutputBacktraceOpts) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let source = resolve_output_source(&app, &opts).await?;
    let mut patterns: Vec<(&'static str, Vec<u8>)> =
        vec![("observed", source.primary_bytes.clone())];
    let mut text_for_decoders = source.text.clone();
    if opts.url_decode {
        if let Some(text) = source.text.as_deref() {
            let decoded = percent_decode_bytes(text.as_bytes());
            if decoded != source.primary_bytes {
                if let Ok(decoded_text) = String::from_utf8(decoded.clone()) {
                    text_for_decoders = Some(decoded_text);
                }
                patterns.push(("percent_decoded", decoded));
            }
        }
    }
    if opts.base64_decode {
        if let Some(text) = text_for_decoders.as_deref() {
            if let Ok(decoded) = base64_decoded_bytes(text) {
                if !decoded.is_empty() && decoded != source.primary_bytes {
                    patterns.push(("base64_decoded", decoded));
                }
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
            route_get_json_value_on(&app, route_path("/api/find-mem-pattern", &params)).await?
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
            let hits = sorted_pattern_hits(&find, source.value_idx);
            if !hits.is_empty() {
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
                    let provenance = route_get_json_value_on(
                        &app,
                        route_path("/api/string-provenance", &provenance_params),
                    )
                    .await?;
                    let top_writers = provenance_writer_counts(&provenance, opts.writes_per_hit);
                    let mut writer_details = Vec::new();
                    for writer in &top_writers {
                        let Some(idx) = writer.get("idx").and_then(|v| v.as_u64()) else {
                            continue;
                        };
                        let record =
                            route_get_json_value_on(&app, format!("/api/record/{idx}")).await?;
                        let writer_seeds = writer_taint_seeds_from_record(&record);
                        for seed in &writer_seeds {
                            push_taint_seed(
                                &mut taint_seed_seen,
                                &mut taint_seed_queue,
                                seed.clone(),
                            );
                        }
                        writer_details.push(serde_json::json!({
                            "writer": writer,
                            "record": record,
                            "writer_seeds": writer_seeds,
                        }));
                    }
                    let writer_runs = provenance_writer_runs(&provenance, &writer_details);
                    let vm_chains = if opts.vm_chain_steps > 0 && opts.vm_chain_runs > 0 {
                        vm_chains_for_writer_runs(&app, &writer_runs, &opts).await?
                    } else {
                        Vec::new()
                    };
                    hit_reports.push(serde_json::json!({
                        "hit": hit,
                        "distance_to_value_idx": source.value_idx.and_then(|idx| {
                            hit.get("first_idx")
                                .and_then(|v| v.as_u64())
                                .map(|first| idx.abs_diff(first as usize))
                        }),
                        "range": {
                            "addr_lo": format!("{addr:#x}"),
                            "addr_hi": format!("{addr_hi:#x}"),
                            "length": bytes.len(),
                        },
                        "provenance": provenance,
                        "top_provenance_writers": top_writers,
                        "writer_details": writer_details,
                        "writer_runs": writer_runs,
                        "vm_chains": vm_chains,
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
            &app,
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

async fn cmd_output_map(trace_dir: PathBuf, opts: OutputMapOpts) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let source = resolve_output_source(
        &app,
        &OutputBacktraceOpts {
            key: opts.key.clone(),
            value: opts.value.clone(),
            bytes_hex: None,
            jni_limit: opts.jni_limit,
            max_mem_hits: opts.max_mem_hits,
            writes_per_hit: 0,
            taint_seeds: 0,
            taint_max_count: 0,
            vm_chain_steps: 0,
            vm_chain_runs: 0,
            vm_chain_lookback: opts.lookback,
            vm_chain_follow_frontier: false,
            skip_taint: true,
            url_decode: opts.url_decode,
            base64_decode: true,
        },
    )
    .await?;
    let Some(source_text) = source.text.as_deref() else {
        bail!("output-map requires textual --key or --value source");
    };
    let mapped_text = if opts.url_decode {
        let decoded = percent_decode_bytes(source_text.as_bytes());
        String::from_utf8(decoded).unwrap_or_else(|_| source_text.to_string())
    } else {
        source_text.to_string()
    };
    let find = if opts.max_mem_hits > 0 {
        let params = vec![
            ("bytes_hex", bytes_to_hex(&source.primary_bytes)),
            ("max", opts.max_mem_hits.to_string()),
        ];
        route_get_json_value_on(&app, route_path("/api/find-mem-pattern", &params)).await?
    } else {
        serde_json::json!({
            "status": "skipped",
            "hits": [],
        })
    };
    let hits = sorted_pattern_hits_by(&find, source.value_idx, opts.hit_order);
    let hit_candidates = hit_candidate_summaries(&hits, source.value_idx);
    let selected_hit = hits.get(opts.hit_rank).cloned();
    let mut writer_runs = Vec::new();
    let mut selected_range = serde_json::Value::Null;
    if let Some(hit) = selected_hit.as_ref() {
        if let Some(addr) = hit
            .get("addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
        {
            let params = vec![
                ("addr", format!("{addr:#x}")),
                ("length", source.primary_bytes.len().to_string()),
            ];
            let provenance =
                route_get_json_value_on(&app, route_path("/api/string-provenance", &params))
                    .await?;
            writer_runs = provenance_writer_runs(&provenance, &[]);
            selected_range = serde_json::json!({
                "addr_lo": format!("{addr:#x}"),
                "addr_hi": format!("{:#x}", addr.saturating_add(source.primary_bytes.len() as u64)),
                "length": source.primary_bytes.len(),
            });
        }
    }

    let group_total = mapped_text.len().div_ceil(4);
    let group_end = if opts.groups == 0 {
        group_total
    } else {
        opts.group_start
            .saturating_add(opts.groups)
            .min(group_total)
    };
    let mut group_rows = Vec::new();
    for group_idx in opts.group_start.min(group_total)..group_end {
        let start = group_idx * 4;
        let end = (start + 4).min(mapped_text.len());
        let chars = &mapped_text[start..end];
        let decoded = base64_decoded_bytes(chars).unwrap_or_default();
        let base64 = base64_group_analysis(chars);
        let runs = output_runs_overlapping(&app, &writer_runs, start, end).await?;
        let mut trees = Vec::new();
        if opts.tree_depth > 0 {
            for run in &runs {
                if let Some(seed) =
                    run.get("writer_seeds")
                        .and_then(|v| v.as_array())
                        .and_then(|seeds| {
                            seeds.iter().find(|seed| {
                                seed.get("kind").and_then(|v| v.as_str())
                                    == Some("memory_writer_src_reg")
                            })
                        })
                {
                    let Some(idx) = seed.get("start").and_then(|v| v.as_u64()) else {
                        continue;
                    };
                    let Some(reg) = seed.get("reg").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let tree = vm_backtree_value_on(
                        &app,
                        idx as usize,
                        Some(reg.to_string()),
                        opts.tree_depth,
                        opts.tree_max_nodes,
                        120,
                        opts.lookback,
                        5000,
                        opts.tree_frontier_with_next,
                        "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x23,x25,x27".to_string(),
                    )
                    .await?;
                    trees.push(serde_json::json!({
                        "seed": seed,
                        "tree": tree,
                    }));
                    break;
                }
            }
        }
        let mut lookup_matches = base64_lookup_matches(&base64, &trees);
        if opts.index_tree_depth > 0 {
            attach_base64_index_trees_on(&app, &mut lookup_matches, &opts).await?;
        }
        group_rows.push(serde_json::json!({
            "group": group_idx,
            "offset": start,
            "chars": chars,
            "base64": base64,
            "base64_lookup_matches": lookup_matches,
            "decoded_hex": bytes_to_hex(&decoded),
            "runs": runs,
            "trees": trees,
        }));
    }

    print_pretty(&serde_json::json!({
        "status": "ready",
        "strategy": "output_base64_group_map",
        "source": source.json,
        "text_len": mapped_text.len(),
        "group_total": group_total,
        "selected_hit_order": opts.hit_order.as_str(),
        "selected_hit_rank": opts.hit_rank,
        "tree_frontier_with_next": opts.tree_frontier_with_next,
        "index_tree_depth": opts.index_tree_depth,
        "index_tree_max_nodes": opts.index_tree_max_nodes,
        "hit_candidates": hit_candidates,
        "selected_hit": selected_hit,
        "selected_range": selected_range,
        "find_mem_pattern": find,
        "groups": group_rows,
    }))
}

async fn output_runs_overlapping(
    app: &axum::Router,
    writer_runs: &[serde_json::Value],
    start: usize,
    end: usize,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for run in writer_runs {
        let run_start = run.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let run_len = run.get("length").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let run_end = run_start.saturating_add(run_len);
        if run_start >= end || run_end <= start {
            continue;
        }
        let mut row = run.clone();
        if row
            .get("writer_seeds")
            .and_then(|v| v.as_array())
            .is_none_or(|items| items.is_empty())
        {
            if let Some(idx) = row.get("writer_idx").and_then(|v| v.as_u64()) {
                let record = route_get_json_value_on(app, format!("/api/record/{idx}")).await?;
                row["record"] = record.clone();
                row["writer_seeds"] =
                    serde_json::Value::Array(writer_taint_seeds_from_record(&record));
            }
        }
        out.push(row);
    }
    Ok(out)
}

async fn resolve_output_source(
    app: &axum::Router,
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
        jni_output_string_pairs_on(app, Some(key.to_string()), None, opts.jni_limit).await?;
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

fn writer_taint_seeds_from_record(record: &serde_json::Value) -> Vec<serde_json::Value> {
    let Some(idx) = record.get("idx").and_then(|v| v.as_u64()) else {
        return Vec::new();
    };
    let Some(asm) = record.get("asm").and_then(|v| v.as_str()) else {
        return Vec::new();
    };
    store_source_regs_from_asm(asm)
        .into_iter()
        .map(|reg| {
            let reg_key = register_value_key(&reg);
            let src_value = record
                .get("regs")
                .and_then(|v| v.get(&reg_key))
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            serde_json::json!({
                "kind": "memory_writer_src_reg",
                "start": idx,
                "reg": reg,
                "src_value": src_value,
                "writer": {
                    "idx": record.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "pc": record.get("pc").cloned().unwrap_or(serde_json::Value::Null),
                    "rel": record.get("rel").cloned().unwrap_or(serde_json::Value::Null),
                    "func": record.get("func").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": record.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                },
            })
        })
        .collect()
}

fn store_source_regs_from_asm(asm: &str) -> Vec<String> {
    let asm = asm.trim();
    let mut parts = asm.splitn(2, char::is_whitespace);
    let Some(mnemonic) = parts.next() else {
        return Vec::new();
    };
    let Some(operands) = parts.next() else {
        return Vec::new();
    };
    let mnemonic = mnemonic.to_ascii_lowercase();
    let operands = split_operands(operands);
    let source_ops: Vec<String> = if matches!(mnemonic.as_str(), "stp" | "stnp") {
        operands.into_iter().take(2).collect()
    } else if matches!(mnemonic.as_str(), "stxp" | "stlxp") {
        operands.into_iter().skip(1).take(2).collect()
    } else if matches!(mnemonic.as_str(), "stxr" | "stlxr") {
        operands.into_iter().skip(1).take(1).collect()
    } else if mnemonic.starts_with("str")
        || mnemonic.starts_with("stur")
        || mnemonic.starts_with("sttr")
        || mnemonic.starts_with("stlr")
    {
        operands.into_iter().take(1).collect()
    } else {
        Vec::new()
    };
    source_ops
        .into_iter()
        .filter_map(|op| first_register_token(&op))
        .collect()
}

fn split_operands(operands: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut bracket_depth = 0i32;
    for (idx, ch) in operands.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => bracket_depth -= 1,
            ',' if bracket_depth == 0 => {
                out.push(operands[start..idx].trim().to_string());
                start = idx + 1;
            }
            _ => {}
        }
    }
    if start < operands.len() {
        out.push(operands[start..].trim().to_string());
    }
    out
}

fn first_register_token(op: &str) -> Option<String> {
    let token = op
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(|ch: char| ch.is_whitespace() || ch == ',' || ch == '[' || ch == ']')
        .find(|part| !part.is_empty())?;
    let token = token.trim_end_matches('!').to_ascii_lowercase();
    is_gp_register_token(&token).then_some(token)
}

fn register_value_key(reg: &str) -> String {
    let reg = reg.to_ascii_lowercase();
    if let Some(rest) = reg.strip_prefix('w') {
        if rest.parse::<u8>().is_ok() {
            return format!("x{rest}");
        }
    }
    match reg.as_str() {
        "wsp" => "sp".to_string(),
        "wzr" => "xzr".to_string(),
        other => other.to_string(),
    }
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

fn sorted_pattern_hits(
    find_response: &serde_json::Value,
    value_idx: Option<usize>,
) -> Vec<serde_json::Value> {
    sorted_pattern_hits_by(find_response, value_idx, HitOrder::Nearest)
}

fn sorted_pattern_hits_by(
    find_response: &serde_json::Value,
    value_idx: Option<usize>,
    order: HitOrder,
) -> Vec<serde_json::Value> {
    let mut hits = find_response
        .get("hits")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    match order {
        HitOrder::Earliest => hits.sort_by_key(|hit| {
            hit.get("first_idx")
                .and_then(|v| v.as_u64())
                .map(|idx| idx as usize)
                .unwrap_or(usize::MAX)
        }),
        HitOrder::Nearest => {
            if let Some(value_idx) = value_idx {
                hits.sort_by_key(|hit| {
                    hit.get("first_idx")
                        .and_then(|v| v.as_u64())
                        .map(|idx| value_idx.abs_diff(idx as usize))
                        .unwrap_or(usize::MAX)
                });
            }
        }
        HitOrder::Latest => hits.sort_by_key(|hit| {
            std::cmp::Reverse(
                hit.get("first_idx")
                    .and_then(|v| v.as_u64())
                    .map(|idx| idx as usize)
                    .unwrap_or(0),
            )
        }),
    }
    hits
}

fn hit_candidate_summaries(
    hits: &[serde_json::Value],
    value_idx: Option<usize>,
) -> Vec<serde_json::Value> {
    hits.iter()
        .enumerate()
        .map(|(rank, hit)| {
            let first_idx = hit
                .get("first_idx")
                .and_then(|v| v.as_u64())
                .map(|idx| idx as usize);
            serde_json::json!({
                "rank": rank,
                "addr": hit.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "first_idx": first_idx,
                "distance_to_value_idx": value_idx.and_then(|idx| first_idx.map(|first| idx.abs_diff(first))),
            })
        })
        .collect()
}

fn provenance_writer_runs(
    provenance: &serde_json::Value,
    writer_details: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut details_by_idx = BTreeMap::new();
    for detail in writer_details {
        if let Some(idx) = detail
            .get("writer")
            .and_then(|v| v.get("idx"))
            .and_then(|v| v.as_u64())
        {
            details_by_idx.insert(idx, detail);
        }
    }

    let mut runs: Vec<(Option<u64>, usize, Vec<u8>)> = Vec::new();
    let Some(bytes) = provenance.get("bytes").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut current_idx: Option<u64> = None;
    for byte in bytes {
        let idx = byte.get("current_writer_idx").and_then(|v| v.as_u64());
        let offset = byte.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let b = byte.get("byte").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        if runs.last().is_none_or(|(run_idx, _, _)| *run_idx != idx) {
            runs.push((idx, offset, Vec::new()));
            current_idx = idx;
        }
        if current_idx == idx {
            if let Some((_, _, data)) = runs.last_mut() {
                data.push(b);
            }
        }
    }

    runs.into_iter()
        .map(|(writer_idx, offset, data)| {
            let detail = writer_idx.and_then(|idx| details_by_idx.get(&idx));
            serde_json::json!({
                "offset": offset,
                "length": data.len(),
                "writer_idx": writer_idx,
                "bytes_hex": bytes_to_hex(&data),
                "text": utf8_preview(&data, 80),
                "record": detail
                    .and_then(|v| v.get("record"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                "writer_seeds": detail
                    .and_then(|v| v.get("writer_seeds"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            })
        })
        .collect()
}

async fn vm_chains_for_writer_runs(
    app: &axum::Router,
    writer_runs: &[serde_json::Value],
    opts: &OutputBacktraceOpts,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let regs =
        "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x23,x25,x27";
    let mut out = Vec::new();
    for run in writer_runs.iter().take(opts.vm_chain_runs) {
        let mut seed_value = run
            .get("writer_seeds")
            .and_then(|v| v.as_array())
            .and_then(|seeds| {
                seeds.iter().find(|seed| {
                    seed.get("kind").and_then(|v| v.as_str()) == Some("memory_writer_src_reg")
                })
            })
            .cloned();
        let fetched_record = if seed_value.is_none() {
            if let Some(idx) = run.get("writer_idx").and_then(|v| v.as_u64()) {
                let record = route_get_json_value_on(app, format!("/api/record/{idx}")).await?;
                let seeds = writer_taint_seeds_from_record(&record);
                seed_value = seeds
                    .iter()
                    .find(|seed| {
                        seed.get("kind").and_then(|v| v.as_str()) == Some("memory_writer_src_reg")
                    })
                    .cloned();
                Some(serde_json::json!({
                    "record": record,
                    "writer_seeds": seeds,
                }))
            } else {
                None
            }
        } else {
            None
        };
        let Some(seed_value) = seed_value else {
            out.push(serde_json::json!({
                "offset": run.get("offset").cloned().unwrap_or(serde_json::Value::Null),
                "length": run.get("length").cloned().unwrap_or(serde_json::Value::Null),
                "writer_idx": run.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
                "fetched_record": fetched_record,
                "status": "no_writer_seed",
            }));
            continue;
        };
        let Some(start) = seed_value.get("start").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(reg) = seed_value.get("reg").and_then(|v| v.as_str()) else {
            continue;
        };
        let chain = vm_backchain_value_on(
            app,
            start as usize,
            Some(reg.to_string()),
            opts.vm_chain_steps,
            120,
            opts.vm_chain_lookback,
            5000,
            opts.vm_chain_follow_frontier,
            regs.to_string(),
        )
        .await?;
        out.push(serde_json::json!({
            "offset": run.get("offset").cloned().unwrap_or(serde_json::Value::Null),
            "length": run.get("length").cloned().unwrap_or(serde_json::Value::Null),
            "text": run.get("text").cloned().unwrap_or(serde_json::Value::Null),
            "writer_idx": run.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
            "seed": seed_value,
            "chain": chain,
        }));
    }
    Ok(out)
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
    app: &axum::Router,
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
        let response =
            route_get_json_value_on(app, route_path("/api/backward-taint", &params)).await?;
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

async fn cmd_vm_slice(
    trace_dir: PathBuf,
    start: usize,
    end: Option<usize>,
    count: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
) -> anyhow::Result<()> {
    let end = end.unwrap_or_else(|| start.saturating_add(count));
    let (rows, source_returned, inferred_base) =
        load_vm_rows(trace_dir, start, end, regs, only_vm, base_ip).await?;

    print_pretty(&serde_json::json!({
        "status": "ready",
        "start": start,
        "end": end,
        "returned": rows.len(),
        "source_returned": source_returned,
        "only_vm": only_vm,
        "vm_base_ip": inferred_base.map(|v| format!("{v:#x}")),
        "records": rows,
    }))
}

async fn cmd_vm_ops(
    trace_dir: PathBuf,
    start: usize,
    end: Option<usize>,
    count: usize,
    regs: String,
    base_ip: Option<String>,
    max_ops: usize,
) -> anyhow::Result<()> {
    let end = end.unwrap_or_else(|| start.saturating_add(count));
    let (rows, source_returned, inferred_base) =
        load_vm_rows(trace_dir, start, end, regs, true, base_ip).await?;
    let all_ops = vm_ops_from_rows(&rows);
    let truncated = all_ops.len() > max_ops;
    let ops = all_ops.into_iter().take(max_ops).collect::<Vec<_>>();
    print_pretty(&serde_json::json!({
        "status": "ready",
        "start": start,
        "end": end,
        "source_returned": source_returned,
        "vm_rows": rows.len(),
        "vm_base_ip": inferred_base.map(|v| format!("{v:#x}")),
        "ops_returned": ops.len(),
        "truncated": truncated,
        "ops": ops,
    }))
}

async fn load_vm_rows(
    trace_dir: PathBuf,
    start: usize,
    end: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
) -> anyhow::Result<(Vec<serde_json::Value>, usize, Option<u64>)> {
    let count = end.saturating_sub(start);
    let params = vec![
        ("start", start.to_string()),
        ("count", count.to_string()),
        ("regs", regs),
    ];
    let response = route_get_json_value(trace_dir, route_path("/api/records", &params)).await?;
    let records = response
        .get("records")
        .and_then(|v| v.as_array())
        .context("/api/records response missing records[]")?;
    let inferred_base = base_ip
        .as_deref()
        .and_then(parse_u64_str)
        .or_else(|| records.iter().find_map(|rec| record_reg_u64(rec, "x21")));

    let mut rows = Vec::new();
    for (pos, rec) in records.iter().enumerate() {
        let asm = rec.get("asm").and_then(|v| v.as_str()).unwrap_or("");
        let class = classify_vm_asm(asm);
        if only_vm && class == "other" {
            continue;
        }
        let next = records.get(pos + 1);
        rows.push(vm_row_from_record(rec, next, inferred_base));
    }
    Ok((rows, records.len(), inferred_base))
}

async fn cmd_vm_backstep(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let value = vm_backstep_value_on(&app, idx, reg, context, lookback, max_writes, regs).await?;
    print_pretty(&value)
}

#[allow(clippy::too_many_arguments)]
async fn cmd_byte_lineage(
    trace_dir: PathBuf,
    addr: String,
    before_idx: usize,
    depth: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    summary: bool,
) -> anyhow::Result<()> {
    let addr = parse_u64_str(&addr).with_context(|| format!("parse addr {addr}"))?;
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let value = byte_lineage_value_on(
        &app, addr, before_idx, depth, context, lookback, max_writes, regs,
    )
    .await?;
    if summary {
        print_pretty(&byte_lineage_summary(&value))
    } else {
        print_pretty(&value)
    }
}

async fn cmd_vm_backchain(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    steps: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    follow_frontier: bool,
    regs: String,
    summary: bool,
) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let value = vm_backchain_value_on(
        &app,
        idx,
        reg,
        steps,
        context,
        lookback,
        max_writes,
        follow_frontier,
        regs,
    )
    .await?;
    if summary {
        print_pretty(&vm_backchain_summary(&value))
    } else {
        print_pretty(&value)
    }
}

#[allow(clippy::too_many_arguments)]
async fn cmd_vm_backtree(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    depth: usize,
    max_nodes: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    frontier_with_next: bool,
    summary: bool,
    regs: String,
) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let value = vm_backtree_value_on(
        &app,
        idx,
        reg,
        depth,
        max_nodes,
        context,
        lookback,
        max_writes,
        frontier_with_next,
        regs,
    )
    .await?;
    if summary {
        print_pretty(&vm_backtree_summary(&value))
    } else {
        print_pretty(&value)
    }
}

async fn vm_backchain_value_on(
    app: &axum::Router,
    idx: usize,
    reg: Option<String>,
    steps: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    follow_frontier: bool,
    regs: String,
) -> anyhow::Result<serde_json::Value> {
    let mut current_idx = idx;
    let mut current_reg = reg.clone();
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    for step_idx in 0..steps {
        if !seen.insert(format!(
            "{}:{}",
            current_idx,
            current_reg.as_deref().unwrap_or("")
        )) {
            rows.push(serde_json::json!({
                "step": step_idx,
                "status": "cycle",
                "idx": current_idx,
                "reg": current_reg,
            }));
            break;
        }
        let step = vm_backstep_value_on(
            &app,
            current_idx,
            current_reg.clone(),
            context,
            lookback,
            max_writes,
            regs.clone(),
        )
        .await?;
        let next = step
            .get("upstream")
            .and_then(|v| v.get("next"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let (chosen_next, decision) = if next.get("idx").and_then(|v| v.as_u64()).is_some() {
            (
                next,
                serde_json::json!({
                    "kind": "upstream_next",
                }),
            )
        } else if follow_frontier {
            match choose_frontier_next(&step) {
                Some(frontier_next) => (
                    frontier_next.clone(),
                    serde_json::json!({
                        "kind": "frontier_auto",
                        "next": frontier_next,
                    }),
                ),
                None => (
                    serde_json::Value::Null,
                    serde_json::json!({
                        "kind": "stop",
                        "reason": "no_upstream_next_or_frontier",
                    }),
                ),
            }
        } else {
            (
                serde_json::Value::Null,
                serde_json::json!({
                    "kind": "stop",
                    "reason": "no_upstream_next",
                }),
            )
        };
        current_idx = match chosen_next.get("idx").and_then(|v| v.as_u64()) {
            Some(idx) => idx as usize,
            None => {
                rows.push(serde_json::json!({
                    "step": step_idx,
                    "backstep": step,
                    "next": serde_json::Value::Null,
                    "decision": decision,
                }));
                break;
            }
        };
        current_reg = chosen_next
            .get("reg")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        rows.push(serde_json::json!({
            "step": step_idx,
            "backstep": step,
            "next": chosen_next,
            "decision": decision,
        }));
        if current_reg.is_none() {
            break;
        }
    }
    Ok(serde_json::json!({
        "status": "ready",
        "start": {
            "idx": idx,
            "reg": reg,
        },
        "follow_frontier": follow_frontier,
        "steps_requested": steps,
        "steps_returned": rows.len(),
        "chain": rows,
    }))
}

fn choose_frontier_next(step: &serde_json::Value) -> Option<serde_json::Value> {
    if step.pointer("/local_def/class").and_then(|v| v.as_str()) == Some("call-return") {
        return None;
    }
    if let Some(next) = choose_semantic_frontier_next(step) {
        return Some(next);
    }
    let frontiers = step.get("frontier")?.as_array()?;
    let mut candidates = frontiers
        .iter()
        .filter_map(|frontier| {
            let reg = frontier.get("reg")?.as_str()?;
            if is_vm_infrastructure_reg(reg) {
                return None;
            }
            let value = frontier
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let score = frontier_value_score(&value);
            Some((score, frontier))
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        candidates = frontiers
            .iter()
            .filter_map(|frontier| {
                let value = frontier
                    .get("value")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let score = frontier_value_score(&value);
                Some((score, frontier))
            })
            .collect::<Vec<_>>();
    }
    candidates.sort_by_key(|(score, _)| *score);
    let (_, frontier) = candidates.first()?;
    frontier_to_next(frontier)
}

fn choose_semantic_frontier_next(step: &serde_json::Value) -> Option<serde_json::Value> {
    let local_def = step.get("local_def")?;
    if local_def.get("class").and_then(|v| v.as_str()) == Some("call-return") {
        return None;
    }
    let formula = row_alu_formula(local_def)?;
    if formula
        .pointer("/semantic/input")
        .and_then(|v| v.as_str())
        .is_some()
    {
        let input = formula
            .pointer("/semantic/input")
            .and_then(|v| v.as_str())?;
        return frontier_next_by_value(step, input);
    }
    if formula.get("op").and_then(|v| v.as_str()) == Some("udiv") {
        let numerator = formula
            .get("operands")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())?;
        if let Some(reg) = numerator.get("reg").and_then(|v| v.as_str()) {
            if let Some(next) = frontier_next_by_reg(step, reg) {
                return Some(next);
            }
        }
        if let Some(value) = numerator.get("value").and_then(|v| v.as_str()) {
            return frontier_next_by_value(step, value);
        }
    }
    if matches!(
        formula.get("op").and_then(|v| v.as_str()),
        Some("lsl" | "lsr" | "asr" | "ubfx")
    ) {
        let input = formula
            .get("operands")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())?;
        if let Some(reg) = input.get("reg").and_then(|v| v.as_str()) {
            if let Some(next) = frontier_next_by_reg(step, reg) {
                return Some(next);
            }
        }
        if let Some(value) = input.get("value").and_then(|v| v.as_str()) {
            return frontier_next_by_value(step, value);
        }
    }
    None
}

fn frontier_next_by_reg(step: &serde_json::Value, reg: &str) -> Option<serde_json::Value> {
    step.get("frontier")?
        .as_array()?
        .iter()
        .find(|frontier| frontier.get("reg").and_then(|v| v.as_str()) == Some(reg))
        .and_then(frontier_to_next)
}

fn frontier_next_by_value(step: &serde_json::Value, value: &str) -> Option<serde_json::Value> {
    step.get("frontier")?
        .as_array()?
        .iter()
        .find(|frontier| frontier.get("value").and_then(|v| v.as_str()) == Some(value))
        .and_then(frontier_to_next)
}

fn frontier_to_next(frontier: &serde_json::Value) -> Option<serde_json::Value> {
    Some(serde_json::json!({
        "idx": frontier.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": frontier.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "src_value": frontier.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "reason": "frontier_auto",
        "frontier": (*frontier).clone(),
    }))
}

fn frontier_value_score(value: &serde_json::Value) -> u8 {
    let parsed = value
        .as_str()
        .and_then(parse_u64_str)
        .or_else(|| value.as_u64());
    match parsed {
        Some(v) if v <= 0xff => 0,
        Some(v) if v <= 0xffff => 1,
        Some(v) if v <= 0xffff_ffff => 2,
        Some(_) => 3,
        None => 4,
    }
}

fn is_vm_infrastructure_reg(reg: &str) -> bool {
    matches!(
        register_value_key(reg).as_str(),
        "sp" | "fp" | "lr" | "x21" | "x23" | "x25" | "x27"
    )
}

#[allow(clippy::too_many_arguments)]
async fn vm_backtree_value_on(
    app: &axum::Router,
    idx: usize,
    reg: Option<String>,
    depth: usize,
    max_nodes: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    frontier_with_next: bool,
    regs: String,
) -> anyhow::Result<serde_json::Value> {
    let mut queue = VecDeque::new();
    queue.push_back(TreeSeed {
        parent: None,
        depth: 0,
        idx,
        reg: reg.clone(),
        via: serde_json::json!({"kind": "root"}),
    });
    let mut seen = HashSet::new();
    let mut nodes = Vec::new();
    let mut truncated = false;
    while let Some(seed) = queue.pop_front() {
        if nodes.len() >= max_nodes {
            truncated = true;
            break;
        }
        let key = format!("{}:{}", seed.idx, seed.reg.as_deref().unwrap_or(""));
        if !seen.insert(key) {
            nodes.push(serde_json::json!({
                "id": nodes.len(),
                "parent": seed.parent,
                "depth": seed.depth,
                "idx": seed.idx,
                "reg": seed.reg,
                "via": seed.via,
                "status": "cycle",
            }));
            continue;
        }
        let backstep = vm_backstep_value_on(
            app,
            seed.idx,
            seed.reg.clone(),
            context,
            lookback,
            max_writes,
            regs.clone(),
        )
        .await?;
        let node_id = nodes.len();
        let upstream_next = backstep
            .get("upstream")
            .and_then(|v| v.get("next"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let upstream_byte_nexts = upstream_byte_nexts_from_step(&backstep);
        let frontier_nexts = frontier_nexts_from_step(&backstep);
        let enqueue_frontiers =
            frontier_with_next || upstream_next.get("idx").and_then(|v| v.as_u64()).is_none();
        nodes.push(compact_backtree_node(
            node_id,
            seed.parent,
            seed.depth,
            &seed.via,
            &backstep,
            &upstream_next,
            &upstream_byte_nexts,
            &frontier_nexts,
        ));
        if seed.depth >= depth {
            continue;
        }
        if let Some(next_seed) = tree_seed_from_next(
            node_id,
            seed.depth + 1,
            upstream_next.clone(),
            serde_json::json!({"kind": "upstream_next"}),
        ) {
            queue.push_back(next_seed);
        }
        for byte_next in upstream_byte_nexts {
            if same_tree_next(&upstream_next, &byte_next) {
                continue;
            }
            if let Some(next_seed) = tree_seed_from_next(
                node_id,
                seed.depth + 1,
                byte_next.clone(),
                serde_json::json!({
                    "kind": "upstream_byte",
                    "byte": byte_next,
                }),
            ) {
                queue.push_back(next_seed);
            }
        }
        if enqueue_frontiers {
            for frontier_next in frontier_nexts {
                if let Some(next_seed) = tree_seed_from_next(
                    node_id,
                    seed.depth + 1,
                    frontier_next.clone(),
                    serde_json::json!({
                        "kind": "frontier",
                        "frontier": frontier_next.get("frontier").cloned().unwrap_or(serde_json::Value::Null),
                    }),
                ) {
                    queue.push_back(next_seed);
                }
            }
        }
    }
    let highlights = vm_backtree_highlights(&nodes);
    Ok(serde_json::json!({
        "status": "ready",
        "start": {
            "idx": idx,
            "reg": reg,
        },
        "depth_requested": depth,
        "max_nodes": max_nodes,
        "frontier_with_next": frontier_with_next,
        "nodes_returned": nodes.len(),
        "truncated": truncated || !queue.is_empty(),
        "highlights": highlights,
        "nodes": nodes,
    }))
}

fn vm_backtree_summary(tree: &serde_json::Value) -> serde_json::Value {
    let nodes = tree
        .get("nodes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let formula_summary = index_tree_summary(tree);
    let interesting_formulas = formula_summary
        .get("interesting_formulas")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let semantic_formulas = formula_summary
        .get("semantic_formulas")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let bytecode_frontiers = nodes
        .iter()
        .filter(|node| {
            local_class(node) == Some("bytecode-read")
                && node
                    .get("frontier_nexts")
                    .and_then(|v| v.as_array())
                    .map_or(true, |items| items.is_empty())
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    let small_byte_loads = nodes
        .iter()
        .filter(|node| {
            local_class(node) == Some("byte-load")
                && node_value_u64(node).is_some_and(|value| value <= 0xff)
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    let terminal_nodes = nodes
        .iter()
        .filter(|node| {
            node.get("status").and_then(|v| v.as_str()) == Some("cycle")
                || (node
                    .get("upstream")
                    .and_then(|v| v.get("status"))
                    .and_then(|v| v.as_str())
                    != Some("ready")
                    && node
                        .get("frontier_nexts")
                        .and_then(|v| v.as_array())
                        .map_or(true, |items| items.is_empty()))
        })
        .take(64)
        .map(compact_tree_node_summary)
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": tree.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": tree.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": tree.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "max_nodes": tree.get("max_nodes").cloned().unwrap_or(serde_json::Value::Null),
        "frontier_with_next": tree.get("frontier_with_next").cloned().unwrap_or(serde_json::Value::Null),
        "nodes_returned": tree.get("nodes_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": tree.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "highlights": {
            "word_loads": tree.pointer("/highlights/word_loads").cloned().unwrap_or_else(|| serde_json::json!([])),
            "table_lookups": tree.pointer("/highlights/table_lookups").cloned().unwrap_or_else(|| serde_json::json!([])),
            "interesting_formulas": interesting_formulas,
            "semantic_formulas": semantic_formulas,
        },
        "small_byte_loads": small_byte_loads,
        "bytecode_frontiers": bytecode_frontiers,
        "terminal_nodes": terminal_nodes,
    })
}

fn local_class(node: &serde_json::Value) -> Option<&str> {
    node.pointer("/local_def/class").and_then(|v| v.as_str())
}

fn node_value_u64(node: &serde_json::Value) -> Option<u64> {
    node.get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
        .or_else(|| node.get("value").and_then(|v| v.as_u64()))
}

fn compact_tree_node_summary(node: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "parent": node.get("parent").cloned().unwrap_or(serde_json::Value::Null),
        "depth": node.get("depth").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": node.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "producer": {
            "asm": node.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
            "class": node.pointer("/local_def/class").cloned().unwrap_or(serde_json::Value::Null),
            "func": node.pointer("/local_def/func").cloned().unwrap_or(serde_json::Value::Null),
            "pc": node.pointer("/local_def/pc").cloned().unwrap_or(serde_json::Value::Null),
            "mem_addr": node.pointer("/local_def/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
            "formula": node.pointer("/local_def/formula").cloned().unwrap_or(serde_json::Value::Null),
        },
        "consumer": {
            "asm": node.pointer("/target/asm").cloned().unwrap_or(serde_json::Value::Null),
            "class": node.pointer("/target/class").cloned().unwrap_or(serde_json::Value::Null),
            "func": node.pointer("/target/func").cloned().unwrap_or(serde_json::Value::Null),
            "pc": node.pointer("/target/pc").cloned().unwrap_or(serde_json::Value::Null),
            "mem_addr": node.pointer("/target/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        },
        "upstream_status": node.pointer("/upstream/status").cloned().unwrap_or(serde_json::Value::Null),
        "via_kind": node.pointer("/via/kind").cloned().unwrap_or(serde_json::Value::Null),
    })
}

enum LineageSeed {
    AddrBefore { addr: u64, before_idx: usize },
    RegAt { idx: usize, reg: String },
}

impl LineageSeed {
    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::AddrBefore { addr, before_idx } => serde_json::json!({
                "kind": "addr_before",
                "addr": format!("{addr:#x}"),
                "before_idx": before_idx,
            }),
            Self::RegAt { idx, reg } => serde_json::json!({
                "kind": "reg_at",
                "idx": idx,
                "reg": reg,
            }),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn byte_lineage_value_on(
    app: &axum::Router,
    addr: u64,
    before_idx: usize,
    depth: usize,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
) -> anyhow::Result<serde_json::Value> {
    let mut seed = LineageSeed::AddrBefore { addr, before_idx };
    let mut steps = Vec::new();
    let mut seen = HashSet::new();
    let mut stop_reason = serde_json::json!({"kind": "depth_limit"});
    for step_idx in 0..depth {
        let seed_json = seed.to_json();
        let key = seed_json.to_string();
        if !seen.insert(key) {
            stop_reason = serde_json::json!({
                "kind": "cycle",
                "seed": seed_json,
            });
            break;
        }
        match seed {
            LineageSeed::AddrBefore { addr, before_idx } => {
                let write = last_write_of_addr_on(app, addr, before_idx).await?;
                let next_seed = write
                    .get("writer_idx")
                    .and_then(|v| v.as_u64())
                    .zip(write.get("src_reg").and_then(|v| v.as_str()))
                    .map(|(idx, reg)| LineageSeed::RegAt {
                        idx: idx as usize,
                        reg: reg.to_string(),
                    });
                let next_json = next_seed.as_ref().map(LineageSeed::to_json);
                steps.push(serde_json::json!({
                    "step": step_idx,
                    "seed": seed_json,
                    "kind": "last_write",
                    "write": write,
                    "next": next_json,
                }));
                if let Some(next) = next_seed {
                    seed = next;
                } else {
                    stop_reason = serde_json::json!({
                        "kind": "no_writer_source",
                    });
                    break;
                }
            }
            LineageSeed::RegAt { idx, ref reg } => {
                let backstep = vm_backstep_value_on(
                    app,
                    idx,
                    Some(reg.clone()),
                    context,
                    lookback,
                    max_writes,
                    regs.clone(),
                )
                .await?;
                let (next_seed, decision) = lineage_next_from_backstep(&backstep);
                let next_json = next_seed.as_ref().map(LineageSeed::to_json);
                steps.push(serde_json::json!({
                    "step": step_idx,
                    "seed": seed_json,
                    "kind": "reg_source",
                    "backstep": compact_lineage_backstep(&backstep),
                    "decision": decision,
                    "next": next_json,
                }));
                if let Some(next) = next_seed {
                    seed = next;
                } else {
                    stop_reason = serde_json::json!({
                        "kind": "terminal",
                        "decision": decision,
                    });
                    break;
                }
            }
        }
    }
    Ok(serde_json::json!({
        "status": "ready",
        "start": {
            "addr": format!("{addr:#x}"),
            "before_idx": before_idx,
        },
        "depth_requested": depth,
        "steps_returned": steps.len(),
        "stop_reason": stop_reason,
        "steps": steps,
    }))
}

async fn last_write_of_addr_on(
    app: &axum::Router,
    addr: u64,
    before_idx: usize,
) -> anyhow::Result<serde_json::Value> {
    let params = vec![
        ("addr", format!("{addr:#x}")),
        ("before_idx", before_idx.to_string()),
    ];
    route_get_json_value_on(app, route_path("/api/last-write-of-addr", &params)).await
}

fn lineage_next_from_backstep(
    backstep: &serde_json::Value,
) -> (Option<LineageSeed>, serde_json::Value) {
    let upstream_next = backstep
        .get("upstream")
        .and_then(|v| v.get("next"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if let Some(seed) = lineage_seed_from_next(&upstream_next) {
        return (
            Some(seed),
            serde_json::json!({
                "kind": "upstream_next",
                "next": upstream_next,
            }),
        );
    }
    let byte_nexts = backstep
        .get("upstream")
        .and_then(|v| v.get("byte_nexts"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if byte_nexts.len() == 1 {
        let next = byte_nexts[0].clone();
        if let Some(seed) = lineage_seed_from_next(&next) {
            return (
                Some(seed),
                serde_json::json!({
                    "kind": "single_byte_next",
                    "next": next,
                }),
            );
        }
    }
    if byte_nexts.len() > 1 {
        return (
            None,
            serde_json::json!({
                "kind": "branch_required",
                "reason": "multiple byte upstream candidates",
                "byte_nexts": byte_nexts,
            }),
        );
    }
    (
        None,
        serde_json::json!({
            "kind": "stop",
            "upstream_status": backstep.pointer("/upstream/status").cloned().unwrap_or(serde_json::Value::Null),
            "frontier": backstep.get("frontier").cloned().unwrap_or_else(|| serde_json::json!([])),
        }),
    )
}

fn lineage_seed_from_next(next: &serde_json::Value) -> Option<LineageSeed> {
    let idx = next.get("idx")?.as_u64()? as usize;
    let reg = next.get("reg")?.as_str()?.to_string();
    Some(LineageSeed::RegAt { idx, reg })
}

fn compact_lineage_backstep(backstep: &serde_json::Value) -> serde_json::Value {
    let upstream = backstep.get("upstream").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "status": backstep.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "idx": backstep.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "source_reg": backstep.get("source_reg").cloned().unwrap_or(serde_json::Value::Null),
        "source_value": backstep.get("source_value").cloned().unwrap_or(serde_json::Value::Null),
        "target": compact_vm_row(backstep.get("target")),
        "local_def": compact_vm_row(backstep.get("local_def")),
        "upstream": {
            "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
            "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "addr_hi": upstream.get("addr_hi").cloned().unwrap_or(serde_json::Value::Null),
            "next": upstream.get("next").cloned().unwrap_or(serde_json::Value::Null),
            "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
            "byte_nexts": upstream.get("byte_nexts").cloned().unwrap_or_else(|| serde_json::json!([])),
        },
        "frontier": backstep.get("frontier").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

fn byte_lineage_summary(lineage: &serde_json::Value) -> serde_json::Value {
    let chain = lineage
        .get("steps")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_lineage_summary_step)
        .collect::<Vec<_>>();
    let recognized_semantics = chain
        .iter()
        .filter_map(|step| {
            step.pointer("/local_def/formula/semantic")
                .cloned()
                .map(|semantic| {
                    serde_json::json!({
                        "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                        "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                        "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                        "semantic": semantic,
                    })
                })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": lineage.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": lineage.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": lineage.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": lineage.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "stop_reason": compact_lineage_stop_reason(lineage.get("stop_reason")),
        "recognized_semantics": recognized_semantics,
        "chain": chain,
    })
}

fn vm_backchain_summary(backchain: &serde_json::Value) -> serde_json::Value {
    let chain = backchain
        .get("chain")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_backchain_summary_step)
        .collect::<Vec<_>>();
    let recognized_semantics = chain
        .iter()
        .filter_map(|step| {
            step.pointer("/local_def/formula/semantic")
                .cloned()
                .map(|semantic| {
                    serde_json::json!({
                        "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                        "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                        "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                        "semantic": semantic,
                    })
                })
        })
        .collect::<Vec<_>>();
    let recognized_patterns = recognized_backchain_patterns(&chain);
    serde_json::json!({
        "status": backchain.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": backchain.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "follow_frontier": backchain.get("follow_frontier").cloned().unwrap_or(serde_json::Value::Null),
        "steps_requested": backchain.get("steps_requested").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": backchain.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "recognized_semantics": recognized_semantics,
        "recognized_patterns": recognized_patterns,
        "chain": chain,
    })
}

fn recognized_backchain_patterns(chain: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut patterns = Vec::new();
    for (idx, step) in chain.iter().enumerate() {
        let semantic = step.pointer("/local_def/formula/semantic");
        if semantic
            .and_then(|v| v.get("kind"))
            .and_then(|v| v.as_str())
            != Some("add_small_delta")
        {
            continue;
        }
        let Some(add_semantic) = semantic else {
            continue;
        };
        let Some(add_input) = add_semantic.get("input").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(mul_step) = chain.iter().skip(idx + 1).find(|candidate| {
            let semantic = candidate.pointer("/local_def/formula/semantic");
            semantic
                .and_then(|v| v.get("kind"))
                .and_then(|v| v.as_str())
                == Some("mul_mod64")
                && semantic
                    .and_then(|v| v.get("result"))
                    .and_then(|v| v.as_str())
                    == Some(add_input)
        }) else {
            continue;
        };
        let Some(mul_semantic) = mul_step.pointer("/local_def/formula/semantic") else {
            continue;
        };
        let multiplier_inverse = mul_semantic
            .get("rhs")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
            .and_then(odd_u64_inverse)
            .map(|value| serde_json::Value::String(format!("{value:#x}")))
            .unwrap_or(serde_json::Value::Null);
        patterns.push(serde_json::json!({
            "kind": "affine_mod64_state_step",
            "add_step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "mul_step": mul_step.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "state": add_semantic.get("result").cloned().unwrap_or(serde_json::Value::Null),
            "previous_state": mul_semantic.get("lhs").cloned().unwrap_or(serde_json::Value::Null),
            "multiplier": mul_semantic.get("rhs").cloned().unwrap_or(serde_json::Value::Null),
            "multiplier_inverse": multiplier_inverse,
            "delta": add_semantic.get("delta").cloned().unwrap_or(serde_json::Value::Null),
            "multiplier_odd": mul_semantic.get("rhs_odd").cloned().unwrap_or(serde_json::Value::Null),
            "expression": "state == (previous_state * multiplier + delta) mod 2^64",
        }));
    }
    patterns
}

fn odd_u64_inverse(value: u64) -> Option<u64> {
    if value & 1 == 0 {
        return None;
    }
    let mut inverse = value;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(value.wrapping_mul(inverse)));
    }
    Some(inverse)
}

fn compact_backchain_summary_step(step: &serde_json::Value) -> serde_json::Value {
    let compact = step
        .get("backstep")
        .map(compact_lineage_backstep)
        .unwrap_or(serde_json::Value::Null);
    let lineage_step = serde_json::json!({
        "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "kind": "reg_source",
        "backstep": compact,
        "decision": step.get("decision").cloned().unwrap_or(serde_json::Value::Null),
        "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
    });
    compact_lineage_summary_step(&lineage_step)
}

fn compact_lineage_summary_step(step: &serde_json::Value) -> serde_json::Value {
    match step.get("kind").and_then(|v| v.as_str()) {
        Some("last_write") => {
            let write = step.get("write").unwrap_or(&serde_json::Value::Null);
            serde_json::json!({
                "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                "kind": "last_write",
                "addr": write.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "writer_idx": write.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
                "func": write.get("func").cloned().unwrap_or(serde_json::Value::Null),
                "asm": write.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "src_reg": write.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
            })
        }
        Some("reg_source") => {
            let backstep = step.get("backstep").unwrap_or(&serde_json::Value::Null);
            let upstream = backstep.get("upstream").unwrap_or(&serde_json::Value::Null);
            serde_json::json!({
                "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                "kind": "reg_source",
                "idx": backstep.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": backstep.get("source_reg").cloned().unwrap_or(serde_json::Value::Null),
                "value": backstep.get("source_value").cloned().unwrap_or(serde_json::Value::Null),
                "target": compact_lineage_row_for_summary(backstep.get("target")),
                "local_def": compact_lineage_row_for_summary(backstep.get("local_def")),
                "upstream": {
                    "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
                    "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
                    "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                    "next": upstream.get("next").cloned().unwrap_or(serde_json::Value::Null),
                    "last_write": compact_lineage_last_write(upstream.get("last_write")),
                    "byte_nexts": compact_lineage_byte_nexts(upstream.get("byte_nexts")),
                },
                "frontier": backstep.get("frontier").cloned().unwrap_or_else(|| serde_json::json!([])),
                "decision": step.get("decision").cloned().unwrap_or(serde_json::Value::Null),
                "next": step.get("next").cloned().unwrap_or(serde_json::Value::Null),
            })
        }
        _ => step.clone(),
    }
}

fn compact_lineage_row_for_summary(row: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(row) = row else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "func": row.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "class": row.get("class").cloned().unwrap_or(serde_json::Value::Null),
        "def": row.get("def").cloned().unwrap_or(serde_json::Value::Null),
        "store_src": row.get("store_src").cloned().unwrap_or_else(|| serde_json::json!([])),
        "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "vm_slot": row.get("vm_slot").cloned().unwrap_or(serde_json::Value::Null),
        "formula": row.get("formula").cloned().unwrap_or(serde_json::Value::Null),
        "call_return": row.get("call_return").cloned().unwrap_or(serde_json::Value::Null),
    })
}

fn compact_lineage_last_write(write: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(write) = write else {
        return serde_json::Value::Null;
    };
    if write.is_null() {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "idx": write.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "func": write.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": write.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "dst_addr": write.get("dst_addr").cloned().unwrap_or(serde_json::Value::Null),
        "size": write.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "src_reg": write.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
        "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
    })
}

fn compact_lineage_byte_nexts(nexts: Option<&serde_json::Value>) -> serde_json::Value {
    let rows = nexts
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|next| {
            let offsets = next
                .get("offsets")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .take(8)
                        .cloned()
                        .collect::<Vec<serde_json::Value>>()
                })
                .unwrap_or_default();
            serde_json::json!({
                "idx": next.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": next.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": next.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "addr": next.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "offset": next.get("offset").cloned().unwrap_or(serde_json::Value::Null),
                "offsets": offsets,
                "reason": next.get("reason").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    serde_json::Value::Array(rows)
}

fn compact_lineage_stop_reason(reason: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(reason) = reason else {
        return serde_json::Value::Null;
    };
    let decision = reason.get("decision");
    serde_json::json!({
        "kind": reason.get("kind").cloned().unwrap_or(serde_json::Value::Null),
        "decision_kind": decision
            .and_then(|v| v.get("kind"))
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        "upstream_status": decision
            .and_then(|v| v.get("upstream_status"))
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        "frontier": decision
            .and_then(|v| v.get("frontier"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    })
}

struct TreeSeed {
    parent: Option<usize>,
    depth: usize,
    idx: usize,
    reg: Option<String>,
    via: serde_json::Value,
}

fn tree_seed_from_next(
    parent: usize,
    depth: usize,
    next: serde_json::Value,
    via: serde_json::Value,
) -> Option<TreeSeed> {
    Some(TreeSeed {
        parent: Some(parent),
        depth,
        idx: next.get("idx")?.as_u64()? as usize,
        reg: next.get("reg").and_then(|v| v.as_str()).map(str::to_string),
        via,
    })
}

fn frontier_nexts_from_step(step: &serde_json::Value) -> Vec<serde_json::Value> {
    step.get("frontier")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|frontier| {
            let reg = frontier.get("reg")?.as_str()?;
            if is_vm_infrastructure_reg(reg) {
                return None;
            }
            Some(serde_json::json!({
                "idx": frontier.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": frontier.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": frontier.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "reason": "frontier",
                "frontier": frontier,
            }))
        })
        .collect()
}

fn upstream_byte_nexts_from_step(step: &serde_json::Value) -> Vec<serde_json::Value> {
    step.get("upstream")
        .and_then(|v| v.get("byte_nexts"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

fn same_tree_next(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a.get("idx").and_then(|v| v.as_u64()) == b.get("idx").and_then(|v| v.as_u64())
        && a.get("reg").and_then(|v| v.as_str()) == b.get("reg").and_then(|v| v.as_str())
}

fn compact_backtree_node(
    id: usize,
    parent: Option<usize>,
    depth: usize,
    via: &serde_json::Value,
    backstep: &serde_json::Value,
    upstream_next: &serde_json::Value,
    upstream_byte_nexts: &[serde_json::Value],
    frontier_nexts: &[serde_json::Value],
) -> serde_json::Value {
    let upstream = backstep.get("upstream").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "id": id,
        "parent": parent,
        "depth": depth,
        "idx": backstep.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": backstep.get("source_reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": backstep.get("source_value").cloned().unwrap_or(serde_json::Value::Null),
        "via": via,
        "target": compact_vm_row(backstep.get("target")),
        "local_def": compact_vm_row(backstep.get("local_def")),
        "upstream": {
            "status": upstream.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "kind": upstream.get("kind").cloned().unwrap_or(serde_json::Value::Null),
            "addr": upstream.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "next": upstream_next,
            "byte_nexts": upstream_byte_nexts,
            "byte_writers": upstream.get("byte_writers").cloned().unwrap_or_else(|| serde_json::json!([])),
            "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
        },
        "frontier_nexts": frontier_nexts,
    })
}

fn compact_vm_row(row: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(row) = row else {
        return serde_json::Value::Null;
    };
    let formula = row_alu_formula(row);
    serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "pc": row.get("pc").cloned().unwrap_or(serde_json::Value::Null),
        "func": row.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "class": row.get("class").cloned().unwrap_or(serde_json::Value::Null),
        "def": row.get("def").cloned().unwrap_or(serde_json::Value::Null),
        "store_src": row.get("store_src").cloned().unwrap_or_else(|| serde_json::json!([])),
        "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "vm_slot": row.get("vm_slot").cloned().unwrap_or(serde_json::Value::Null),
        "formula": formula,
        "call_return": row.get("call_return").cloned().unwrap_or(serde_json::Value::Null),
    })
}

async fn vm_backstep_value_on(
    app: &axum::Router,
    idx: usize,
    reg: Option<String>,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
) -> anyhow::Result<serde_json::Value> {
    let start = idx.saturating_sub(context);
    let count = context.saturating_add(3);
    let params = vec![
        ("start", start.to_string()),
        ("count", count.to_string()),
        ("regs", regs),
    ];
    let response = route_get_json_value_on(app, route_path("/api/records", &params)).await?;
    let records = response
        .get("records")
        .and_then(|v| v.as_array())
        .context("/api/records response missing records[]")?;
    let inferred_base = records.iter().find_map(|rec| record_reg_u64(rec, "x21"));
    let rows = records
        .iter()
        .enumerate()
        .map(|(pos, rec)| vm_row_from_record(rec, records.get(pos + 1), inferred_base))
        .collect::<Vec<_>>();
    let target_pos = rows
        .iter()
        .position(|row| row.get("idx").and_then(|v| v.as_u64()) == Some(idx as u64))
        .with_context(|| format!("idx {idx} not present in local record window"))?;
    let target_row = &rows[target_pos];
    let target_record = &records[target_pos];
    let source_reg = reg.or_else(|| {
        target_row
            .get("store_src")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .and_then(|item| item.get("reg"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    let Some(source_reg) = source_reg else {
        return Ok(serde_json::json!({
            "status": "no_source_reg",
            "idx": idx,
            "target": target_row,
        }));
    };
    let source_key = register_value_key(&source_reg);
    let target_defines_source = row_defines_reg(target_row, &source_key);
    let local_def = if target_defines_source {
        row_for_def_reg(target_row, &source_key)
    } else if let Some(call_return) =
        call_return_def_from_previous_call(&rows, records, target_pos, &source_key, target_record)
    {
        Some(call_return)
    } else {
        rows[..target_pos]
            .iter()
            .rev()
            .find_map(|row| row_for_def_reg(row, &source_key))
    };
    let upstream = if let Some(def_row) = local_def.as_ref() {
        upstream_writer_for_def_on(app, def_row, lookback, max_writes).await?
    } else {
        serde_json::json!({
            "status": "no_local_def",
            "searched_context": context,
        })
    };
    let frontier = local_def
        .as_ref()
        .map(backstep_frontier_from_def)
        .unwrap_or_default();
    Ok(serde_json::json!({
        "status": "ready",
        "idx": idx,
        "source_reg": source_reg,
        "source_value": if target_defines_source {
            row_def_entry_for_key(target_row, &source_key)
                .and_then(|def| def.get("value_after").cloned())
                .unwrap_or(serde_json::Value::Null)
        } else {
            record_reg_value(target_record, &source_key).cloned().unwrap_or(serde_json::Value::Null)
        },
        "target": target_row,
        "local_def": local_def,
        "upstream": upstream,
        "frontier": frontier,
    }))
}

fn row_def_reg_key(row: &serde_json::Value) -> Option<String> {
    row.get("def")
        .and_then(|v| v.get("reg"))
        .and_then(|v| v.as_str())
        .map(register_value_key)
}

fn call_return_def_from_previous_call(
    rows: &[serde_json::Value],
    records: &[serde_json::Value],
    target_pos: usize,
    source_key: &str,
    target_record: &serde_json::Value,
) -> Option<serde_json::Value> {
    if source_key != "x0" || target_pos == 0 {
        return None;
    }
    let call_row = rows.get(target_pos - 1)?;
    let call_record = records.get(target_pos - 1)?;
    let asm = call_row.get("asm").and_then(|v| v.as_str())?.trim();
    if !is_call_asm(asm) {
        return None;
    }
    let target_reg = indirect_call_target_reg(asm);
    let target_value = target_reg
        .as_deref()
        .and_then(|reg| record_reg_value(call_record, reg))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let args = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        .into_iter()
        .map(|reg| {
            serde_json::json!({
                "reg": reg,
                "value": record_reg_value(call_record, reg).cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let mut src = args.clone();
    if let Some(reg) = target_reg.as_deref() {
        src.push(serde_json::json!({
            "reg": reg,
            "role": "call_target",
            "value": target_value.clone(),
        }));
    }
    let mut row = call_row.clone();
    if let Some(obj) = row.as_object_mut() {
        obj.insert("class".to_string(), serde_json::json!("call-return"));
        obj.insert(
            "def".to_string(),
            serde_json::json!({
                "reg": "x0",
                "src": src,
                "value_after": record_reg_value(target_record, "x0").cloned().unwrap_or(serde_json::Value::Null),
            }),
        );
        obj.insert(
            "call_return".to_string(),
            serde_json::json!({
                "call_idx": call_row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "call_pc": call_row.get("pc").cloned().unwrap_or(serde_json::Value::Null),
                "asm": asm,
                "return_reg": "x0",
                "return_value": record_reg_value(target_record, "x0").cloned().unwrap_or(serde_json::Value::Null),
                "target_reg": target_reg,
                "target_value": target_value,
                "args": args,
                "note": "x0 changed across a call; do not attribute it to pre-call local definitions",
            }),
        );
    }
    Some(row)
}

fn is_call_asm(asm: &str) -> bool {
    let mnemonic = asm.split_whitespace().next().unwrap_or("");
    matches!(mnemonic, "bl" | "blr")
}

fn indirect_call_target_reg(asm: &str) -> Option<String> {
    let mut parts = asm.trim().splitn(2, char::is_whitespace);
    if parts.next()? != "blr" {
        return None;
    }
    parts
        .next()
        .and_then(|operands| split_operands(operands).first().cloned())
        .and_then(|op| first_register_token(&op))
}

fn row_defines_reg(row: &serde_json::Value, reg_key: &str) -> bool {
    row_def_entry_for_key(row, reg_key).is_some()
}

fn row_for_def_reg(row: &serde_json::Value, reg_key: &str) -> Option<serde_json::Value> {
    let def = row_def_entry_for_key(row, reg_key)?;
    let mut out = row.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("def".to_string(), def.clone());
        if let Some(mem_addr) = def.get("mem_addr") {
            obj.insert("mem_addr".to_string(), mem_addr.clone());
        }
    }
    Some(out)
}

fn row_def_entry_for_key(row: &serde_json::Value, reg_key: &str) -> Option<serde_json::Value> {
    row.get("defs")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .find(|def| {
            def.get("reg")
                .and_then(|v| v.as_str())
                .map(register_value_key)
                .as_deref()
                == Some(reg_key)
        })
        .cloned()
        .or_else(|| {
            (row_def_reg_key(row).as_deref() == Some(reg_key))
                .then(|| row.get("def").cloned())
                .flatten()
        })
}

fn backstep_frontier_from_def(def_row: &serde_json::Value) -> Vec<serde_json::Value> {
    let idx = def_row
        .get("idx")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    def_row
        .get("def")
        .and_then(|v| v.get("src"))
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|src| {
            let reg = src.get("reg")?.clone();
            Some(serde_json::json!({
                "idx": idx,
                "reg": reg,
                "value": src.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "reason": "local_def_source_reg",
            }))
        })
        .collect()
}

fn vm_row_from_record(
    rec: &serde_json::Value,
    next: Option<&serde_json::Value>,
    inferred_base: Option<u64>,
) -> serde_json::Value {
    let asm = rec.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let class = classify_vm_asm(asm);
    let vm_ip = record_reg_u64(rec, "x21");
    let vm_off = vm_ip.and_then(|ip| inferred_base.map(|base| ip.wrapping_sub(base)));
    let vm_slot = vm_slot_from_asm(asm, rec);
    let mem_addr = mem_addr_from_asm(asm, rec);
    let defs = def_entries_from_asm(asm, rec, next, mem_addr);
    let def = defs.first().cloned();
    let store_src = store_source_regs_from_asm(asm)
        .into_iter()
        .map(|reg| {
            serde_json::json!({
                "reg": reg,
                "value": record_reg_value(rec, &reg).cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "idx": rec.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "pc": rec.get("pc").cloned().unwrap_or(serde_json::Value::Null),
        "func": rec.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "class": class,
        "def": def,
        "defs": defs,
        "store_src": store_src,
        "vm_ip": vm_ip.map(|v| format!("{v:#x}")),
        "vm_off": vm_off.map(|v| format!("{v:#x}")),
        "vm_slot": vm_slot,
        "mem_addr": mem_addr.map(|v| format!("{v:#x}")),
        "regs": rec.get("regs").cloned().unwrap_or_else(|| serde_json::json!({})),
    })
}

fn def_entries_from_asm(
    asm: &str,
    rec: &serde_json::Value,
    next: Option<&serde_json::Value>,
    mem_addr: Option<u64>,
) -> Vec<serde_json::Value> {
    if let Some(dest_regs) = pair_load_dest_regs_from_asm(asm) {
        let src = memory_source_regs_from_asm(asm)
            .into_iter()
            .map(|src_reg| {
                serde_json::json!({
                    "reg": src_reg,
                    "value": record_reg_value(rec, &src_reg).cloned().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>();
        let mut offset = 0u64;
        return dest_regs
            .into_iter()
            .map(|reg| {
                let width = register_load_width(&reg);
                let entry = serde_json::json!({
                    "reg": reg.clone(),
                    "src": src.clone(),
                    "value_after": next.and_then(|next| record_reg_value(next, &reg).cloned()).unwrap_or(serde_json::Value::Null),
                    "mem_addr": mem_addr.map(|addr| format!("{:#x}", addr.wrapping_add(offset))),
                });
                offset = offset.saturating_add(width);
                entry
            })
            .collect();
    }
    def_reg_from_asm(asm)
        .map(|reg| {
            let src = def_source_regs_from_asm(asm)
                .into_iter()
                .map(|src_reg| {
                    serde_json::json!({
                        "reg": src_reg,
                        "value": record_reg_value(rec, &src_reg).cloned().unwrap_or(serde_json::Value::Null),
                    })
                })
                .collect::<Vec<_>>();
            vec![serde_json::json!({
                "reg": reg.clone(),
                "src": src,
                "value_after": next.and_then(|next| record_reg_value(next, &reg).cloned()).unwrap_or(serde_json::Value::Null),
                "mem_addr": mem_addr.map(|addr| format!("{addr:#x}")),
            })]
        })
        .unwrap_or_default()
}

fn vm_ops_from_rows(rows: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut groups: Vec<Vec<serde_json::Value>> = Vec::new();
    let mut current_key: Option<String> = None;
    for row in rows {
        let key = row
            .get("vm_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if current_key.as_deref() != Some(key.as_str()) {
            groups.push(Vec::new());
            current_key = Some(key);
        }
        if let Some(group) = groups.last_mut() {
            group.push(row.clone());
        }
    }
    groups
        .into_iter()
        .filter(|group| !group.is_empty())
        .map(|group| vm_op_from_group(&group))
        .collect()
}

fn vm_op_from_group(group: &[serde_json::Value]) -> serde_json::Value {
    let first = &group[0];
    let last = group.last().unwrap_or(first);
    let mut class_counts = BTreeMap::<String, usize>::new();
    for row in group {
        let class = row
            .get("class")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        *class_counts.entry(class).or_default() += 1;
    }
    let bytecode_reads = group
        .iter()
        .filter_map(bytecode_read_summary)
        .collect::<Vec<_>>();
    let vm_slot_reads = group
        .iter()
        .filter(|row| row.get("class").and_then(|v| v.as_str()) == Some("vm-reg-load"))
        .filter_map(vm_slot_access_summary)
        .collect::<Vec<_>>();
    let vm_slot_writes = group
        .iter()
        .filter(|row| row.get("class").and_then(|v| v.as_str()) == Some("vm-reg-store"))
        .filter_map(vm_slot_access_summary)
        .collect::<Vec<_>>();
    let small_byte_loads = group
        .iter()
        .filter_map(byte_load_summary)
        .collect::<Vec<_>>();
    let memory_stores = group
        .iter()
        .filter(|row| {
            matches!(
                row.get("class").and_then(|v| v.as_str()),
                Some("mem-store" | "byte-store")
            )
        })
        .map(memory_access_summary)
        .collect::<Vec<_>>();
    let alu_formulas = group.iter().filter_map(row_alu_formula).collect::<Vec<_>>();
    serde_json::json!({
        "idx_start": first.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "idx_end": last
            .get("idx")
            .and_then(|v| v.as_u64())
            .map(|idx| serde_json::json!(idx + 1))
            .unwrap_or(serde_json::Value::Null),
        "vm_ip": first.get("vm_ip").cloned().unwrap_or(serde_json::Value::Null),
        "vm_off": first.get("vm_off").cloned().unwrap_or(serde_json::Value::Null),
        "rows": group.len(),
        "class_counts": class_counts,
        "bytecode_reads": bytecode_reads,
        "vm_slot_reads": vm_slot_reads,
        "vm_slot_writes": vm_slot_writes,
        "small_byte_loads": small_byte_loads,
        "memory_stores": memory_stores,
        "alu_formulas": alu_formulas,
        "dispatches": group
            .iter()
            .filter(|row| row.get("class").and_then(|v| v.as_str()) == Some("dispatch-branch"))
            .map(|row| {
                serde_json::json!({
                    "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn bytecode_read_summary(row: &serde_json::Value) -> Option<serde_json::Value> {
    if row.get("class").and_then(|v| v.as_str()) != Some("bytecode-read") {
        return None;
    }
    let asm = row.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let width = memory_access_width(asm).min(8);
    let value = row
        .pointer("/def/value_after")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let value_u64 = value
        .as_str()
        .and_then(parse_u64_str)
        .or_else(|| value.as_u64());
    let vm_ip = row
        .get("vm_ip")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str);
    let mem_addr = row
        .get("mem_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str);
    let offset = vm_ip.zip(mem_addr).map(|(ip, addr)| addr.wrapping_sub(ip));
    Some(serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "reg": row.pointer("/def/reg").cloned().unwrap_or(serde_json::Value::Null),
        "offset": offset.map(|v| format!("{v:#x}")),
        "width": width,
        "value": value,
        "bytes_le_hex": value_u64.map(|v| {
            let bytes = v.to_le_bytes();
            bytes_to_hex(&bytes[..width as usize])
        }),
    }))
}

fn vm_slot_access_summary(row: &serde_json::Value) -> Option<serde_json::Value> {
    let slot = row.get("vm_slot")?;
    let class = row.get("class").and_then(|v| v.as_str()).unwrap_or("");
    let (op, reg, value) = if class == "vm-reg-load" {
        (
            "load",
            row.pointer("/def/reg")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            row.pointer("/def/value_after")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
    } else if class == "vm-reg-store" {
        let src = row
            .get("store_src")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first());
        (
            "store",
            src.and_then(|v| v.get("reg"))
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            src.and_then(|v| v.get("value"))
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        )
    } else {
        return None;
    };
    Some(serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "op": op,
        "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "slot": slot.get("slot").cloned().unwrap_or(serde_json::Value::Null),
        "index_reg": slot.get("index_reg").cloned().unwrap_or(serde_json::Value::Null),
        "index_value": slot.get("index_value").cloned().unwrap_or(serde_json::Value::Null),
        "reg": reg,
        "value": value,
        "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
    }))
}

fn byte_load_summary(row: &serde_json::Value) -> Option<serde_json::Value> {
    if row.get("class").and_then(|v| v.as_str()) != Some("byte-load") {
        return None;
    }
    let value = row
        .pointer("/def/value_after")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    (value <= 0xff).then(|| {
        serde_json::json!({
            "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
            "reg": row.pointer("/def/reg").cloned().unwrap_or(serde_json::Value::Null),
            "value": format!("{value:#x}"),
            "byte_hex": format!("{:02x}", value as u8),
            "ascii": printable_ascii_char(value as u8),
            "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        })
    })
}

fn memory_access_summary(row: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "class": row.get("class").cloned().unwrap_or(serde_json::Value::Null),
        "asm": row.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "mem_addr": row.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "store_src": row.get("store_src").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

fn row_alu_formula(row: &serde_json::Value) -> Option<serde_json::Value> {
    if row.get("class").and_then(|v| v.as_str()) != Some("alu") {
        return None;
    }
    let asm = row.get("asm").and_then(|v| v.as_str())?;
    let result = row.pointer("/def/value_after").and_then(|v| v.as_str())?;
    let operands = row
        .pointer("/def/src")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let operand_values = operands
        .iter()
        .filter_map(|operand| operand.get("value").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let expression = alu_expression_from_asm(asm, result, &operand_values)?;
    let op = asm
        .split_whitespace()
        .next()
        .map(|mnemonic| mnemonic.to_ascii_lowercase())
        .unwrap_or_default();
    let mut formula = serde_json::json!({
        "idx": row.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "reg": row.pointer("/def/reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": result,
        "op": op,
        "expression": expression,
        "operands": operands,
    });
    if let Some(semantic) = recognize_alu_semantic(asm, result, &operand_values) {
        if let Some(obj) = formula.as_object_mut() {
            obj.insert("semantic".to_string(), semantic);
        }
    }
    Some(formula)
}

async fn upstream_writer_for_def_on(
    app: &axum::Router,
    def_row: &serde_json::Value,
    lookback: usize,
    max_writes: usize,
) -> anyhow::Result<serde_json::Value> {
    let class = def_row.get("class").and_then(|v| v.as_str()).unwrap_or("");
    let idx = def_row.get("idx").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    if class == "call-return" {
        return Ok(serde_json::json!({
            "status": "call_return_boundary",
            "reason": "register value came from a call return; inspect call_return target and args",
            "call_return": def_row.get("call_return").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    let mut kind = None;
    let mut addr = None;
    let mut size = 1u64;
    if class == "vm-reg-load" {
        kind = Some("vm_slot_last_write");
        addr = def_row
            .get("mem_addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str);
        size = 8;
    } else if matches!(class, "mem-load" | "byte-load") {
        kind = Some("memory_last_write");
        addr = def_row
            .get("mem_addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str);
        size = memory_access_width(def_row.get("asm").and_then(|v| v.as_str()).unwrap_or(""));
    }
    let Some(kind) = kind else {
        return Ok(serde_json::json!({
            "status": "not_memory_backed",
            "reason": "local def is not a VM slot load or memory load",
        }));
    };
    let Some(addr) = addr else {
        return Ok(serde_json::json!({
            "status": "missing_address",
            "kind": kind,
        }));
    };
    let idx_lo = idx.saturating_sub(lookback);
    let idx_hi = idx;
    let addr_hi = addr.saturating_add(size);
    let params = vec![
        ("idx_lo", idx_lo.to_string()),
        ("idx_hi", idx_hi.to_string()),
        ("addr_lo", format!("{addr:#x}")),
        ("addr_hi", format!("{addr_hi:#x}")),
        ("max", max_writes.to_string()),
    ];
    let response =
        route_get_json_value_on(app, route_path("/api/mem-writes-in-range", &params)).await?;
    let writes = response
        .get("writes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let range_truncated = response
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(writes.len() >= max_writes);
    let byte_writers = if range_truncated {
        exact_byte_writers_for_load_on(app, addr, size, idx).await?
    } else {
        byte_writers_from_range_writes(addr, size, &writes)
    };
    let byte_nexts = dedupe_byte_nexts(&byte_writers);
    let last_write = if range_truncated {
        byte_writers
            .first()
            .and_then(|writer| writer.get("last_write").cloned())
    } else {
        writes.last().cloned()
    };
    let writes_tail = writes
        .iter()
        .rev()
        .take(16)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "status": if last_write.is_some() { "ready" } else { "not_found" },
        "kind": kind,
        "addr": format!("{addr:#x}"),
        "addr_hi": format!("{addr_hi:#x}"),
        "idx_lo": idx_lo,
        "idx_hi": idx_hi,
        "returned": writes.len(),
        "maybe_truncated": range_truncated,
        "last_write": last_write,
        "writes_tail": writes_tail,
        "byte_writers": byte_writers,
        "byte_nexts": byte_nexts,
        "next": last_write.as_ref().and_then(|write| {
            Some(serde_json::json!({
                "idx": write.get("idx")?,
                "reg": write.get("src_reg")?,
                "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            }))
        }),
    }))
}

async fn exact_byte_writers_for_load_on(
    app: &axum::Router,
    addr: u64,
    size: u64,
    before_idx: usize,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for offset in 0..size {
        let byte_addr = addr.saturating_add(offset);
        let params = vec![
            ("addr", format!("{byte_addr:#x}")),
            ("before_idx", before_idx.to_string()),
        ];
        let response =
            route_get_json_value_on(app, route_path("/api/last-write-of-addr", &params)).await?;
        let last_write = if response.get("status").and_then(|v| v.as_str()) == Some("found") {
            Some(serde_json::json!({
                "idx": response.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
                "pc": response.get("writer_pc").cloned().unwrap_or(serde_json::Value::Null),
                "rel": response.get("rel").cloned().unwrap_or(serde_json::Value::Null),
                "func": response.get("func").cloned().unwrap_or(serde_json::Value::Null),
                "asm": response.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "dst_addr": format!("{byte_addr:#x}"),
                "size": 1,
                "src_reg": response.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": response.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            }))
        } else {
            None
        };
        out.push(byte_writer_entry(offset, byte_addr, last_write));
    }
    Ok(out)
}

fn byte_writers_from_range_writes(
    addr: u64,
    size: u64,
    writes: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for offset in 0..size {
        let byte_addr = addr.saturating_add(offset);
        let last_write = writes
            .iter()
            .filter(|write| mem_write_touches_addr(write, byte_addr))
            .last()
            .cloned();
        out.push(byte_writer_entry(offset, byte_addr, last_write));
    }
    out
}

fn byte_writer_entry(
    offset: u64,
    byte_addr: u64,
    last_write: Option<serde_json::Value>,
) -> serde_json::Value {
    let next = last_write.as_ref().and_then(|write| {
        Some(serde_json::json!({
            "idx": write.get("idx")?,
            "reg": write.get("src_reg")?,
            "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            "reason": "memory_load_byte",
            "offset": offset,
            "addr": format!("{byte_addr:#x}"),
        }))
    });
    serde_json::json!({
        "offset": offset,
        "addr": format!("{byte_addr:#x}"),
        "status": if last_write.is_some() { "ready" } else { "not_found" },
        "last_write": last_write,
        "next": next,
    })
}

fn dedupe_byte_nexts(byte_writers: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    for writer in byte_writers {
        let Some(next) = writer.get("next") else {
            continue;
        };
        let Some(idx) = next.get("idx").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(reg) = next.get("reg").and_then(|v| v.as_str()) else {
            continue;
        };
        let offset = writer
            .get("offset")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let addr = writer
            .get("addr")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if let Some(existing) = out.iter_mut().find(|item| {
            item.get("idx").and_then(|v| v.as_u64()) == Some(idx)
                && item.get("reg").and_then(|v| v.as_str()) == Some(reg)
        }) {
            if let Some(offsets) = existing.get_mut("offsets").and_then(|v| v.as_array_mut()) {
                offsets.push(offset);
            }
            if let Some(addrs) = existing.get_mut("addrs").and_then(|v| v.as_array_mut()) {
                addrs.push(addr);
            }
            continue;
        }
        let mut item = next.clone();
        if let Some(obj) = item.as_object_mut() {
            obj.insert("offsets".to_string(), serde_json::json!([offset]));
            obj.insert("addrs".to_string(), serde_json::json!([addr]));
        }
        out.push(item);
    }
    out
}

fn mem_write_touches_addr(write: &serde_json::Value, addr: u64) -> bool {
    let Some(start) = write
        .get("dst_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
    else {
        return false;
    };
    let size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
    addr >= start && addr < start.saturating_add(size)
}

fn vm_backtree_highlights(nodes: &[serde_json::Value]) -> serde_json::Value {
    let word_loads = nodes
        .iter()
        .filter_map(highlight_word_load)
        .collect::<Vec<_>>();
    let table_lookups = nodes
        .iter()
        .filter_map(highlight_table_lookup)
        .collect::<Vec<_>>();
    let alu_formulas = nodes
        .iter()
        .filter_map(highlight_alu_formula)
        .collect::<Vec<_>>();
    serde_json::json!({
        "word_loads": word_loads,
        "table_lookups": table_lookups,
        "alu_formulas": alu_formulas,
    })
}

fn highlight_word_load(node: &serde_json::Value) -> Option<serde_json::Value> {
    let local = node.get("local_def")?;
    let asm = local.get("asm")?.as_str()?;
    if !asm.trim_start().starts_with("ldr w") {
        return None;
    }
    let byte_nexts = node
        .get("upstream")?
        .get("byte_nexts")?
        .as_array()
        .filter(|items| items.len() > 1)?;
    let mut byte_sources = Vec::new();
    for next in byte_nexts {
        let offsets = next
            .get("offsets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_else(|| {
                vec![next
                    .get("offset")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null)]
            });
        for offset_value in offsets {
            let offset = offset_value.as_u64().unwrap_or(0);
            let src_value = next
                .get("src_value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let byte = src_value.map(|v| (v & 0xff) as u8);
            byte_sources.push(serde_json::json!({
                "offset": offset,
                "addr": next.get("addr").cloned().unwrap_or(serde_json::Value::Null),
                "idx": next.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": next.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "src_value": next.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "byte_hex": byte.map(|b| format!("{b:02x}")),
                "ascii": byte.and_then(printable_ascii_char),
            }));
        }
    }
    byte_sources.sort_by_key(|source| {
        source
            .get("offset")
            .and_then(|v| v.as_u64())
            .unwrap_or(u64::MAX)
    });
    let bytes = byte_sources
        .iter()
        .filter_map(|source| {
            source
                .get("byte_hex")
                .and_then(|v| v.as_str())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        })
        .collect::<Vec<_>>();
    Some(serde_json::json!({
        "node": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": node.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "bytes_hex": bytes_to_hex(&bytes),
        "ascii": ascii_preview(&bytes),
        "byte_sources": byte_sources,
    }))
}

fn highlight_table_lookup(node: &serde_json::Value) -> Option<serde_json::Value> {
    let local = node.get("local_def")?;
    if local.get("class").and_then(|v| v.as_str()) != Some("byte-load") {
        return None;
    }
    let asm = local.get("asm")?.as_str()?;
    if !asm.contains('[') {
        return None;
    }
    let frontier_nexts = node.get("frontier_nexts").and_then(|v| v.as_array())?;
    let index = frontier_nexts
        .iter()
        .filter_map(|next| {
            let value = next
                .get("src_value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)?;
            (value <= 0x3f).then_some((next, value))
        })
        .min_by_key(|(_, value)| *value)?;
    let base = frontier_nexts
        .iter()
        .filter_map(|next| {
            let value = next
                .get("src_value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str)?;
            (value > 0x1000).then_some((next, value))
        })
        .next();
    let char_value = node
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
        .map(|v| (v & 0xff) as u8);
    if char_value != Some(base64_char_for_index(index.1)?) {
        return None;
    }
    Some(serde_json::json!({
        "node": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "char_hex": char_value.map(|b| format!("{b:02x}")),
        "char": char_value.and_then(printable_ascii_char),
        "index_reg": index.0.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "index_value": format!("{:#x}", index.1),
        "base_reg": base.map(|(next, _)| next.get("reg").cloned().unwrap_or(serde_json::Value::Null)),
        "base_value": base.map(|(_, value)| format!("{value:#x}")),
    }))
}

fn base64_char_for_index(index: u64) -> Option<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ALPHABET.get(index as usize).copied()
}

fn highlight_alu_formula(node: &serde_json::Value) -> Option<serde_json::Value> {
    let local = node.get("local_def")?;
    if local.get("class").and_then(|v| v.as_str()) != Some("alu") {
        return None;
    }
    let asm = local.get("asm")?.as_str()?;
    let mnemonic = asm.split_whitespace().next()?.to_ascii_lowercase();
    if !matches!(
        mnemonic.as_str(),
        "orr" | "and" | "lsl" | "lsr" | "add" | "sub" | "ubfx" | "udiv"
    ) {
        return None;
    }
    let operands = local
        .get("def")
        .and_then(|v| v.get("src"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let operand_values = operands
        .iter()
        .filter_map(|operand| operand.get("value").and_then(|v| v.as_str()))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let result = node
        .get("value")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            local
                .get("def")
                .and_then(|v| v.get("value_after"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })?;
    let expression = alu_expression_from_asm(asm, &result, &operand_values)?;
    let mut formula = serde_json::json!({
        "node": node.get("id").cloned().unwrap_or(serde_json::Value::Null),
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": result,
        "asm": asm,
        "op": mnemonic,
        "expression": expression,
        "operands": operands,
    });
    if let Some(semantic) = recognize_alu_semantic(asm, &result, &operand_values) {
        if let Some(obj) = formula.as_object_mut() {
            obj.insert("semantic".to_string(), semantic);
        }
    }
    Some(formula)
}

fn alu_expression_from_asm(asm: &str, result: &str, values: &[String]) -> Option<String> {
    let mut parts = asm.trim().splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    let operands = parts.next().map(split_operands).unwrap_or_default();
    match mnemonic.as_str() {
        "orr" | "and" | "add" | "sub" | "mul" if values.len() >= 2 => {
            if mnemonic == "mul" {
                return Some(format!(
                    "{result} = ({} * {}) mod 2^64",
                    values[0], values[1]
                ));
            }
            let op = match mnemonic.as_str() {
                "orr" => "|",
                "and" => "&",
                "add" => "+",
                "sub" => "-",
                _ => unreachable!(),
            };
            Some(format!("{result} = {} {op} {}", values[0], values[1]))
        }
        "lsl" | "lsr" if !values.is_empty() => {
            let op = if mnemonic == "lsl" { "<<" } else { ">>" };
            let shift = values
                .get(1)
                .cloned()
                .or_else(|| operands.get(2).and_then(|op| immediate_operand_value(op)))
                .unwrap_or_else(|| "?".to_string());
            Some(format!("{result} = {} {op} {shift}", values[0]))
        }
        "ubfx" if !values.is_empty() => {
            let lsb = operands
                .get(2)
                .and_then(|op| immediate_operand_value(op))
                .unwrap_or_else(|| "?".to_string());
            let width = operands
                .get(3)
                .and_then(|op| immediate_operand_value(op))
                .unwrap_or_else(|| "?".to_string());
            Some(format!("{result} = ubfx({}, {lsb}, {width})", values[0]))
        }
        "udiv" if values.len() >= 2 => Some(format!("{result} = {} / {}", values[0], values[1])),
        _ => None,
    }
}

fn recognize_alu_semantic(asm: &str, result: &str, values: &[String]) -> Option<serde_json::Value> {
    let mnemonic = asm.split_whitespace().next()?.to_ascii_lowercase();
    if values.len() < 2 {
        return None;
    }
    let result = parse_u64_str(result)?;
    let lhs = parse_u64_str(&values[0])?;
    let rhs = parse_u64_str(&values[1])?;
    match mnemonic.as_str() {
        "add" => mod255_fold_semantic(lhs, rhs, result)
            .or_else(|| mod255_fold_semantic(rhs, lhs, result))
            .or_else(|| add_small_delta_semantic(lhs, rhs, result))
            .or_else(|| add_small_delta_semantic(rhs, lhs, result)),
        "mul" => mul_mod64_semantic(lhs, rhs, result),
        _ => None,
    }
}

fn mod255_fold_semantic(input: u64, quotient: u64, result: u64) -> Option<serde_json::Value> {
    if quotient != input / 0xff {
        return None;
    }
    let output_byte = (result & 0xff) as u8;
    let remainder = (input % 0xff) as u8;
    if output_byte != remainder {
        return None;
    }
    Some(serde_json::json!({
        "kind": "mod255_low_byte",
        "input": format!("{input:#x}"),
        "quotient": format!("{quotient:#x}"),
        "divisor": "0xff",
        "result": format!("{result:#x}"),
        "output_byte": format!("{output_byte:#x}"),
        "expression": "(input + input / 0xff) & 0xff == input % 0xff",
    }))
}

fn add_small_delta_semantic(input: u64, delta: u64, result: u64) -> Option<serde_json::Value> {
    if delta > 0xfff || input <= 0xfff || input.wrapping_add(delta) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "add_small_delta",
        "input": format!("{input:#x}"),
        "delta": format!("{delta:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == input + small_delta",
    }))
}

fn mul_mod64_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    if lhs.wrapping_mul(rhs) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "mul_mod64",
        "lhs": format!("{lhs:#x}"),
        "rhs": format!("{rhs:#x}"),
        "result": format!("{result:#x}"),
        "modulus": "2^64",
        "lhs_odd": lhs & 1 == 1,
        "rhs_odd": rhs & 1 == 1,
        "expression": "result == (lhs * rhs) mod 2^64",
    }))
}

fn immediate_operand_value(op: &str) -> Option<String> {
    let trimmed = op.trim().trim_start_matches('#');
    if trimmed.is_empty() {
        return None;
    }
    parse_u64_str(trimmed)
        .map(|value| format!("{value:#x}"))
        .or_else(|| Some(trimmed.to_string()))
}

fn printable_ascii_char(byte: u8) -> Option<String> {
    byte.is_ascii_graphic()
        .then(|| char::from(byte).to_string())
        .or_else(|| (byte == b' ').then(|| " ".to_string()))
}

fn ascii_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&byte| printable_ascii_char(byte).unwrap_or_else(|| ".".to_string()))
        .collect()
}

fn classify_vm_asm(asm: &str) -> &'static str {
    let asm = asm.trim().to_ascii_lowercase();
    if asm.starts_with("br ") {
        return "dispatch-branch";
    }
    if asm.starts_with("blr ") {
        return "call-indirect";
    }
    if asm.contains("[x23,") {
        return "dispatch-table-load";
    }
    if asm.contains("[x21") {
        return "bytecode-read";
    }
    if asm.contains("[x25,") {
        if asm.starts_with("ldr") {
            return "vm-reg-load";
        }
        if asm.starts_with("str") {
            return "vm-reg-store";
        }
    }
    if asm.starts_with("strb ") {
        return "byte-store";
    }
    if asm.starts_with("ldrb ") {
        return "byte-load";
    }
    if asm.starts_with("str ") || asm.starts_with("stp ") {
        return "mem-store";
    }
    if asm.starts_with("ldr ")
        || asm.starts_with("ldrsw ")
        || asm.starts_with("ldp ")
        || asm.starts_with("ldnp ")
        || asm.starts_with("ldpsw ")
    {
        return "mem-load";
    }
    if is_alu_mnemonic(asm.split_whitespace().next().unwrap_or("")) {
        return "alu";
    }
    if asm.starts_with("b.") || asm == "ret" {
        return "control";
    }
    "other"
}

fn is_alu_mnemonic(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "adc"
            | "adcs"
            | "add"
            | "adds"
            | "adr"
            | "adrp"
            | "and"
            | "ands"
            | "asr"
            | "bic"
            | "bics"
            | "cinc"
            | "cinv"
            | "cneg"
            | "csel"
            | "cset"
            | "csetm"
            | "csinc"
            | "csinv"
            | "csneg"
            | "eon"
            | "eor"
            | "extr"
            | "lsl"
            | "lsr"
            | "madd"
            | "mov"
            | "movk"
            | "movn"
            | "movz"
            | "msub"
            | "mul"
            | "mvn"
            | "neg"
            | "negs"
            | "orn"
            | "orr"
            | "ror"
            | "sbc"
            | "sbcs"
            | "sbfiz"
            | "sbfx"
            | "sdiv"
            | "smaddl"
            | "smull"
            | "smsubl"
            | "sub"
            | "subs"
            | "sxtb"
            | "sxth"
            | "sxtw"
            | "ubfiz"
            | "ubfx"
            | "udiv"
            | "umaddl"
            | "umull"
            | "umsubl"
            | "uxtb"
            | "uxth"
            | "uxtw"
    )
}

fn record_reg_u64(record: &serde_json::Value, reg: &str) -> Option<u64> {
    record_reg_value(record, reg)
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
}

fn record_reg_value<'a>(record: &'a serde_json::Value, reg: &str) -> Option<&'a serde_json::Value> {
    let regs = record.get("regs")?;
    regs.get(reg)
        .or_else(|| regs.get(register_value_key(reg).as_str()))
}

fn def_reg_from_asm(asm: &str) -> Option<String> {
    let asm = asm.trim();
    let mut parts = asm.splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    if mnemonic.starts_with('b')
        || matches!(mnemonic.as_str(), "ret" | "cmp" | "cmn" | "tst")
        || !store_source_regs_from_asm(asm).is_empty()
    {
        return None;
    }
    let operands = parts.next()?;
    split_operands(operands)
        .first()
        .and_then(|op| first_register_token(op))
}

fn pair_load_dest_regs_from_asm(asm: &str) -> Option<Vec<String>> {
    let asm = asm.trim();
    let mut parts = asm.splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    if !matches!(mnemonic.as_str(), "ldp" | "ldnp" | "ldpsw") {
        return None;
    }
    let regs = split_operands(parts.next()?)
        .into_iter()
        .take(2)
        .filter_map(|op| first_register_token(&op))
        .collect::<Vec<_>>();
    (regs.len() == 2).then_some(regs)
}

fn def_source_regs_from_asm(asm: &str) -> Vec<String> {
    let asm = asm.trim();
    if pair_load_dest_regs_from_asm(asm).is_some() {
        return memory_source_regs_from_asm(asm);
    }
    let Some((_, operands)) = asm.split_once(char::is_whitespace) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    split_operands(operands)
        .into_iter()
        .skip(1)
        .flat_map(|op| register_tokens(&op))
        .filter(|reg| seen.insert(register_value_key(reg)))
        .collect()
}

fn memory_source_regs_from_asm(asm: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    bracket_registers(&asm.to_ascii_lowercase())
        .unwrap_or_default()
        .into_iter()
        .filter(|reg| seen.insert(register_value_key(reg)))
        .collect()
}

fn register_tokens(op: &str) -> Vec<String> {
    op.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let token = token.trim_end_matches('!').to_ascii_lowercase();
            is_gp_register_token(&token).then_some(token)
        })
        .collect()
}

fn is_gp_register_token(token: &str) -> bool {
    token == "sp"
        || token == "wsp"
        || token == "fp"
        || token == "lr"
        || token == "xzr"
        || token == "wzr"
        || token
            .strip_prefix('x')
            .is_some_and(|rest| rest.parse::<u8>().is_ok())
        || token
            .strip_prefix('w')
            .is_some_and(|rest| rest.parse::<u8>().is_ok())
}

fn memory_access_width(asm: &str) -> u64 {
    let mnemonic = asm
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(mnemonic.as_str(), "ldp" | "ldnp" | "ldpsw") {
        pair_load_dest_regs_from_asm(asm)
            .and_then(|regs| regs.first().map(|reg| register_load_width(reg)))
            .unwrap_or(8)
    } else if mnemonic.ends_with('b') {
        1
    } else if mnemonic.ends_with('h') {
        2
    } else if mnemonic == "ldrsw" {
        4
    } else {
        let reg = def_reg_from_asm(asm).unwrap_or_default();
        if reg.starts_with('w') {
            4
        } else {
            8
        }
    }
}

fn register_load_width(reg: &str) -> u64 {
    if reg.starts_with('w') {
        4
    } else {
        8
    }
}

fn vm_slot_from_asm(asm: &str, record: &serde_json::Value) -> Option<serde_json::Value> {
    let lower = asm.to_ascii_lowercase();
    if !lower.contains("[x25,") {
        return None;
    }
    let regs = bracket_registers(&lower)?;
    if regs.first().map(String::as_str) != Some("x25") {
        return None;
    }
    let idx_reg = regs.get(1)?;
    let idx_val = record_reg_u64(record, idx_reg)?;
    let slot = if lower.contains("lsl #3") {
        idx_val
    } else {
        idx_val / 8
    };
    Some(serde_json::json!({
        "index_reg": idx_reg,
        "index_value": format!("{idx_val:#x}"),
        "slot": slot,
    }))
}

fn mem_addr_from_asm(asm: &str, record: &serde_json::Value) -> Option<u64> {
    let lower = asm.to_ascii_lowercase();
    let regs = bracket_registers(&lower)?;
    let base = regs.first().and_then(|reg| record_reg_u64(record, reg))?;
    let index = regs
        .get(1)
        .and_then(|reg| record_reg_u64(record, reg))
        .unwrap_or(0);
    let index = index.checked_shl(bracket_index_shift(&lower).unwrap_or(0))?;
    let imm = bracket_immediate(&lower).unwrap_or(0);
    Some(base.wrapping_add(index).wrapping_add(imm))
}

fn bracket_registers(asm: &str) -> Option<Vec<String>> {
    let start = asm.find('[')?;
    let end = asm[start..].find(']')? + start;
    let inside = &asm[start + 1..end];
    let regs = split_operands(inside)
        .into_iter()
        .filter_map(|part| first_register_token(&part))
        .collect::<Vec<_>>();
    (!regs.is_empty()).then_some(regs)
}

fn bracket_immediate(asm: &str) -> Option<u64> {
    let start = asm.find('[')?;
    let end = asm[start..].find(']')? + start;
    let inside = &asm[start + 1..end];
    split_operands(inside).into_iter().find_map(|part| {
        let trimmed = part.trim().trim_start_matches('#');
        parse_u64_str(trimmed)
    })
}

fn bracket_index_shift(asm: &str) -> Option<u32> {
    let start = asm.find('[')?;
    let end = asm[start..].find(']')? + start;
    let inside = &asm[start + 1..end];
    split_operands(inside).into_iter().find_map(|part| {
        let part = part.trim();
        let rest = part.strip_prefix("lsl")?.trim();
        let shift = rest.trim_start_matches('#');
        shift.parse::<u32>().ok().filter(|bits| *bits < 64)
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

fn cmd_resolve_map_addr(maps_file: PathBuf, addr: String) -> anyhow::Result<()> {
    let addr = parse_u64_str(&addr).with_context(|| format!("invalid address: {addr}"))?;
    let text = std::fs::read_to_string(&maps_file)
        .with_context(|| format!("failed to read maps file: {}", maps_file.display()))?;
    let out = resolve_addr_in_maps_text(&text, addr).unwrap_or_else(|| {
        serde_json::json!({
            "status": "miss",
            "addr": format!("{addr:#x}"),
            "maps_file": maps_file.display().to_string(),
        })
    });
    print_pretty(&out)
}

fn resolve_addr_in_maps_text(text: &str, addr: u64) -> Option<serde_json::Value> {
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next()?;
        let perms = parts.next().unwrap_or("");
        let offset_raw = parts.next().unwrap_or("0");
        let dev = parts.next().unwrap_or("");
        let inode = parts.next().unwrap_or("");
        let path = parts.collect::<Vec<_>>().join(" ");
        let (lo_raw, hi_raw) = range.split_once('-')?;
        let lo = u64::from_str_radix(lo_raw, 16).ok()?;
        let hi = u64::from_str_radix(hi_raw, 16).ok()?;
        if !(lo <= addr && addr < hi) {
            continue;
        }
        let map_file_offset = u64::from_str_radix(offset_raw, 16).unwrap_or(0);
        let map_offset = addr.saturating_sub(lo);
        let file_offset = map_file_offset.saturating_add(map_offset);
        return Some(serde_json::json!({
            "status": "hit",
            "addr": format!("{addr:#x}"),
            "map_start": format!("{lo:#x}"),
            "map_end": format!("{hi:#x}"),
            "perms": perms,
            "map_file_offset": format!("{map_file_offset:#x}"),
            "map_offset": format!("{map_offset:#x}"),
            "file_offset": format!("{file_offset:#x}"),
            "dev": dev,
            "inode": inode,
            "path": if path.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(path) },
            "line": line,
        }));
    }
    None
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

#[cfg(test)]
mod tests {
    use super::{
        alu_expression_from_asm, base64_decoded_bytes, choose_frontier_next, classify_vm_asm,
        def_entries_from_asm, def_source_regs_from_asm, mem_addr_from_asm, memory_access_width,
        odd_u64_inverse, recognize_alu_semantic, recognized_backchain_patterns,
        resolve_addr_in_maps_text, store_source_regs_from_asm, vm_slot_from_asm,
    };

    #[test]
    fn parses_store_source_registers() {
        assert_eq!(store_source_regs_from_asm("str w1, [x19, x6]"), vec!["w1"]);
        assert_eq!(
            store_source_regs_from_asm("stp x9, x10, [x11, #0x10]"),
            vec!["x9", "x10"]
        );
        assert_eq!(
            store_source_regs_from_asm("stxp w0, x1, x2, [x3]"),
            vec!["x1", "x2"]
        );
        assert_eq!(store_source_regs_from_asm("stxr w0, x1, [x2]"), vec!["x1"]);
        assert!(store_source_regs_from_asm("ldr x0, [x1]").is_empty());
    }

    #[test]
    fn classifies_vm_records_and_scaled_slots() {
        let record = serde_json::json!({
            "regs": {
                "x25": "0x1000",
                "x19": "0x19",
                "x1": "0xe0",
            }
        });
        assert_eq!(classify_vm_asm("ldr x4, [x25, x19, lsl #3]"), "vm-reg-load");
        assert_eq!(classify_vm_asm("ldp x9, x10, [x25, #0xc0]"), "mem-load");
        assert_eq!(
            mem_addr_from_asm("ldr x4, [x25, x19, lsl #3]", &record),
            Some(0x10c8)
        );
        let slot = vm_slot_from_asm("ldr x4, [x25, x19, lsl #3]", &record).unwrap();
        assert_eq!(slot["slot"], serde_json::json!(25));
        assert_eq!(
            mem_addr_from_asm("str x3, [x25, x1]", &record),
            Some(0x10e0)
        );
        let slot = vm_slot_from_asm("str x3, [x25, x1]", &record).unwrap();
        assert_eq!(slot["slot"], serde_json::json!(28));
    }

    #[test]
    fn estimates_memory_access_widths() {
        assert_eq!(memory_access_width("ldrb w1, [x0, x4]"), 1);
        assert_eq!(memory_access_width("ldrh w5, [x21, #0x10]!"), 2);
        assert_eq!(memory_access_width("ldr w16, [x8, x20]"), 4);
        assert_eq!(memory_access_width("ldrsw x4, [x21, #0x18]"), 4);
        assert_eq!(memory_access_width("ldr x4, [x25, x19, lsl #3]"), 8);
        assert_eq!(memory_access_width("ldp x9, x10, [x25, #0xc0]"), 8);
    }

    #[test]
    fn parses_definition_source_registers() {
        assert_eq!(
            def_source_regs_from_asm("and x20, x19, x4"),
            vec!["x19", "x4"]
        );
        assert_eq!(
            def_source_regs_from_asm("ldrb w1, [x0, x4]"),
            vec!["x0", "x4"]
        );
        assert_eq!(
            def_source_regs_from_asm("ldp x9, x10, [x25, #0xc0]"),
            vec!["x25"]
        );
        assert_eq!(def_source_regs_from_asm("lsl x5, x3, #3"), vec!["x3"]);
    }

    #[test]
    fn expands_pair_load_defs() {
        let rec = serde_json::json!({
            "regs": {
                "x25": "0x1000"
            }
        });
        let next = serde_json::json!({
            "regs": {
                "x9": "0x1111",
                "x10": "0x2222"
            }
        });
        let defs =
            def_entries_from_asm("ldp x9, x10, [x25, #0xc0]", &rec, Some(&next), Some(0x10c0));
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0]["reg"], serde_json::json!("x9"));
        assert_eq!(defs[0]["value_after"], serde_json::json!("0x1111"));
        assert_eq!(defs[0]["mem_addr"], serde_json::json!("0x10c0"));
        assert_eq!(defs[1]["reg"], serde_json::json!("x10"));
        assert_eq!(defs[1]["value_after"], serde_json::json!("0x2222"));
        assert_eq!(defs[1]["mem_addr"], serde_json::json!("0x10c8"));
    }

    #[test]
    fn renders_alu_value_formulas() {
        assert_eq!(
            alu_expression_from_asm(
                "orr x4, x14, x17",
                "0x29",
                &["0x28".to_string(), "0x1".to_string()],
            ),
            Some("0x29 = 0x28 | 0x1".to_string())
        );
        assert_eq!(
            alu_expression_from_asm("lsl w16, w2, #2", "0x28", &["0xa".to_string()]),
            Some("0x28 = 0xa << 0x2".to_string())
        );
        assert_eq!(
            alu_expression_from_asm(
                "lsr w4, w20, w1",
                "0x1",
                &["0x62".to_string(), "0x6".to_string()],
            ),
            Some("0x1 = 0x62 >> 0x6".to_string())
        );
        assert_eq!(
            alu_expression_from_asm(
                "udiv x14, x13, x12",
                "0x757524ef",
                &["0x74ffafca73".to_string(), "0xff".to_string()],
            ),
            Some("0x757524ef = 0x74ffafca73 / 0xff".to_string())
        );
        assert_eq!(
            alu_expression_from_asm(
                "mul x3, x6, x4",
                "0xdd1841bea1487649",
                &[
                    "0x52c36263893da50d".to_string(),
                    "0x5851f42d4c957f2d".to_string()
                ],
            ),
            Some(
                "0xdd1841bea1487649 = (0x52c36263893da50d * 0x5851f42d4c957f2d) mod 2^64"
                    .to_string()
            )
        );
        let semantic = recognize_alu_semantic(
            "add x15, x13, x14",
            "0x757524ef62",
            &["0x74ffafca73".to_string(), "0x757524ef".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("mod255_low_byte"));
        assert_eq!(semantic["output_byte"], serde_json::json!("0x62"));
        let semantic = recognize_alu_semantic(
            "add x5, x3, x4",
            "0x99bd5d21d7d8103",
            &["0x99bd5d21d7d8102".to_string(), "0x1".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("add_small_delta"));
        assert_eq!(semantic["input"], serde_json::json!("0x99bd5d21d7d8102"));
        let semantic = recognize_alu_semantic(
            "mul x3, x6, x4",
            "0xdd1841bea1487649",
            &[
                "0x52c36263893da50d".to_string(),
                "0x5851f42d4c957f2d".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("mul_mod64"));
        assert_eq!(semantic["rhs_odd"], serde_json::json!(true));
    }

    #[test]
    fn frontier_auto_prefers_small_non_infrastructure_registers() {
        let step = serde_json::json!({
            "frontier": [
                {"idx": 10, "reg": "x25", "value": "0x70000000"},
                {"idx": 10, "reg": "x4", "value": "0x74fbf29990"},
                {"idx": 10, "reg": "x20", "value": "0x18"}
            ]
        });
        let next = choose_frontier_next(&step).unwrap();
        assert_eq!(next["idx"], serde_json::json!(10));
        assert_eq!(next["reg"], serde_json::json!("x20"));
        assert_eq!(next["src_value"], serde_json::json!("0x18"));

        let infra_only = serde_json::json!({
            "frontier": [
                {"idx": 20, "reg": "x23", "value": "0x69f5b3cb"}
            ]
        });
        let next = choose_frontier_next(&infra_only).unwrap();
        assert_eq!(next["idx"], serde_json::json!(20));
        assert_eq!(next["reg"], serde_json::json!("x23"));
        assert_eq!(next["src_value"], serde_json::json!("0x69f5b3cb"));

        let call_return = serde_json::json!({
            "local_def": {
                "class": "call-return"
            },
            "frontier": [
                {"idx": 30, "reg": "x0", "value": "0x0"}
            ]
        });
        assert!(choose_frontier_next(&call_return).is_none());
    }

    #[test]
    fn frontier_auto_prefers_semantic_alu_inputs() {
        let udiv = serde_json::json!({
            "local_def": {
                "asm": "udiv x1, x19, x6",
                "class": "alu",
                "def": {
                    "reg": "x1",
                    "src": [
                        {"reg": "x19", "value": "0x74ffafca73"},
                        {"reg": "x6", "value": "0xff"}
                    ],
                    "value_after": "0x757524ef"
                }
            },
            "frontier": [
                {"idx": 20, "reg": "x19", "value": "0x74ffafca73"},
                {"idx": 20, "reg": "x6", "value": "0xff"}
            ]
        });
        let next = choose_frontier_next(&udiv).unwrap();
        assert_eq!(next["reg"], serde_json::json!("x19"));
        assert_eq!(next["src_value"], serde_json::json!("0x74ffafca73"));

        let folded = serde_json::json!({
            "local_def": {
                "asm": "add x15, x13, x14",
                "class": "alu",
                "def": {
                    "reg": "x15",
                    "src": [
                        {"reg": "x13", "value": "0x74ffafca73"},
                        {"reg": "x14", "value": "0x757524ef"}
                    ],
                    "value_after": "0x757524ef62"
                }
            },
            "frontier": [
                {"idx": 30, "reg": "x13", "value": "0x74ffafca73"},
                {"idx": 30, "reg": "x14", "value": "0x757524ef"}
            ]
        });
        let next = choose_frontier_next(&folded).unwrap();
        assert_eq!(next["reg"], serde_json::json!("x13"));
        assert_eq!(next["src_value"], serde_json::json!("0x74ffafca73"));

        let shift = serde_json::json!({
            "local_def": {
                "asm": "lsr w0, w13, w4",
                "class": "alu",
                "def": {
                    "reg": "w0",
                    "src": [
                        {"reg": "w13", "value": "0x69adbccc"},
                        {"reg": "w4", "value": "0x0"}
                    ],
                    "value_after": "0x69adbccc"
                }
            },
            "frontier": [
                {"idx": 40, "reg": "w13", "value": "0x69adbccc"},
                {"idx": 40, "reg": "w4", "value": "0x0"}
            ]
        });
        let next = choose_frontier_next(&shift).unwrap();
        assert_eq!(next["reg"], serde_json::json!("w13"));
        assert_eq!(next["src_value"], serde_json::json!("0x69adbccc"));

        let add_delta = serde_json::json!({
            "local_def": {
                "asm": "add x5, x3, x4",
                "class": "alu",
                "def": {
                    "reg": "x5",
                    "src": [
                        {"reg": "x3", "value": "0x99bd5d21d7d8102"},
                        {"reg": "x4", "value": "0x1"}
                    ],
                    "value_after": "0x99bd5d21d7d8103"
                }
            },
            "frontier": [
                {"idx": 50, "reg": "x3", "value": "0x99bd5d21d7d8102"},
                {"idx": 50, "reg": "x4", "value": "0x1"}
            ]
        });
        let next = choose_frontier_next(&add_delta).unwrap();
        assert_eq!(next["reg"], serde_json::json!("x3"));
        assert_eq!(next["src_value"], serde_json::json!("0x99bd5d21d7d8102"));
    }

    #[test]
    fn recognizes_affine_mod64_state_steps() {
        let chain = vec![
            serde_json::json!({
                "step": 0,
                "local_def": {
                    "formula": {
                        "semantic": {
                            "kind": "add_small_delta",
                            "input": "0x52c36263893da50c",
                            "delta": "0x1",
                            "result": "0x52c36263893da50d"
                        }
                    }
                }
            }),
            serde_json::json!({
                "step": 1,
                "local_def": {
                    "formula": {
                        "semantic": {
                            "kind": "mul_mod64",
                            "lhs": "0x5036f3354bed40bc",
                            "rhs": "0x5851f42d4c957f2d",
                            "result": "0x52c36263893da50c",
                            "rhs_odd": true
                        }
                    }
                }
            }),
        ];
        let patterns = recognized_backchain_patterns(&chain);
        assert_eq!(patterns.len(), 1);
        assert_eq!(
            patterns[0]["kind"],
            serde_json::json!("affine_mod64_state_step")
        );
        assert_eq!(
            patterns[0]["previous_state"],
            serde_json::json!("0x5036f3354bed40bc")
        );
        assert_eq!(
            patterns[0]["multiplier"],
            serde_json::json!("0x5851f42d4c957f2d")
        );
        assert_eq!(
            patterns[0]["multiplier_inverse"],
            serde_json::json!("0xc097ef87329e28a5")
        );
        assert_eq!(patterns[0]["delta"], serde_json::json!("0x1"));
    }

    #[test]
    fn computes_odd_inverse_mod_2_64() {
        let multiplier = 0x5851f42d4c957f2d_u64;
        let inverse = odd_u64_inverse(multiplier).unwrap();
        assert_eq!(inverse, 0xc097ef87329e28a5);
        assert_eq!(multiplier.wrapping_mul(inverse), 1);
        assert!(odd_u64_inverse(2).is_none());
    }

    #[test]
    fn resolves_proc_maps_addresses() {
        let maps = "\
787beb8000-787bf61000 r-xp 0005b000 07:128 126231 /apex/com.android.runtime/lib64/bionic/libc.so\n";
        let hit = resolve_addr_in_maps_text(maps, 0x787bf034e8).unwrap();
        assert_eq!(hit["status"], serde_json::json!("hit"));
        assert_eq!(hit["map_offset"], serde_json::json!("0x4b4e8"));
        assert_eq!(hit["file_offset"], serde_json::json!("0xa64e8"));
        assert_eq!(
            hit["path"],
            serde_json::json!("/apex/com.android.runtime/lib64/bionic/libc.so")
        );
        assert!(resolve_addr_in_maps_text(maps, 0x7601b72790).is_none());
    }

    #[test]
    fn base64_decoder_accepts_unpadded_xsign_output() {
        let decoded = base64_decoded_bytes(
            "azYBCM007xAApiYQXVKLkaXxoOr2BiYWKai5MLGI6T9yCUYPHSKV0zba5j/4Jbr6D0UvFBHd3FllrCJShVQSWn+qcIYmFY3mFgYmFi",
        )
        .unwrap();
        assert_eq!(decoded.len(), 76);
        assert_eq!(
            &decoded[..9],
            &[0x6b, 0x36, 0x01, 0x08, 0xcd, 0x34, 0xef, 0x10, 0x00]
        );
    }
}

fn print_pretty(value: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
