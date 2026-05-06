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
    /// Resolve an ELF/shared-library virtual offset to the nearest symbol.
    ResolveElfSymbol { elf_file: PathBuf, offset: String },
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
        #[arg(long)]
        cursor: Option<u64>,
        /// Emit compact hex/ascii fields instead of only per-byte entries.
        #[arg(long)]
        summary: bool,
        /// Interpret the range as a NUL-terminated C string.
        #[arg(long)]
        cstr: bool,
    },
    /// GET /api/last-write-of-addr.
    LastWriteOfAddr {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long, default_value_t = -1)]
        before_idx: isize,
        /// Include boundary-diff external writes from MemShadow.
        #[arg(long)]
        with_external: bool,
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
        /// Include byte values from MemShadow, blocking to load/build it if needed.
        #[arg(long)]
        with_bytes: bool,
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
        #[arg(long)]
        with_external: bool,
        #[arg(long, default_value_t = 200)]
        max: usize,
    },
    /// Expand memory writes into the latest writer for each byte in a buffer.
    ByteWriterMap {
        trace_dir: PathBuf,
        #[arg(long)]
        addr: String,
        #[arg(long)]
        size: u64,
        #[arg(long, default_value_t = 0)]
        idx_lo: usize,
        #[arg(long, default_value_t = -1)]
        idx_hi: isize,
        #[arg(long, default_value_t = 5000)]
        max: usize,
        /// Attach VM backchains for this many steps per selected writer run. 0 disables.
        #[arg(long, default_value_t = 0)]
        vm_chain_steps: usize,
        /// Max writer runs to expand with VM backchains.
        #[arg(long, default_value_t = 6)]
        vm_chain_runs: usize,
        /// Lookback window for each VM backchain step.
        #[arg(long, default_value_t = 1800000)]
        vm_chain_lookback: usize,
        /// Let attached VM chains continue through frontier source regs.
        #[arg(long)]
        vm_chain_follow_frontier: bool,
        /// Emit a compact AI-readable summary instead of all byte and chain details.
        #[arg(long)]
        summary: bool,
        /// Register holding the VM instruction pointer in this trace/profile.
        #[arg(long, default_value = "x21")]
        vm_ip_reg: String,
        /// Register holding the VM state/virtual-register base.
        #[arg(long, default_value = "x25")]
        vm_state_reg: String,
        /// Register holding the dispatch table base or dispatch lookup base.
        #[arg(long, default_value = "x23")]
        vm_dispatch_reg: String,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        #[arg(long, default_value = "x27")]
        vm_infra_regs: String,
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
        /// Expand candidate output buffers with byte-writer-map evidence.
        #[arg(long)]
        map_bytes: bool,
        /// Max candidates to expand when --map-bytes is enabled.
        #[arg(long, default_value_t = 50)]
        map_candidates: usize,
        /// Keep only mapped candidates whose bytes are not all zero.
        #[arg(long)]
        nonzero_only: bool,
        /// Optional target bytes as hex; mapped candidates report byte-offset hits.
        #[arg(long = "target-bytes")]
        target_bytes: Option<String>,
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
        /// Output key to diff. Repeat to compare multiple keys. Defaults to all observed keys.
        #[arg(long = "key")]
        keys: Vec<String>,
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
        /// Keep only pairs with this output key, for example a header name.
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
        /// Keep only pairs with this output key, for example a header name.
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
        /// Analyze a Base64 tail beginning at this output character offset.
        #[arg(long)]
        base64_tail_start: Option<usize>,
        /// Base64 characters to prepend before decoding the tail, for alignment.
        #[arg(long, default_value = "")]
        base64_tail_align_prefix: String,
        /// Drop this many decoded bytes from the aligned tail before diffing.
        #[arg(long, default_value_t = 0)]
        base64_tail_drop: usize,
        /// Include this many recent GetStringUTFChars strings before each output.
        #[arg(long, default_value_t = 0)]
        prior_inputs: usize,
    },
    /// Build an output-to-input backward trace report for a known output.
    OutputBacktrace {
        trace_dir: PathBuf,
        /// Start from a JNI NewStringUTF key/value pair, for example a header name.
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
        /// Register holding the VM instruction pointer in this trace/profile.
        #[arg(long, default_value = "x21")]
        vm_ip_reg: String,
        /// Register holding the VM state/virtual-register base.
        #[arg(long, default_value = "x25")]
        vm_state_reg: String,
        /// Register holding the dispatch table base or dispatch lookup base.
        #[arg(long, default_value = "x23")]
        vm_dispatch_reg: String,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        #[arg(long, default_value = "x27")]
        vm_infra_regs: String,
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
        /// Start from a JNI NewStringUTF key/value pair, for example a header name.
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
        /// Select groups covering this decoded semantic byte offset.
        #[arg(long)]
        semantic_offset: Option<usize>,
        /// Number of decoded semantic bytes to cover when --semantic-offset is set.
        #[arg(long, default_value_t = 1)]
        semantic_count: usize,
        /// Attach VM backtrees for this depth per group. 0 disables.
        #[arg(long, default_value_t = 0)]
        tree_depth: usize,
        /// Max nodes per attached VM backtree.
        #[arg(long, default_value_t = 120)]
        tree_max_nodes: usize,
        /// Attach VM backtrees to matched Base64 alphabet index registers. If --tree-depth is 0,
        /// output-map builds hidden lookup trees to find alphabet table lookups first.
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
        /// Analyze a Base64 tail beginning at this output character offset.
        #[arg(long)]
        base64_tail_start: Option<usize>,
        /// Base64 characters to prepend before grouping the tail, for alignment.
        #[arg(long, default_value = "")]
        base64_tail_align_prefix: String,
        /// Drop this many decoded bytes from the aligned tail before assigning semantic offsets.
        #[arg(long, default_value_t = 0)]
        base64_tail_drop: usize,
        /// Attach byte-writer-map evidence for decoded semantic bytes in the pre-encoding scratch buffer.
        #[arg(long)]
        semantic_writer_map: bool,
        /// Override the exclusive idx_hi used for --semantic-writer-map. Defaults to the first final-output writer.
        #[arg(long)]
        semantic_writer_map_idx_hi: Option<usize>,
        /// Max writes to read while building --semantic-writer-map.
        #[arg(long, default_value_t = 5000)]
        semantic_writer_map_max: usize,
        /// Attach VM backchains for this many steps per semantic writer run. 0 disables.
        #[arg(long, default_value_t = 0)]
        semantic_writer_map_vm_chain_steps: usize,
        /// Max semantic writer runs to expand with VM backchains.
        #[arg(long, default_value_t = 8)]
        semantic_writer_map_vm_chain_runs: usize,
        /// Expand semantic writer VM chains per byte lane instead of per coalesced writer run.
        #[arg(long)]
        semantic_writer_map_vm_chain_bytes: bool,
        /// Lookback window for each semantic writer VM backchain step.
        #[arg(long, default_value_t = 1800000)]
        semantic_writer_map_vm_chain_lookback: usize,
        /// Let semantic writer VM chains continue through frontier source regs.
        #[arg(long)]
        semantic_writer_map_vm_chain_follow_frontier: bool,
        /// Register holding the VM instruction pointer in this trace/profile.
        #[arg(long, default_value = "x21")]
        vm_ip_reg: String,
        /// Register holding the VM state/virtual-register base.
        #[arg(long, default_value = "x25")]
        vm_state_reg: String,
        /// Register holding the dispatch table base or dispatch lookup base.
        #[arg(long, default_value = "x23")]
        vm_dispatch_reg: String,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        #[arg(long, default_value = "x27")]
        vm_infra_regs: String,
        /// Emit a compact AI-readable summary.
        #[arg(long)]
        summary: bool,
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
        /// Register holding the VM instruction pointer in this trace/profile.
        #[arg(long, default_value = "x21")]
        vm_ip_reg: String,
        /// Register holding the VM state/virtual-register base.
        #[arg(long, default_value = "x25")]
        vm_state_reg: String,
        /// Register holding the dispatch table base or dispatch lookup base.
        #[arg(long, default_value = "x23")]
        vm_dispatch_reg: String,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        #[arg(long, default_value = "x27")]
        vm_infra_regs: String,
        /// Base VM IP for vm_off. Defaults to the first row's --vm-ip-reg.
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
        /// Register holding the VM instruction pointer in this trace/profile.
        #[arg(long, default_value = "x21")]
        vm_ip_reg: String,
        /// Register holding the VM state/virtual-register base.
        #[arg(long, default_value = "x25")]
        vm_state_reg: String,
        /// Register holding the dispatch table base or dispatch lookup base.
        #[arg(long, default_value = "x23")]
        vm_dispatch_reg: String,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        #[arg(long, default_value = "x27")]
        vm_infra_regs: String,
        /// Base VM IP for vm_off. Defaults to the first row's --vm-ip-reg.
        #[arg(long)]
        base_ip: Option<String>,
        /// Max VM op groups to return.
        #[arg(long, default_value_t = 80)]
        max_ops: usize,
        /// Max records per /api/records request. Use 0 to keep the old single-request behavior.
        #[arg(long, default_value_t = 900)]
        chunk_size: usize,
        /// Emit a compact AI-readable summary.
        #[arg(long)]
        summary: bool,
        /// With --summary, emit only top-level effects and state updates.
        #[arg(long)]
        effects_only: bool,
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
        /// Register holding the VM instruction pointer in this trace/profile.
        #[arg(long, default_value = "x21")]
        vm_ip_reg: String,
        /// Register holding the VM state/virtual-register base.
        #[arg(long, default_value = "x25")]
        vm_state_reg: String,
        /// Register holding the dispatch table base or dispatch lookup base.
        #[arg(long, default_value = "x23")]
        vm_dispatch_reg: String,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        #[arg(long, default_value = "x27")]
        vm_infra_regs: String,
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
        /// Prefer upstream memory byte writers matching this little-endian source byte lane.
        #[arg(long)]
        byte_lane: Option<usize>,
        /// Emit a compact AI-readable summary instead of the full step payload.
        #[arg(long)]
        summary: bool,
        /// Comma-separated registers to request from /api/records.
        #[arg(
            long,
            default_value = "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28"
        )]
        regs: String,
        /// Register holding the VM instruction pointer in this trace/profile.
        #[arg(long, default_value = "x21")]
        vm_ip_reg: String,
        /// Register holding the VM state/virtual-register base.
        #[arg(long, default_value = "x25")]
        vm_state_reg: String,
        /// Register holding the dispatch table base or dispatch lookup base.
        #[arg(long, default_value = "x23")]
        vm_dispatch_reg: String,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        #[arg(long, default_value = "x27")]
        vm_infra_regs: String,
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
        /// Register holding the VM instruction pointer in this trace/profile.
        #[arg(long, default_value = "x21")]
        vm_ip_reg: String,
        /// Register holding the VM state/virtual-register base.
        #[arg(long, default_value = "x25")]
        vm_state_reg: String,
        /// Register holding the dispatch table base or dispatch lookup base.
        #[arg(long, default_value = "x23")]
        vm_dispatch_reg: String,
        /// Extra VM infrastructure registers to de-prioritize while following frontiers.
        #[arg(long, default_value = "x27")]
        vm_infra_regs: String,
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
        Some(Cmd::ResolveElfSymbol { elf_file, offset }) => {
            cmd_resolve_elf_symbol(elf_file, offset)
        }
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
                profile,
            )
            .await
        }
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

async fn cmd_byte_writer_map(
    trace_dir: PathBuf,
    addr: String,
    size: u64,
    idx_lo: usize,
    idx_hi: isize,
    max: usize,
    vm_chain_steps: usize,
    vm_chain_runs: usize,
    vm_chain_lookback: usize,
    vm_chain_follow_frontier: bool,
    summary: bool,
    vm_profile: VmProfile,
) -> anyhow::Result<()> {
    let addr_value =
        parse_u64_str(&addr).with_context(|| format!("invalid --addr value {addr:?}"))?;
    if size == 0 {
        bail!("byte-writer-map requires --size > 0");
    }
    let size_usize = usize::try_from(size).context("--size does not fit in usize")?;
    if size_usize > 1_000_000 {
        bail!("byte-writer-map refuses buffers larger than 1,000,000 bytes");
    }
    let addr_hi = addr_value
        .checked_add(size)
        .context("--addr + --size overflowed u64")?;
    let params = vec![
        ("idx_lo", idx_lo.to_string()),
        ("idx_hi", idx_hi.to_string()),
        ("addr_lo", format!("{addr_value:#x}")),
        ("addr_hi", format!("{addr_hi:#x}")),
        ("max", max.to_string()),
    ];
    let path = route_path("/api/mem-writes-in-range", &params);
    let app = if vm_chain_steps > 0 && vm_chain_runs > 0 {
        tracemiku_server::build_router_with_memshadow(trace_dir)?
    } else {
        build_cli_router(trace_dir, &path, None)?
    };
    let response = route_get_json_value_on(&app, path).await?;
    let mut output = byte_writer_map_output(addr_value, size_usize, &response);
    if vm_chain_steps > 0 && vm_chain_runs > 0 {
        let runs = output
            .get("writer_runs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let chains = vm_chains_for_byte_writer_runs(
            &app,
            &runs,
            vm_chain_steps,
            vm_chain_runs,
            vm_chain_lookback,
            vm_chain_follow_frontier,
            &vm_profile,
        )
        .await?;
        let chain_summary = vm_chain_batch_summary(&chains);
        if let Some(obj) = output.as_object_mut() {
            obj.insert("vm_chain_summary".to_string(), chain_summary);
            obj.insert("vm_chains".to_string(), serde_json::Value::Array(chains));
        }
    }
    let output = if summary {
        byte_writer_map_summary(&output)
    } else {
        output
    };
    print_pretty(&output)
}

#[allow(clippy::too_many_arguments)]
async fn cmd_hash_finalize_detect(
    trace_dir: PathBuf,
    window: usize,
    min_size: u64,
    limit: usize,
    map_bytes: bool,
    map_candidates: usize,
    nonzero_only: bool,
    target_bytes: Option<String>,
) -> anyhow::Result<()> {
    let params = vec![
        ("window", window.to_string()),
        ("min_size", min_size.to_string()),
        ("limit", limit.to_string()),
    ];
    let path = route_path("/api/hash-finalize-detect", &params);
    let needs_map = map_bytes || nonzero_only || target_bytes.is_some();
    if !needs_map {
        return route_get_json(trace_dir, path).await;
    }
    let target = target_bytes
        .as_deref()
        .map(parse_hex_bytes_cli)
        .transpose()?;
    let target_hex = target.as_ref().map(|bytes| bytes_to_hex(bytes));
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let mut response = route_get_json_value_on(&app, path).await?;
    let candidates = response
        .get("candidates")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut maps = Vec::new();
    let mut zero_candidates = 0usize;
    let mut nonzero_candidates = 0usize;
    let mut target_hits = 0usize;
    for candidate in candidates.iter().take(map_candidates) {
        let map = hash_candidate_byte_map(&app, candidate, target_hex.as_deref()).await?;
        let all_zero = map
            .get("all_zero")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let has_target_hit = map
            .get("target_hits")
            .and_then(|v| v.as_array())
            .is_some_and(|hits| !hits.is_empty());
        if all_zero {
            zero_candidates += 1;
        } else {
            nonzero_candidates += 1;
        }
        if has_target_hit {
            target_hits += 1;
        }
        if nonzero_only && all_zero {
            continue;
        }
        maps.push(map);
    }
    if let Some(obj) = response.as_object_mut() {
        obj.insert(
            "candidate_map_summary".to_string(),
            serde_json::json!({
                "mapped": maps.len(),
                "inspected": candidates.len().min(map_candidates),
                "map_candidates_limit": map_candidates,
                "zero_candidates": zero_candidates,
                "nonzero_candidates": nonzero_candidates,
                "target_hit_candidates": target_hits,
                "nonzero_only": nonzero_only,
                "target_bytes_len": target.as_ref().map(|bytes| bytes.len()),
            }),
        );
        obj.insert("candidate_maps".to_string(), serde_json::Value::Array(maps));
    }
    print_pretty(&response)
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
    base64_tail_start: Option<usize>,
    base64_tail_align_prefix: String,
    base64_tail_drop: usize,
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
            if let Some(tail_start) = base64_tail_start {
                let base64_text = row
                    .get("url_decoded")
                    .and_then(|v| v.as_str())
                    .unwrap_or(value_text);
                row["base64_tail"] = base64_tail_summary(
                    base64_text,
                    tail_start,
                    &base64_tail_align_prefix,
                    base64_tail_drop,
                    decode_base64_full || diff_base64,
                );
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
    let base64_tail_diff =
        (diff_base64 && base64_tail_start.is_some()).then(|| decoded_base64_tail_diff(&pairs));
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
    if let Some(diff) = base64_tail_diff {
        out["base64_tail_diff"] = diff;
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

fn base64_tail_summary(
    raw: &str,
    tail_start: usize,
    align_prefix: &str,
    drop_bytes: usize,
    include_full_hex: bool,
) -> serde_json::Value {
    let Some(tail) = raw.get(tail_start..) else {
        return serde_json::json!({
            "ok": false,
            "error": "tail_start is not a valid UTF-8 boundary or is past end",
            "tail_start_chars": tail_start,
        });
    };
    let aligned = format!("{align_prefix}{tail}");
    match base64_decoded_bytes(&aligned) {
        Ok(bytes) => {
            if drop_bytes > bytes.len() {
                return serde_json::json!({
                    "ok": false,
                    "error": "drop_bytes exceeds aligned decoded length",
                    "tail_start_chars": tail_start,
                    "tail_chars": tail.len(),
                    "align_prefix": align_prefix,
                    "drop_bytes": drop_bytes,
                    "aligned_decoded_len": bytes.len(),
                });
            }
            let semantic = &bytes[drop_bytes..];
            let mut summary = serde_json::json!({
                "ok": true,
                "tail_start_chars": tail_start,
                "tail_chars": tail.len(),
                "align_prefix": align_prefix,
                "drop_bytes": drop_bytes,
                "aligned_decoded_len": bytes.len(),
                "semantic_len": semantic.len(),
                "aligned_prefix_hex": bytes_to_hex(&bytes[..bytes.len().min(16)]),
                "semantic_prefix_hex": bytes_to_hex(&semantic[..semantic.len().min(16)]),
                "semantic_suffix_hex": bytes_to_hex(&semantic[semantic.len().saturating_sub(16)..]),
            });
            if include_full_hex {
                summary["aligned_decoded_hex"] = serde_json::Value::String(bytes_to_hex(&bytes));
                summary["semantic_hex"] = serde_json::Value::String(bytes_to_hex(semantic));
            }
            summary
        }
        Err(err) => serde_json::json!({
            "ok": false,
            "error": err.to_string(),
            "tail_start_chars": tail_start,
            "tail_chars": tail.len(),
            "align_prefix": align_prefix,
            "drop_bytes": drop_bytes,
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
    decoded_byte_samples_diff(samples)
}

fn decoded_base64_tail_diff(pairs: &[serde_json::Value]) -> serde_json::Value {
    let samples = pairs
        .iter()
        .enumerate()
        .filter_map(|(sample, pair)| {
            let decoded_hex = pair
                .get("base64_tail")
                .and_then(|v| v.get("semantic_hex"))
                .and_then(|v| v.as_str())?;
            let bytes = parse_hex_bytes_cli(decoded_hex).ok()?;
            Some((sample, pair, bytes))
        })
        .collect::<Vec<_>>();
    let mut diff = decoded_byte_samples_diff(samples);
    diff["source"] = serde_json::json!("base64_tail.semantic_hex");
    diff
}

fn decoded_byte_samples_diff(
    samples: Vec<(usize, &serde_json::Value, Vec<u8>)>,
) -> serde_json::Value {
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
    let repeated_ranges = repeated_ranges_all_samples(&samples, 3, 64);
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
        "repeated_ranges_all_samples": repeated_ranges,
        "per_byte": per_byte,
        "samples": sample_rows,
    })
}

fn repeated_ranges_all_samples(
    samples: &[(usize, &serde_json::Value, Vec<u8>)],
    min_len: usize,
    max_rows: usize,
) -> Vec<serde_json::Value> {
    let Some(compared_len) = samples.iter().map(|(_, _, bytes)| bytes.len()).min() else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for src in 0..compared_len {
        for dst in src + 1..compared_len {
            if src > 0
                && dst > 0
                && samples
                    .iter()
                    .all(|(_, _, bytes)| bytes[src - 1] == bytes[dst - 1])
            {
                continue;
            }
            let mut len = 0usize;
            while src + len < compared_len
                && dst + len < compared_len
                && samples
                    .iter()
                    .all(|(_, _, bytes)| bytes[src + len] == bytes[dst + len])
            {
                len += 1;
            }
            if len < min_len {
                continue;
            }
            let examples = samples
                .iter()
                .take(4)
                .map(|(sample, pair, bytes)| {
                    serde_json::json!({
                        "sample": sample,
                        "call_dir": pair.get("call_dir").cloned().unwrap_or(serde_json::Value::Null),
                        "src_hex": bytes_to_hex(&bytes[src..src + len]),
                        "dst_hex": bytes_to_hex(&bytes[dst..dst + len]),
                    })
                })
                .collect::<Vec<_>>();
            rows.push(serde_json::json!({
                "src_start": src,
                "src_end": src + len,
                "dst_start": dst,
                "dst_end": dst + len,
                "length": len,
                "examples": examples,
            }));
        }
    }
    rows.sort_by_key(|row| {
        (
            std::cmp::Reverse(row.get("length").and_then(|v| v.as_u64()).unwrap_or(0)),
            row.get("src_start").and_then(|v| v.as_u64()).unwrap_or(0),
            row.get("dst_start").and_then(|v| v.as_u64()).unwrap_or(0),
        )
    });
    rows.truncate(max_rows);
    rows
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
                "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28".to_string(),
                &opts.vm_profile,
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
            (formula.get("semantic").is_some()
                || formula.get("op").and_then(|v| v.as_str()) == Some("udiv"))
                && !formula_is_low_signal(formula)
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
    vm_profile: VmProfile,
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
    semantic_offset: Option<usize>,
    semantic_count: usize,
    tree_depth: usize,
    tree_max_nodes: usize,
    index_tree_depth: usize,
    index_tree_max_nodes: usize,
    tree_frontier_with_next: bool,
    lookback: usize,
    url_decode: bool,
    base64_tail_start: Option<usize>,
    base64_tail_align_prefix: String,
    base64_tail_drop: usize,
    semantic_writer_map: bool,
    semantic_writer_map_idx_hi: Option<usize>,
    semantic_writer_map_max: usize,
    semantic_writer_map_vm_chain_steps: usize,
    semantic_writer_map_vm_chain_runs: usize,
    semantic_writer_map_vm_chain_bytes: bool,
    semantic_writer_map_vm_chain_lookback: usize,
    semantic_writer_map_vm_chain_follow_frontier: bool,
    vm_profile: VmProfile,
    summary: bool,
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

#[allow(clippy::too_many_arguments)]
async fn output_map_group_vm_trees(
    app: &axum::Router,
    runs: &[serde_json::Value],
    depth: usize,
    max_nodes: usize,
    lookback: usize,
    frontier_with_next: bool,
    profile: &VmProfile,
) -> anyhow::Result<Vec<serde_json::Value>> {
    if depth == 0 {
        return Ok(Vec::new());
    }
    let mut trees = Vec::new();
    let mut seen_tree_seeds = HashSet::new();
    for run in runs {
        if let Some(seed) = run
            .get("writer_seeds")
            .and_then(|v| v.as_array())
            .and_then(|seeds| {
                seeds.iter().find(|seed| {
                    seed.get("kind").and_then(|v| v.as_str()) == Some("memory_writer_src_reg")
                })
            })
        {
            let Some(idx) = seed.get("start").and_then(|v| v.as_u64()) else {
                continue;
            };
            let Some(reg) = seed.get("reg").and_then(|v| v.as_str()) else {
                continue;
            };
            if !seen_tree_seeds.insert((idx, reg.to_string())) {
                continue;
            }
            let tree = vm_backtree_value_on(
                app,
                idx as usize,
                Some(reg.to_string()),
                depth,
                max_nodes,
                120,
                lookback,
                5000,
                frontier_with_next,
                "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28".to_string(),
                profile,
            )
            .await?;
            trees.push(serde_json::json!({
                "seed": seed,
                "tree": tree,
            }));
            if trees.len() >= 8 {
                break;
            }
        }
    }
    Ok(trees)
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
            vm_profile: opts.vm_profile.clone(),
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
    let base64_context = base64_output_context(&mapped_text, &opts)?;
    let grouped_text = base64_context
        .get("grouped_text")
        .and_then(|v| v.as_str())
        .unwrap_or(mapped_text.as_str())
        .to_string();
    let align_prefix_len = base64_context
        .get("align_prefix_chars")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let tail_start = base64_context
        .get("tail_start_chars")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    let semantic_drop = base64_context
        .get("semantic_drop_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let selected_semantic_range = opts.semantic_offset.map(|start| {
        let count = opts.semantic_count.max(1);
        let end = start.saturating_add(count);
        serde_json::json!({
            "start": start,
            "end": end,
            "length": count,
        })
    });
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
    let mut selected_addr = None;
    let mut first_output_writer_idx = None;
    if let Some(hit) = selected_hit.as_ref() {
        if let Some(addr) = hit
            .get("addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
        {
            selected_addr = Some(addr);
            let params = vec![
                ("addr", format!("{addr:#x}")),
                ("length", source.primary_bytes.len().to_string()),
            ];
            let provenance =
                route_get_json_value_on(&app, route_path("/api/string-provenance", &params))
                    .await?;
            writer_runs = provenance_writer_runs(&provenance, &[]);
            first_output_writer_idx = min_writer_idx(&writer_runs);
            selected_range = serde_json::json!({
                "addr_lo": format!("{addr:#x}"),
                "addr_hi": format!("{:#x}", addr.saturating_add(source.primary_bytes.len() as u64)),
                "length": source.primary_bytes.len(),
            });
        }
    }

    let group_total = grouped_text.len().div_ceil(4);
    let (selected_group_start, selected_group_end) =
        if let Some(semantic_start) = opts.semantic_offset {
            let count = opts.semantic_count.max(1);
            let aligned_start = (semantic_start as u64).saturating_add(semantic_drop) as usize;
            let aligned_end = (semantic_start.saturating_add(count) as u64)
                .saturating_add(semantic_drop) as usize;
            (
                (aligned_start / 3).min(group_total),
                aligned_end.div_ceil(3).min(group_total),
            )
        } else {
            let group_end = if opts.groups == 0 {
                group_total
            } else {
                opts.group_start
                    .saturating_add(opts.groups)
                    .min(group_total)
            };
            (opts.group_start.min(group_total), group_end)
        };
    let mut group_rows = Vec::new();
    for group_idx in selected_group_start..selected_group_end {
        let start = group_idx * 4;
        let end = (start + 4).min(grouped_text.len());
        let chars = &grouped_text[start..end];
        let decoded = base64_decoded_bytes(chars).unwrap_or_default();
        let base64 = base64_group_analysis(chars);
        let original_range =
            original_output_range_for_group(start, end, tail_start, align_prefix_len);
        let runs = if let Some((orig_start, orig_end)) = original_range {
            output_runs_overlapping(&app, &writer_runs, orig_start, orig_end).await?
        } else {
            Vec::new()
        };
        let trees = output_map_group_vm_trees(
            &app,
            &runs,
            opts.tree_depth,
            opts.tree_max_nodes,
            opts.lookback,
            opts.tree_frontier_with_next,
            &opts.vm_profile,
        )
        .await?;
        let hidden_lookup_trees;
        let lookup_trees = if opts.index_tree_depth > 0 && trees.is_empty() {
            hidden_lookup_trees = output_map_group_vm_trees(
                &app,
                &runs,
                BASE64_LOOKUP_TREE_DEPTH,
                BASE64_LOOKUP_TREE_MAX_NODES.max(opts.index_tree_max_nodes),
                opts.lookback,
                true,
                &opts.vm_profile,
            )
            .await?;
            hidden_lookup_trees.as_slice()
        } else {
            trees.as_slice()
        };
        let mut lookup_matches = base64_lookup_matches(&base64, lookup_trees);
        if opts.index_tree_depth > 0 {
            attach_base64_index_trees_on(&app, &mut lookup_matches, &opts).await?;
        }
        group_rows.push(serde_json::json!({
            "group": group_idx,
            "offset": start,
            "end": end,
            "original_output_start": original_range.map(|(start, _)| start),
            "original_output_end": original_range.map(|(_, end)| end),
            "decoded_offset_base": group_idx.saturating_mul(3),
            "semantic_drop_bytes": semantic_drop,
            "chars": chars,
            "base64": base64,
            "base64_lookup_matches": lookup_matches,
            "decoded_hex": bytes_to_hex(&decoded),
            "runs": runs,
            "trees": trees,
        }));
    }
    let semantic_writer_map = if opts.semantic_writer_map {
        output_semantic_writer_map(
            &app,
            &grouped_text,
            selected_addr,
            first_output_writer_idx,
            &opts,
        )
        .await?
    } else {
        serde_json::Value::Null
    };

    let output = serde_json::json!({
        "status": "ready",
        "strategy": "output_base64_group_map",
        "source": source.json,
        "text_len": mapped_text.len(),
        "base64_context": base64_context,
        "group_total": group_total,
        "selected_group_start": selected_group_start,
        "selected_group_end": selected_group_end,
        "selected_semantic_range": selected_semantic_range,
        "selected_hit_order": opts.hit_order.as_str(),
        "selected_hit_rank": opts.hit_rank,
        "tree_frontier_with_next": opts.tree_frontier_with_next,
        "index_tree_depth": opts.index_tree_depth,
        "index_tree_max_nodes": opts.index_tree_max_nodes,
        "hit_candidates": hit_candidates,
        "selected_hit": selected_hit,
        "selected_range": selected_range,
        "find_mem_pattern": find,
        "semantic_writer_map": semantic_writer_map,
        "groups": group_rows,
    });
    if opts.summary {
        print_pretty(&output_map_summary(&output))
    } else {
        print_pretty(&output)
    }
}

fn min_writer_idx(runs: &[serde_json::Value]) -> Option<usize> {
    runs.iter()
        .filter_map(|run| run.get("writer_idx").and_then(|v| v.as_u64()))
        .filter_map(|idx| usize::try_from(idx).ok())
        .min()
}

async fn output_semantic_writer_map(
    app: &axum::Router,
    grouped_text: &str,
    selected_addr: Option<u64>,
    first_output_writer_idx: Option<usize>,
    opts: &OutputMapOpts,
) -> anyhow::Result<serde_json::Value> {
    let Some(base_addr) = selected_addr else {
        return Ok(serde_json::json!({
            "status": "unavailable",
            "reason": "no selected output memory hit",
        }));
    };
    let idx_hi = opts.semantic_writer_map_idx_hi.or(first_output_writer_idx);
    let Some(idx_hi) = idx_hi else {
        return Ok(serde_json::json!({
            "status": "unavailable",
            "reason": "no final-output writer idx found; pass --semantic-writer-map-idx-hi",
        }));
    };
    let decoded = base64_decoded_bytes(grouped_text)
        .context("failed to decode selected output text for --semantic-writer-map")?;
    let drop = opts.base64_tail_drop;
    if drop >= decoded.len() {
        return Ok(serde_json::json!({
            "status": "unavailable",
            "reason": "semantic drop is past decoded byte length",
            "decoded_len": decoded.len(),
            "semantic_drop_bytes": drop,
        }));
    }
    let semantic_total = decoded.len() - drop;
    let semantic_start = opts.semantic_offset.unwrap_or(0);
    if semantic_start >= semantic_total {
        return Ok(serde_json::json!({
            "status": "unavailable",
            "reason": "semantic offset is past decoded semantic byte length",
            "semantic_offset": semantic_start,
            "semantic_total": semantic_total,
        }));
    }
    let requested_count = if opts.semantic_offset.is_some() {
        opts.semantic_count.max(1)
    } else {
        semantic_total
    };
    let semantic_len = requested_count.min(semantic_total - semantic_start);
    let addr_offset = drop
        .checked_add(semantic_start)
        .context("semantic writer-map offset overflowed")?;
    let map_addr = base_addr
        .checked_add(addr_offset as u64)
        .context("semantic writer-map address overflowed")?;
    let addr_hi = map_addr
        .checked_add(semantic_len as u64)
        .context("semantic writer-map end address overflowed")?;
    let params = vec![
        ("idx_lo", "0".to_string()),
        ("idx_hi", idx_hi.to_string()),
        ("addr_lo", format!("{map_addr:#x}")),
        ("addr_hi", format!("{addr_hi:#x}")),
        ("max", opts.semantic_writer_map_max.to_string()),
    ];
    let response =
        route_get_json_value_on(app, route_path("/api/mem-writes-in-range", &params)).await?;
    let mut map = byte_writer_map_output(map_addr, semantic_len, &response);
    if opts.semantic_writer_map_vm_chain_steps > 0 && opts.semantic_writer_map_vm_chain_runs > 0 {
        let (seed_mode, chains) = if opts.semantic_writer_map_vm_chain_bytes {
            let bytes = map
                .get("bytes")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            (
                "bytes",
                vm_chains_for_byte_writer_entries(
                    app,
                    &bytes,
                    opts.semantic_writer_map_vm_chain_steps,
                    opts.semantic_writer_map_vm_chain_runs,
                    opts.semantic_writer_map_vm_chain_lookback,
                    opts.semantic_writer_map_vm_chain_follow_frontier,
                    &opts.vm_profile,
                )
                .await?,
            )
        } else {
            let runs = map
                .get("writer_runs")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            (
                "writer_runs",
                vm_chains_for_byte_writer_runs(
                    app,
                    &runs,
                    opts.semantic_writer_map_vm_chain_steps,
                    opts.semantic_writer_map_vm_chain_runs,
                    opts.semantic_writer_map_vm_chain_lookback,
                    opts.semantic_writer_map_vm_chain_follow_frontier,
                    &opts.vm_profile,
                )
                .await?,
            )
        };
        let chain_summary = vm_chain_batch_summary(&chains);
        if let Some(obj) = map.as_object_mut() {
            obj.insert(
                "vm_chain_seed_mode".to_string(),
                serde_json::json!(seed_mode),
            );
            obj.insert("vm_chain_summary".to_string(), chain_summary);
            obj.insert("vm_chains".to_string(), serde_json::Value::Array(chains));
        }
    }
    if let Some(obj) = map.as_object_mut() {
        obj.insert(
            "semantic_context".to_string(),
            serde_json::json!({
                "mode": "selected_output_buffer_pre_encoding",
                "base_addr": format!("{base_addr:#x}"),
                "addr_offset_from_base": addr_offset,
                "semantic_offset": semantic_start,
                "semantic_count": semantic_len,
                "semantic_total": semantic_total,
                "decoded_len": decoded.len(),
                "idx_hi": idx_hi,
                "idx_hi_source": if opts.semantic_writer_map_idx_hi.is_some() {
                    "explicit"
                } else {
                    "first_final_output_writer"
                },
                "note": "Uses the selected final output buffer as the earlier pre-encoding scratch buffer and stops before the final output overwrite.",
            }),
        );
    }
    Ok(map)
}

fn base64_output_context(
    mapped_text: &str,
    opts: &OutputMapOpts,
) -> anyhow::Result<serde_json::Value> {
    if let Some(tail_start) = opts.base64_tail_start {
        let Some(tail) = mapped_text.get(tail_start..) else {
            bail!("--base64-tail-start is not a valid boundary or is past the output text");
        };
        let grouped_text = format!("{}{}", opts.base64_tail_align_prefix, tail);
        Ok(serde_json::json!({
            "mode": "aligned_tail",
            "tail_start_chars": tail_start,
            "tail_chars": tail.len(),
            "align_prefix": opts.base64_tail_align_prefix,
            "align_prefix_chars": opts.base64_tail_align_prefix.len(),
            "semantic_drop_bytes": opts.base64_tail_drop,
            "grouped_text_len": grouped_text.len(),
            "grouped_text": grouped_text,
        }))
    } else {
        Ok(serde_json::json!({
            "mode": "whole_output",
            "tail_start_chars": serde_json::Value::Null,
            "tail_chars": mapped_text.len(),
            "align_prefix": "",
            "align_prefix_chars": 0,
            "semantic_drop_bytes": 0,
            "grouped_text_len": mapped_text.len(),
            "grouped_text": mapped_text,
        }))
    }
}

fn original_output_range_for_group(
    grouped_start: usize,
    grouped_end: usize,
    tail_start: Option<usize>,
    align_prefix_len: usize,
) -> Option<(usize, usize)> {
    match tail_start {
        Some(tail_start) => {
            if grouped_end <= align_prefix_len {
                None
            } else {
                let start =
                    tail_start.saturating_add(grouped_start.saturating_sub(align_prefix_len));
                let end = tail_start.saturating_add(grouped_end.saturating_sub(align_prefix_len));
                (start < end).then_some((start, end))
            }
        }
        None => Some((grouped_start, grouped_end)),
    }
}

fn output_map_summary(value: &serde_json::Value) -> serde_json::Value {
    let groups = value
        .get("groups")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(output_map_group_summary)
        .collect::<Vec<_>>();
    let semantic_writer_map = output_semantic_writer_map_summary(
        value
            .get("semantic_writer_map")
            .unwrap_or(&serde_json::Value::Null),
    );
    let semantic_byte_equation_summary = semantic_writer_map
        .get("byte_equation_summary")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let semantic_byte_input_summary = semantic_writer_map
        .get("byte_equation_input_summary")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let semantic_vm_chain_summary = semantic_writer_map
        .get("vm_chain_summary")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "strategy": value.get("strategy").cloned().unwrap_or(serde_json::Value::Null),
        "source": value.get("source").cloned().unwrap_or(serde_json::Value::Null),
        "text_len": value.get("text_len").cloned().unwrap_or(serde_json::Value::Null),
        "base64_context": {
            "mode": value.pointer("/base64_context/mode").cloned().unwrap_or(serde_json::Value::Null),
            "tail_start_chars": value.pointer("/base64_context/tail_start_chars").cloned().unwrap_or(serde_json::Value::Null),
            "align_prefix": value.pointer("/base64_context/align_prefix").cloned().unwrap_or(serde_json::Value::Null),
            "semantic_drop_bytes": value.pointer("/base64_context/semantic_drop_bytes").cloned().unwrap_or(serde_json::Value::Null),
            "grouped_text_len": value.pointer("/base64_context/grouped_text_len").cloned().unwrap_or(serde_json::Value::Null),
        },
        "group_total": value.get("group_total").cloned().unwrap_or(serde_json::Value::Null),
        "selected_group_start": value.get("selected_group_start").cloned().unwrap_or(serde_json::Value::Null),
        "selected_group_end": value.get("selected_group_end").cloned().unwrap_or(serde_json::Value::Null),
        "selected_semantic_range": value.get("selected_semantic_range").cloned().unwrap_or(serde_json::Value::Null),
        "selected_hit_order": value.get("selected_hit_order").cloned().unwrap_or(serde_json::Value::Null),
        "selected_hit_rank": value.get("selected_hit_rank").cloned().unwrap_or(serde_json::Value::Null),
        "selected_range": value.get("selected_range").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_byte_equation_summary": semantic_byte_equation_summary,
        "semantic_byte_input_summary": semantic_byte_input_summary,
        "semantic_vm_chain_summary": semantic_vm_chain_summary,
        "semantic_writer_map": semantic_writer_map,
        "groups": groups,
    })
}

fn output_semantic_writer_map_summary(value: &serde_json::Value) -> serde_json::Value {
    if value.is_null() {
        return serde_json::Value::Null;
    }
    let writer_run_count = value
        .get("writer_runs")
        .and_then(|v| v.as_array())
        .map(|runs| runs.len())
        .unwrap_or(0);
    let byte_equations = output_semantic_byte_equations(value);
    let byte_equation_summary = output_semantic_byte_equation_summary_with_context(
        &byte_equations,
        value.get("semantic_context"),
    );
    let byte_equation_input_summary = output_semantic_byte_equation_input_summary(&byte_equations);
    let xor_word_templates = output_semantic_xor_word_templates(&byte_equations);
    let xor_word_template_count = xor_word_templates
        .as_array()
        .map(|templates| templates.len())
        .unwrap_or(0);
    let xor_word_run_templates = output_semantic_xor_word_run_templates(&byte_equations);
    let xor_word_run_template_count = xor_word_run_templates
        .as_array()
        .map(|templates| templates.len())
        .unwrap_or(0);
    let xor_word_state_sources =
        output_semantic_xor_word_state_sources(value, &xor_word_run_templates);
    let xor_word_state_source_summary = output_semantic_xor_word_state_source_summary(
        &xor_word_run_templates,
        &xor_word_state_sources,
    );
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_context": value.get("semantic_context").cloned().unwrap_or(serde_json::Value::Null),
        "addr": value.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "size": value.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "idx_range": value.get("idx_range").cloned().unwrap_or(serde_json::Value::Null),
        "source": value.get("source").cloned().unwrap_or(serde_json::Value::Null),
        "complete": value.get("complete").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": value.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": value.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "missing_offsets": value.get("missing_offsets").cloned().unwrap_or(serde_json::Value::Null),
        "writer_run_count": writer_run_count,
        "writer_runs": value.get("writer_runs").cloned().unwrap_or(serde_json::Value::Null),
        "vm_chain_seed_mode": value.get("vm_chain_seed_mode").cloned().unwrap_or(serde_json::Value::Null),
        "vm_chain_summary": value.get("vm_chain_summary").cloned().unwrap_or(serde_json::Value::Null),
        "byte_equation_summary": byte_equation_summary,
        "byte_equation_input_summary": byte_equation_input_summary,
        "byte_equations": byte_equations,
        "xor_word_template_count": xor_word_template_count,
        "xor_word_templates": xor_word_templates,
        "xor_word_run_template_count": xor_word_run_template_count,
        "xor_word_run_templates": xor_word_run_templates,
        "xor_word_state_source_summary": xor_word_state_source_summary,
        "xor_word_state_sources": xor_word_state_sources,
        "vm_chains": output_semantic_vm_chain_summaries(value),
    })
}

fn output_semantic_byte_equations(value: &serde_json::Value) -> serde_json::Value {
    let equations = value
        .get("vm_chains")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(output_semantic_byte_equation)
        .collect::<Vec<_>>();
    serde_json::Value::Array(equations)
}

#[cfg(test)]
fn output_semantic_byte_equation_summary(equations: &serde_json::Value) -> serde_json::Value {
    output_semantic_byte_equation_summary_with_context(equations, None)
}

fn output_semantic_byte_equation_summary_with_context(
    equations: &serde_json::Value,
    semantic_context: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut parsed = equations
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(compact_byte_equation)
        .collect::<Vec<_>>();
    parsed.sort_by_key(|item| item.offset);
    let covered_set = parsed
        .iter()
        .map(|item| item.offset)
        .collect::<HashSet<_>>();
    let mut kind_counts = BTreeMap::<String, usize>::new();
    for item in &parsed {
        *kind_counts.entry(item.kind.clone()).or_insert(0) += 1;
    }
    let covered_offsets = parsed
        .iter()
        .map(|item| serde_json::json!(item.offset))
        .collect::<Vec<_>>();
    let min_offset = parsed.first().map(|item| item.offset);
    let max_offset = parsed.last().map(|item| item.offset);
    let missing_offsets = match (min_offset, max_offset) {
        (Some(lo), Some(hi)) => (lo..=hi)
            .filter(|offset| !covered_set.contains(offset))
            .map(|offset| serde_json::json!(offset))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    };
    let requested_range = semantic_context.and_then(semantic_requested_range);
    let missing_offsets_in_requested_range = requested_range
        .map(|(start, end)| {
            (start..end)
                .filter(|offset| !covered_set.contains(offset))
                .map(|offset| serde_json::json!(offset))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let covered_count_in_requested_range = requested_range
        .map(|(start, end)| {
            (start..end)
                .filter(|offset| covered_set.contains(offset))
                .count()
        })
        .unwrap_or(0);
    let requested_range_json = requested_range
        .map(|(start, end)| serde_json::json!([start, end]))
        .unwrap_or(serde_json::Value::Null);
    let requested_coverage_status = requested_range
        .map(|(start, end)| {
            if start == end {
                "empty_requested_range"
            } else if missing_offsets_in_requested_range.is_empty() {
                "complete_in_requested_range"
            } else {
                "partial_in_requested_range"
            }
        })
        .map(|status| serde_json::json!(status))
        .unwrap_or(serde_json::Value::Null);
    let xor_lhs_run_chunks = semantic_xor_lhs_run_chunks(&parsed);
    serde_json::json!({
        "count": parsed.len(),
        "covered_offsets": covered_offsets,
        "covered_range": match (min_offset, max_offset) {
            (Some(lo), Some(hi)) => serde_json::json!([lo, hi + 1]),
            _ => serde_json::Value::Null,
        },
        "missing_offsets_in_covered_range": missing_offsets,
        "requested_range": requested_range_json,
        "covered_count_in_requested_range": covered_count_in_requested_range,
        "missing_count_in_requested_range": missing_offsets_in_requested_range.len(),
        "missing_offsets_in_requested_range": missing_offsets_in_requested_range,
        "requested_coverage_status": requested_coverage_status,
        "kind_counts": kind_counts
            .into_iter()
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect::<Vec<_>>(),
        "xor_rhs_pattern": semantic_xor_rhs_offset_pattern(&parsed),
        "xor_lhs_runs": semantic_xor_lhs_runs(&parsed),
        "xor_lhs_run_chunks": xor_lhs_run_chunks.clone(),
        "xor_lhs_word_chunks": xor_lhs_run_chunks,
    })
}

fn semantic_requested_range(context: &serde_json::Value) -> Option<(u64, u64)> {
    let start = context.get("semantic_offset").and_then(value_as_u64)?;
    let count = context.get("semantic_count").and_then(value_as_u64)?;
    let end = start.checked_add(count)?;
    Some((start, end))
}

#[derive(Debug, Default)]
struct ByteLaneInputGroup {
    source_value: String,
    offsets: Vec<u64>,
    source_byte_offsets: BTreeSet<u64>,
    result: Vec<u8>,
}

#[derive(Debug, Default)]
struct Mod255InputGroup {
    input: String,
    output_byte: String,
    quotient: Option<String>,
    offsets: Vec<u64>,
}

fn output_semantic_byte_equation_input_summary(equations: &serde_json::Value) -> serde_json::Value {
    let mut byte_lane_sources = BTreeMap::<String, ByteLaneInputGroup>::new();
    let mut mod255_inputs = BTreeMap::<String, Mod255InputGroup>::new();
    let mut xor_lhs_offsets = Vec::<u64>::new();
    for item in equations.as_array().into_iter().flatten() {
        let Some(kind) = item.get("kind").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(offset) = item.get("offset").and_then(value_as_u64) else {
            continue;
        };
        match kind {
            "byte_lane_extract" => {
                let Some(source_value) = item.get("source_value").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(source_byte_offset) =
                    item.get("source_byte_offset").and_then(value_as_u64)
                else {
                    continue;
                };
                let result = item
                    .get("result")
                    .and_then(value_as_u64)
                    .map(|v| (v & 0xff) as u8)
                    .or_else(|| {
                        item.get("bytes_hex")
                            .and_then(|v| v.as_str())
                            .and_then(first_hex_byte)
                    });
                let group = byte_lane_sources
                    .entry(source_value.to_string())
                    .or_insert_with(|| ByteLaneInputGroup {
                        source_value: source_value.to_string(),
                        ..ByteLaneInputGroup::default()
                    });
                group.offsets.push(offset);
                group.source_byte_offsets.insert(source_byte_offset);
                if let Some(result) = result {
                    group.result.push(result);
                }
            }
            "mod255_low_byte" => {
                let Some(input) = item.get("input").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(output_byte) = item.get("output_byte").and_then(|v| v.as_str()) else {
                    continue;
                };
                let key = format!("{input}|{output_byte}");
                let group = mod255_inputs
                    .entry(key)
                    .or_insert_with(|| Mod255InputGroup {
                        input: input.to_string(),
                        output_byte: output_byte.to_string(),
                        quotient: item
                            .get("quotient")
                            .and_then(|v| v.as_str())
                            .map(str::to_string),
                        ..Mod255InputGroup::default()
                    });
                group.offsets.push(offset);
            }
            "xor_mix" => {
                xor_lhs_offsets.push(offset);
            }
            _ => {}
        }
    }
    xor_lhs_offsets.sort_unstable();
    serde_json::json!({
        "byte_lane_sources": byte_lane_sources
            .into_values()
            .map(|group| serde_json::json!({
                "source_value": group.source_value,
                "offsets": group.offsets,
                "source_byte_offsets": group.source_byte_offsets.into_iter().collect::<Vec<_>>(),
                "result_hex": bytes_to_hex(&group.result),
                "count": group.result.len(),
            }))
            .collect::<Vec<_>>(),
        "mod255_inputs": mod255_inputs
            .into_values()
            .map(|group| serde_json::json!({
                "input": group.input,
                "output_byte": group.output_byte,
                "quotient": group.quotient,
                "offsets": group.offsets,
                "count": group.offsets.len(),
            }))
            .collect::<Vec<_>>(),
        "xor_lhs_offsets": xor_lhs_offsets,
    })
}

#[derive(Debug)]
struct XorByteRun {
    start: u64,
    end: u64,
    lhs: Vec<u8>,
    rhs: Vec<u8>,
    result: Vec<u8>,
}

impl XorByteRun {
    fn new(offset: u64, lhs: u8, rhs: u8, result: u8) -> Self {
        Self {
            start: offset,
            end: offset + 1,
            lhs: vec![lhs],
            rhs: vec![rhs],
            result: vec![result],
        }
    }

    fn push(&mut self, offset: u64, lhs: u8, rhs: u8, result: u8) -> bool {
        if offset != self.end {
            return false;
        }
        self.end += 1;
        self.lhs.push(lhs);
        self.rhs.push(rhs);
        self.result.push(result);
        true
    }

    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "range": [self.start, self.end],
            "size": self.end.saturating_sub(self.start),
            "lhs_hex": bytes_to_hex(&self.lhs),
            "rhs_hex": bytes_to_hex(&self.rhs),
            "result_hex": bytes_to_hex(&self.result),
        })
    }
}

fn semantic_xor_lhs_runs(equations: &[CompactByteEquation]) -> serde_json::Value {
    let mut runs = Vec::<XorByteRun>::new();
    let mut current: Option<XorByteRun> = None;
    for item in equations.iter().filter(|item| item.kind == "xor_mix") {
        let Some(lhs) = item.lhs.map(|v| (v & 0xff) as u8) else {
            continue;
        };
        let Some(rhs) = item.rhs.map(|v| (v & 0xff) as u8) else {
            continue;
        };
        let result = (item.result & 0xff) as u8;
        if let Some(run) = current.as_mut() {
            if run.push(item.offset, lhs, rhs, result) {
                continue;
            }
            runs.push(current.take().unwrap());
        }
        current = Some(XorByteRun::new(item.offset, lhs, rhs, result));
    }
    if let Some(run) = current {
        runs.push(run);
    }
    serde_json::Value::Array(runs.into_iter().map(XorByteRun::into_json).collect())
}

fn semantic_xor_lhs_run_chunks(equations: &[CompactByteEquation]) -> serde_json::Value {
    let mut chunks = Vec::new();
    let mut current = Vec::<CompactByteEquation>::new();
    for item in equations.iter().filter(|item| item.kind == "xor_mix") {
        if current
            .last()
            .is_some_and(|prev| item.offset != prev.offset + 1)
        {
            push_xor_lhs_word_chunks(&mut chunks, &current, equations);
            current.clear();
        }
        current.push(item.clone());
    }
    if !current.is_empty() {
        push_xor_lhs_word_chunks(&mut chunks, &current, equations);
    }
    serde_json::Value::Array(chunks)
}

fn push_xor_lhs_word_chunks(
    chunks: &mut Vec<serde_json::Value>,
    run: &[CompactByteEquation],
    equations: &[CompactByteEquation],
) {
    let Some(first) = run.first() else {
        return;
    };
    let Some(last) = run.last() else {
        return;
    };
    let run_range = serde_json::json!([first.offset, last.offset + 1]);
    for (chunk_index, chunk) in run.chunks(4).enumerate() {
        if chunk.len() == 4 {
            if let Some(mut value) = semantic_xor_word_template(chunk, equations) {
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("kind".to_string(), serde_json::json!("word32"));
                    obj.insert("run_range".to_string(), run_range.clone());
                    obj.insert("run_chunk".to_string(), serde_json::json!(chunk_index));
                }
                chunks.push(value);
            }
            continue;
        }

        let lhs = chunk
            .iter()
            .filter_map(|item| item.lhs.map(|v| (v & 0xff) as u8))
            .collect::<Vec<_>>();
        let rhs = chunk
            .iter()
            .filter_map(|item| item.rhs.map(|v| (v & 0xff) as u8))
            .collect::<Vec<_>>();
        if lhs.len() != chunk.len() || rhs.len() != chunk.len() {
            continue;
        }
        let result = chunk
            .iter()
            .map(|item| (item.result & 0xff) as u8)
            .collect::<Vec<_>>();
        let start = chunk
            .first()
            .map(|item| item.offset)
            .unwrap_or(first.offset);
        let end = chunk.last().map(|item| item.offset + 1).unwrap_or(start);
        chunks.push(serde_json::json!({
            "kind": "tail_bytes",
            "run_range": run_range,
            "run_chunk": chunk_index,
            "semantic_range": [start, end],
            "size": end.saturating_sub(start),
            "lhs_hex": bytes_to_hex(&lhs),
            "rhs_hex": bytes_to_hex(&rhs),
            "result_hex": bytes_to_hex(&result),
        }));
    }
}

fn semantic_xor_rhs_offset_pattern(equations: &[CompactByteEquation]) -> serde_json::Value {
    let xor_items = equations
        .iter()
        .filter(|item| item.kind == "xor_mix")
        .filter_map(|item| item.rhs.map(|rhs| (item.offset, (rhs & 0xff) as u8)))
        .collect::<Vec<_>>();
    if xor_items.is_empty() {
        return serde_json::Value::Null;
    }
    let mut even = Vec::<u8>::new();
    let mut odd = Vec::<u8>::new();
    for (offset, rhs) in &xor_items {
        let values = if offset % 2 == 0 { &mut even } else { &mut odd };
        if !values.contains(rhs) {
            values.push(*rhs);
        }
    }
    let values_to_json = |values: &[u8]| {
        values
            .iter()
            .map(|value| serde_json::json!(format!("{value:#x}")))
            .collect::<Vec<_>>()
    };
    if even.len() == 1 && odd.len() == 1 {
        serde_json::json!({
            "kind": "offset_parity_mask",
            "formula": "xor rhs = even_byte when semantic offset is even, odd_byte when semantic offset is odd",
            "even_byte": format!("{:#x}", even[0]),
            "odd_byte": format!("{:#x}", odd[0]),
            "matched_offsets": xor_items.len(),
        })
    } else {
        serde_json::json!({
            "kind": "mixed_rhs_values",
            "even_values": values_to_json(&even),
            "odd_values": values_to_json(&odd),
            "matched_offsets": xor_items.len(),
        })
    }
}

fn output_semantic_byte_equation(item: &serde_json::Value) -> Option<serde_json::Value> {
    let offset = item
        .get("start_offset")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let bytes_hex = item.get("bytes_hex").and_then(|v| v.as_str())?;
    let byte = first_hex_byte(bytes_hex)?;
    let semantics = item
        .pointer("/chain/recognized_semantics")
        .and_then(|v| v.as_array())?;
    let mut first_mismatch: Option<serde_json::Value> = None;
    for entry in semantics {
        let semantic = entry.get("semantic")?;
        let kind = semantic.get("kind").and_then(|v| v.as_str())?;
        match kind {
            "xor_mix" => {
                let result = semantic
                    .get("result")
                    .and_then(|v| v.as_str())
                    .and_then(parse_u64_str)?;
                let equation = serde_json::json!({
                    "offset": offset,
                    "bytes_hex": bytes_hex,
                    "kind": "xor_mix",
                    "step": entry.get("step").cloned().unwrap_or(serde_json::Value::Null),
                    "idx": entry.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": entry.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                    "lhs": semantic.get("lhs").cloned().unwrap_or(serde_json::Value::Null),
                    "rhs": semantic.get("rhs").cloned().unwrap_or(serde_json::Value::Null),
                    "result": semantic.get("result").cloned().unwrap_or(serde_json::Value::Null),
                    "expression": "result == (lhs ^ rhs) & 0xff",
                    "matches_first_byte": (result & 0xff) as u8 == byte,
                });
                if equation.get("matches_first_byte").and_then(|v| v.as_bool()) == Some(true) {
                    return Some(equation);
                }
                first_mismatch.get_or_insert(equation);
            }
            "mod255_low_byte" => {
                let output_byte = semantic
                    .get("output_byte")
                    .and_then(|v| v.as_str())
                    .and_then(parse_u64_str)?;
                let equation = serde_json::json!({
                    "offset": offset,
                    "bytes_hex": bytes_hex,
                    "kind": "mod255_low_byte",
                    "step": entry.get("step").cloned().unwrap_or(serde_json::Value::Null),
                    "idx": entry.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": entry.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                    "input": semantic.get("input").cloned().unwrap_or(serde_json::Value::Null),
                    "quotient": semantic.get("quotient").cloned().unwrap_or(serde_json::Value::Null),
                    "output_byte": semantic.get("output_byte").cloned().unwrap_or(serde_json::Value::Null),
                    "result": semantic.get("output_byte").cloned().unwrap_or(serde_json::Value::Null),
                    "expression": "result == (input + floor(input / 0xff)) & 0xff",
                    "matches_first_byte": (output_byte & 0xff) as u8 == byte,
                });
                if equation.get("matches_first_byte").and_then(|v| v.as_bool()) == Some(true) {
                    return Some(equation);
                }
                first_mismatch.get_or_insert(equation);
            }
            _ => {}
        }
    }
    output_semantic_byte_lane_equation(item, offset.clone(), bytes_hex, byte)
        .or_else(|| {
            output_semantic_writer_byte_lane_equation(
                item,
                offset,
                bytes_hex,
                byte,
                first_mismatch.clone(),
            )
        })
        .or(first_mismatch)
}

fn output_semantic_writer_byte_lane_equation(
    item: &serde_json::Value,
    offset: serde_json::Value,
    bytes_hex: &str,
    byte: u8,
    rejected_semantic: Option<serde_json::Value>,
) -> Option<serde_json::Value> {
    let source_byte_offset = item
        .get("source_byte_offset")
        .or_else(|| item.pointer("/seed/byte_lane"))
        .and_then(value_as_u64)?;
    if source_byte_offset >= 8 {
        return None;
    }
    let src_value = item.pointer("/seed/src_value").and_then(value_as_u64)?;
    let result = ((src_value >> (source_byte_offset * 8)) & 0xff) as u8;
    if result != byte {
        return None;
    }
    Some(serde_json::json!({
        "offset": offset,
        "bytes_hex": bytes_hex,
        "kind": "writer_byte_lane_extract",
        "step": serde_json::Value::Null,
        "idx": item.pointer("/seed/idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": item.pointer("/seed/asm").cloned().unwrap_or(serde_json::Value::Null),
        "source_value": format!("{src_value:#x}"),
        "source_byte_offset": source_byte_offset,
        "result": format!("{result:#x}"),
        "expression": "result == byte_lane_le(writer_src_value, source_byte_offset)",
        "matches_first_byte": true,
        "rejected_semantic": rejected_semantic.unwrap_or(serde_json::Value::Null),
    }))
}

fn output_semantic_byte_lane_equation(
    item: &serde_json::Value,
    offset: serde_json::Value,
    bytes_hex: &str,
    byte: u8,
) -> Option<serde_json::Value> {
    let steps = item.pointer("/chain/chain").and_then(|v| v.as_array())?;
    for entry in steps {
        let next = entry.get("next").unwrap_or(&serde_json::Value::Null);
        if next.get("reason").and_then(|v| v.as_str()) != Some("memory_load_byte") {
            continue;
        }
        let source_byte_offset = next.get("source_byte_offset").and_then(value_as_u64)?;
        if source_byte_offset >= 8 {
            continue;
        }
        let src_value = next.get("src_value").and_then(value_as_u64)?;
        if src_value <= 0xff {
            continue;
        }
        let result = ((src_value >> (source_byte_offset * 8)) & 0xff) as u8;
        if result != byte {
            continue;
        }
        return Some(serde_json::json!({
            "offset": offset,
            "bytes_hex": bytes_hex,
            "kind": "byte_lane_extract",
            "step": entry.get("step").cloned().unwrap_or(serde_json::Value::Null),
            "idx": entry.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "asm": entry.pointer("/local_def/asm").or_else(|| entry.pointer("/target/asm")).cloned().unwrap_or(serde_json::Value::Null),
            "source_value": format!("{src_value:#x}"),
            "source_byte_offset": source_byte_offset,
            "result": format!("{result:#x}"),
            "expression": "result == byte_lane_le(source_value, source_byte_offset)",
            "matches_first_byte": true,
        }));
    }
    None
}

#[derive(Clone, Debug)]
struct CompactByteEquation {
    offset: u64,
    kind: String,
    result: u64,
    lhs: Option<u64>,
    rhs: Option<u64>,
    output_byte: Option<u64>,
}

fn output_semantic_xor_word_templates(equations: &serde_json::Value) -> serde_json::Value {
    let mut parsed = equations
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(compact_byte_equation)
        .collect::<Vec<_>>();
    parsed.sort_by_key(|item| item.offset);

    let mut templates = Vec::new();
    for window in parsed.windows(4) {
        if let Some(template) = semantic_xor_word_template(window, &parsed) {
            templates.push(template);
        }
    }
    serde_json::Value::Array(templates)
}

fn output_semantic_xor_word_run_templates(equations: &serde_json::Value) -> serde_json::Value {
    let mut parsed = equations
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(compact_byte_equation)
        .collect::<Vec<_>>();
    parsed.sort_by_key(|item| item.offset);
    let chunks = semantic_xor_lhs_run_chunks(&parsed)
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|item| item.get("kind").and_then(|v| v.as_str()) == Some("word32"))
        .collect::<Vec<_>>();
    serde_json::Value::Array(chunks)
}

fn compact_byte_equation(value: &serde_json::Value) -> Option<CompactByteEquation> {
    if value.get("matches_first_byte").and_then(|v| v.as_bool()) == Some(false) {
        return None;
    }
    let offset = value.get("offset").and_then(value_as_u64)?;
    let kind = value.get("kind")?.as_str()?.to_string();
    let result = value
        .get("result")
        .or_else(|| value.get("output_byte"))
        .and_then(value_as_u64)?;
    let lhs = value.get("lhs").and_then(value_as_u64);
    let rhs = value.get("rhs").and_then(value_as_u64);
    let output_byte = value.get("output_byte").and_then(value_as_u64);
    Some(CompactByteEquation {
        offset,
        kind,
        result,
        lhs,
        rhs,
        output_byte,
    })
}

fn semantic_xor_word_template(
    window: &[CompactByteEquation],
    equations: &[CompactByteEquation],
) -> Option<serde_json::Value> {
    let start = window.first()?.offset;
    if !window
        .iter()
        .enumerate()
        .all(|(idx, item)| item.offset == start + idx as u64 && item.kind == "xor_mix")
    {
        return None;
    }

    let lhs = window
        .iter()
        .map(|item| item.lhs.map(|v| (v & 0xff) as u8))
        .collect::<Option<Vec<_>>>()?;
    let rhs = window
        .iter()
        .map(|item| item.rhs.map(|v| (v & 0xff) as u8))
        .collect::<Option<Vec<_>>>()?;
    let result = window
        .iter()
        .map(|item| (item.result & 0xff) as u8)
        .collect::<Vec<_>>();
    if result
        .iter()
        .zip(lhs.iter().zip(rhs.iter()))
        .any(|(out, (l, r))| *out != (*l ^ *r))
    {
        return None;
    }

    let rhs_pattern = if rhs[0] == rhs[2] && rhs[1] == rhs[3] {
        serde_json::json!({
            "kind": "alternating_two_byte_mask",
            "bytes_hex": bytes_to_hex(&rhs[..2]),
            "repeat_hex": bytes_to_hex(&rhs),
            "source_offsets": [
                equation_offset_for_byte(equations, start, rhs[0]),
                equation_offset_for_byte(equations, start, rhs[1]),
            ],
        })
    } else {
        serde_json::json!({
            "kind": "literal_bytes",
            "bytes_hex": bytes_to_hex(&rhs),
        })
    };

    Some(serde_json::json!({
        "semantic_range": [start, start + 4],
        "formula": "semantic[start..start+4] = word32_le(lhs_word_le) xor rhs_bytes",
        "lhs_bytes_hex": bytes_to_hex(&lhs),
        "lhs_word_le": format!("0x{:08x}", le_word_u32(&lhs)),
        "rhs_bytes_hex": bytes_to_hex(&rhs),
        "rhs_word_le": format!("0x{:08x}", le_word_u32(&rhs)),
        "rhs_pattern": rhs_pattern,
        "result_bytes_hex": bytes_to_hex(&result),
        "result_word_le": format!("0x{:08x}", le_word_u32(&result)),
    }))
}

fn equation_offset_for_byte(
    equations: &[CompactByteEquation],
    before_offset: u64,
    byte: u8,
) -> serde_json::Value {
    equations
        .iter()
        .rev()
        .find(|item| {
            item.offset < before_offset
                && (item.output_byte.or(Some(item.result)).unwrap_or_default() & 0xff) as u8 == byte
        })
        .map(|item| serde_json::json!(item.offset))
        .unwrap_or(serde_json::Value::Null)
}

fn le_word_u32(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .take(4)
        .enumerate()
        .fold(0u32, |acc, (idx, byte)| acc | ((*byte as u32) << (idx * 8)))
}

fn output_semantic_xor_word_state_sources(
    value: &serde_json::Value,
    templates: &serde_json::Value,
) -> serde_json::Value {
    let Some(templates) = templates.as_array() else {
        return serde_json::json!([]);
    };
    let chains = value
        .get("vm_chains")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut sources = Vec::new();
    for template in templates {
        let Some(start) = template
            .get("semantic_range")
            .and_then(|v| v.as_array())
            .and_then(|range| range.first())
            .and_then(value_as_u64)
        else {
            continue;
        };
        let Some(chain) = chains
            .iter()
            .find(|chain| chain.get("start_offset").and_then(value_as_u64) == Some(start))
        else {
            continue;
        };
        let semantics = chain
            .pointer("/chain/recognized_semantics")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let lhs_word_le = template
            .get("lhs_word_le")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
            .map(|v| (v as u32).swap_bytes() as u64);
        let Some(source) = xor_word_source_from_semantics(&semantics, lhs_word_le) else {
            continue;
        };
        let source_status = if source
            .get("state_update")
            .is_some_and(|state_update| !state_update.is_null())
        {
            "state_update_found"
        } else {
            "word_source_only"
        };
        sources.push(serde_json::json!({
            "semantic_range": template.get("semantic_range").cloned().unwrap_or(serde_json::Value::Null),
            "lhs_word_le": template.get("lhs_word_le").cloned().unwrap_or(serde_json::Value::Null),
            "source_offset": start,
            "source_status": source_status,
            "source_word": source.get("source_word").cloned().unwrap_or(serde_json::Value::Null),
            "source_word_be": source.get("source_word_be").cloned().unwrap_or(serde_json::Value::Null),
            "source_word_match": source.get("source_word_match").cloned().unwrap_or(serde_json::Value::Null),
            "word_extract": source.get("word_extract").cloned().unwrap_or(serde_json::Value::Null),
            "state_update": source.get("state_update").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    serde_json::Value::Array(sources)
}

fn output_semantic_xor_word_state_source_summary(
    templates: &serde_json::Value,
    sources: &serde_json::Value,
) -> serde_json::Value {
    let templates = templates.as_array().cloned().unwrap_or_default();
    let sources = sources.as_array().cloned().unwrap_or_default();
    let mut source_status_counts = BTreeMap::<String, usize>::new();
    let mut source_status_ranges = BTreeMap::<String, Vec<serde_json::Value>>::new();
    for source in &sources {
        let Some(status) = source.get("source_status").and_then(|v| v.as_str()) else {
            continue;
        };
        *source_status_counts.entry(status.to_string()).or_insert(0) += 1;
        source_status_ranges
            .entry(status.to_string())
            .or_default()
            .push(serde_json::json!({
                "semantic_range": source.get("semantic_range").cloned().unwrap_or(serde_json::Value::Null),
                "lhs_word_le": source.get("lhs_word_le").cloned().unwrap_or(serde_json::Value::Null),
                "source_word": source.get("source_word").cloned().unwrap_or(serde_json::Value::Null),
            }));
    }
    let source_starts = sources
        .iter()
        .filter_map(|source| {
            source
                .get("semantic_range")
                .and_then(|v| v.as_array())
                .and_then(|range| range.first())
                .and_then(value_as_u64)
        })
        .collect::<HashSet<_>>();
    let missing_templates = templates
        .iter()
        .filter_map(|template| {
            let range = template.get("semantic_range")?.as_array()?;
            let start = range.first().and_then(value_as_u64)?;
            if source_starts.contains(&start) {
                return None;
            }
            Some(serde_json::json!({
                "semantic_range": template.get("semantic_range").cloned().unwrap_or(serde_json::Value::Null),
                "lhs_word_le": template.get("lhs_word_le").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "template_count": templates.len(),
        "source_count": sources.len(),
        "missing_count": missing_templates.len(),
        "coverage_status": if templates.is_empty() {
            "no_xor_word_templates"
        } else if missing_templates.is_empty() {
            "complete"
        } else {
            "partial"
        },
        "missing_templates": missing_templates,
        "source_status_counts": source_status_counts
            .into_iter()
            .map(|(status, count)| serde_json::json!({ "status": status, "count": count }))
            .collect::<Vec<_>>(),
        "source_status_ranges": source_status_ranges
            .into_iter()
            .map(|(status, ranges)| serde_json::json!({ "status": status, "ranges": ranges }))
            .collect::<Vec<_>>(),
    })
}

fn xor_word_source_from_semantics(
    semantics: &[serde_json::Value],
    expected_source_word_be: Option<u64>,
) -> Option<serde_json::Value> {
    let candidates = expected_source_word_be
        .map(xor_source_word_candidates)
        .unwrap_or_default();
    let word_extract = semantics
        .iter()
        .filter(|entry| {
            let semantic = entry.get("semantic").unwrap_or(&serde_json::Value::Null);
            semantic.get("kind").and_then(|v| v.as_str()) == Some("shift_right")
                && semantic.get("shift").and_then(value_as_u64) == Some(0x18)
        })
        .find(|entry| {
            if candidates.is_empty() {
                return true;
            }
            let semantic = entry.get("semantic").unwrap_or(&serde_json::Value::Null);
            semantic_word_candidate_match(semantic, &candidates, &["input"]).is_some()
        })
        .or_else(|| {
            semantics.iter().find(|entry| {
                let semantic = entry.get("semantic").unwrap_or(&serde_json::Value::Null);
                semantic_word_candidate_match(semantic, &candidates, &["input", "result"]).is_some()
            })
        })?;
    let semantic = word_extract
        .get("semantic")
        .unwrap_or(&serde_json::Value::Null);
    let source_word = word_extract
        .pointer("/semantic/input")
        .and_then(value_as_u64)
        .or_else(|| {
            word_extract
                .pointer("/semantic/result")
                .and_then(value_as_u64)
        })?;
    let source_match = semantic_word_candidate_match(semantic, &candidates, &["input", "result"])
        .map(|(word, relation, field)| {
            serde_json::json!({
                "word": format!("{word:#x}"),
                "relation": relation,
                "field": field,
            })
        });
    let state_update = semantics.iter().find(|entry| {
        let semantic = entry.get("semantic").unwrap_or(&serde_json::Value::Null);
        if semantic.get("kind").and_then(|v| v.as_str()) != Some("add32_mix") {
            return false;
        }
        semantic
            .get("result_low32")
            .or_else(|| semantic.get("result"))
            .and_then(value_as_u64)
            .is_some_and(|result| (result & 0xffff_ffff) == source_word)
    });
    Some(serde_json::json!({
        "source_word": format!("{source_word:#x}"),
        "source_word_be": format!("{source_word:#x}"),
        "source_word_match": source_match.unwrap_or(serde_json::Value::Null),
        "word_extract": word_extract,
        "state_update": state_update.cloned().unwrap_or(serde_json::Value::Null),
    }))
}

fn xor_source_word_candidates(lhs_word_le_bswap: u64) -> Vec<(u64, &'static str)> {
    let be = lhs_word_le_bswap & 0xffff_ffff;
    let le = (be as u32).swap_bytes() as u64;
    if be == le {
        vec![(be, "lhs_word_le_or_bswap")]
    } else {
        vec![(be, "bswap_lhs_word_le"), (le, "lhs_word_le")]
    }
}

fn semantic_word_candidate_match(
    semantic: &serde_json::Value,
    candidates: &[(u64, &'static str)],
    fields: &[&'static str],
) -> Option<(u64, &'static str, &'static str)> {
    for field in fields {
        let Some(value) = semantic.get(*field).and_then(value_as_u64) else {
            continue;
        };
        let value = value & 0xffff_ffff;
        for (candidate, relation) in candidates {
            if value == *candidate {
                return Some((value, *relation, *field));
            }
        }
    }
    None
}

fn first_hex_byte(hex: &str) -> Option<u8> {
    let compact = hex
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    if compact.len() < 2 {
        return None;
    }
    u8::from_str_radix(&compact[..2], 16).ok()
}

fn output_semantic_vm_chain_summaries(value: &serde_json::Value) -> serde_json::Value {
    let chains = value
        .get("vm_chains")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(output_semantic_vm_chain_summary)
        .collect::<Vec<_>>();
    serde_json::Value::Array(chains)
}

fn output_semantic_vm_chain_summary(item: &serde_json::Value) -> serde_json::Value {
    let semantics = item
        .pointer("/chain/recognized_semantics")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let semantic_kinds = semantics
        .iter()
        .filter_map(|entry| {
            entry
                .get("semantic")
                .and_then(|v| v.get("kind"))
                .and_then(|v| v.as_str())
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    serde_json::json!({
        "start_offset": item.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
        "end_offset": item.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
        "size": item.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": item.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": item.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offset": item.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offsets": item.get("source_byte_offsets").cloned().unwrap_or(serde_json::Value::Null),
        "writer_idx": item.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
        "seed": item.get("seed").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_kinds": semantic_kinds,
        "recognized_semantics": semantics,
    })
}

fn output_map_group_summary(group: &serde_json::Value) -> serde_json::Value {
    let indices = group
        .pointer("/base64/indices")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            serde_json::json!({
                "pos": item.get("pos").cloned().unwrap_or(serde_json::Value::Null),
                "char": item.get("char").cloned().unwrap_or(serde_json::Value::Null),
                "index_hex": item.get("index_hex").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let decoded = group
        .pointer("/base64/decoded_bytes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            serde_json::json!({
                "byte": item.get("byte").cloned().unwrap_or(serde_json::Value::Null),
                "value_hex": item.get("value_hex").cloned().unwrap_or(serde_json::Value::Null),
                "formula": item.get("formula").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let lookups = group
        .get("base64_lookup_matches")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(output_map_lookup_summary)
        .collect::<Vec<_>>();
    let decoded_payload = output_map_decoded_payload_summary(group, &lookups);
    let trees = group
        .get("trees")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(output_map_tree_summary)
        .collect::<Vec<_>>();
    let payload_formula_table = output_map_payload_formula_table(&decoded_payload);
    serde_json::json!({
        "group": group.get("group").cloned().unwrap_or(serde_json::Value::Null),
        "offset": group.get("offset").cloned().unwrap_or(serde_json::Value::Null),
        "end": group.get("end").cloned().unwrap_or(serde_json::Value::Null),
        "original_output_start": group.get("original_output_start").cloned().unwrap_or(serde_json::Value::Null),
        "original_output_end": group.get("original_output_end").cloned().unwrap_or(serde_json::Value::Null),
        "chars": group.get("chars").cloned().unwrap_or(serde_json::Value::Null),
        "decoded_hex": group.get("decoded_hex").cloned().unwrap_or(serde_json::Value::Null),
        "indices": indices,
        "decoded": decoded,
        "decoded_payload": decoded_payload,
        "payload_formula_table": payload_formula_table,
        "lookups": lookups,
        "trees": trees,
    })
}

fn output_map_tree_summary(item: &serde_json::Value) -> serde_json::Value {
    let tree = item
        .get("tree")
        .map(vm_backtree_summary)
        .unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "seed": item.get("seed").cloned().unwrap_or(serde_json::Value::Null),
        "tree": tree,
    })
}

fn output_map_decoded_payload_summary(
    group: &serde_json::Value,
    lookups: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let decoded_base = group
        .get("decoded_offset_base")
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| group.get("group").and_then(|v| v.as_u64()).unwrap_or(0) * 3);
    let semantic_drop = group
        .get("semantic_drop_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    group
        .pointer("/base64/decoded_bytes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            let byte_idx = item.get("byte").and_then(|v| v.as_u64()).unwrap_or(0);
            let aligned_decoded_offset = decoded_base.saturating_add(byte_idx);
            let semantic_offset = aligned_decoded_offset.checked_sub(semantic_drop);
            let index_sources = item
                .get("indices")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .filter_map(|idx| idx.as_u64())
                .filter_map(|idx| {
                    lookups
                        .iter()
                        .find(|lookup| lookup.get("pos").and_then(|v| v.as_u64()) == Some(idx))
                        .map(compact_lookup_source_for_payload)
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "payload_offset": aligned_decoded_offset,
                "aligned_decoded_offset": aligned_decoded_offset,
                "semantic_offset": semantic_offset,
                "dropped_by_alignment": semantic_offset.is_none(),
                "byte_in_group": byte_idx,
                "value_hex": item.get("value_hex").cloned().unwrap_or(serde_json::Value::Null),
                "formula": item.get("formula").cloned().unwrap_or(serde_json::Value::Null),
                "index_sources": index_sources,
            })
        })
        .collect()
}

fn output_map_payload_formula_table(
    decoded_payload: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    decoded_payload
        .iter()
        .filter(|row| {
            row.get("dropped_by_alignment")
                .and_then(|v| v.as_bool())
                != Some(true)
        })
        .map(|row| {
            let index_sources = row
                .get("index_sources")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .map(|source| {
                    serde_json::json!({
                        "pos": source.get("pos").cloned().unwrap_or(serde_json::Value::Null),
                        "char": source.get("char").cloned().unwrap_or(serde_json::Value::Null),
                        "index_hex": source.get("index_hex").cloned().unwrap_or(serde_json::Value::Null),
                        "match_count": source.get("match_count").cloned().unwrap_or(serde_json::Value::Null),
                        "interesting": formula_expression_list(source.pointer("/formulas/interesting")),
                        "semantic": formula_expression_list(source.pointer("/formulas/semantic")),
                        "interesting_refs": formula_reference_list(source.pointer("/formulas/interesting")),
                        "semantic_refs": formula_reference_list(source.pointer("/formulas/semantic")),
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "semantic_offset": row.get("semantic_offset").cloned().unwrap_or(serde_json::Value::Null),
                "payload_offset": row.get("payload_offset").cloned().unwrap_or(serde_json::Value::Null),
                "value_hex": row.get("value_hex").cloned().unwrap_or(serde_json::Value::Null),
                "base64_formula": row.get("formula").cloned().unwrap_or(serde_json::Value::Null),
                "index_sources": index_sources,
            })
        })
        .collect()
}

fn formula_expression_list(value: Option<&serde_json::Value>) -> Vec<serde_json::Value> {
    value
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|formula| {
            formula
                .get("expression")
                .cloned()
                .or_else(|| formula.get("asm").cloned())
        })
        .take(4)
        .collect()
}

fn formula_reference_list(value: Option<&serde_json::Value>) -> Vec<serde_json::Value> {
    value
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .take(4)
        .map(|formula| {
            let idx = formula
                .get("idx")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let reg = formula
                .get("reg")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let continue_with = if idx.is_null() || reg.is_null() {
                serde_json::Value::Null
            } else {
                serde_json::json!({
                    "cmd": "vm-backtree",
                    "idx": idx,
                    "reg": reg,
                })
            };
            serde_json::json!({
                "idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": formula.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "value": formula.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "asm": formula.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "expression": formula
                    .get("expression")
                    .cloned()
                    .or_else(|| formula.get("asm").cloned())
                    .unwrap_or(serde_json::Value::Null),
                "kind": formula
                    .pointer("/semantic/kind")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                "continue_with": continue_with,
            })
        })
        .collect()
}

fn compact_lookup_source_for_payload(lookup: &serde_json::Value) -> serde_json::Value {
    let formulas = lookup
        .get("matches")
        .and_then(|v| v.as_array())
        .and_then(|matches| matches.first())
        .map(|first| {
            let interesting = first
                .get("interesting_formulas")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(3)
                .cloned()
                .collect::<Vec<_>>();
            let semantic = first
                .get("semantic_formulas")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(3)
                .cloned()
                .collect::<Vec<_>>();
            serde_json::json!({
                "interesting": interesting,
                "semantic": semantic,
            })
        })
        .unwrap_or_else(|| {
            serde_json::json!({
                "interesting": [],
                "semantic": [],
            })
        });
    serde_json::json!({
        "pos": lookup.get("pos").cloned().unwrap_or(serde_json::Value::Null),
        "char": lookup.get("char").cloned().unwrap_or(serde_json::Value::Null),
        "index_hex": lookup.get("index_hex").cloned().unwrap_or(serde_json::Value::Null),
        "match_count": lookup.get("match_count").cloned().unwrap_or(serde_json::Value::Null),
        "formulas": formulas,
    })
}

fn output_map_lookup_summary(lookup: &serde_json::Value) -> serde_json::Value {
    let matches = lookup
        .get("matches")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            let interesting = item
                .pointer("/index_summary/interesting_formulas")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(6)
                .map(compact_formula_summary)
                .collect::<Vec<_>>();
            let semantic = item
                .pointer("/index_summary/semantic_formulas")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten()
                .take(6)
                .map(compact_formula_summary)
                .collect::<Vec<_>>();
            serde_json::json!({
                "idx": item.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": item.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "index_reg": item.get("index_reg").cloned().unwrap_or(serde_json::Value::Null),
                "base_value": item.get("base_value").cloned().unwrap_or(serde_json::Value::Null),
                "interesting_formulas": interesting,
                "semantic_formulas": semantic,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "pos": lookup.get("pos").cloned().unwrap_or(serde_json::Value::Null),
        "char": lookup.get("char").cloned().unwrap_or(serde_json::Value::Null),
        "index_hex": lookup.get("index_hex").cloned().unwrap_or(serde_json::Value::Null),
        "match_count": lookup
            .get("matches")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0),
        "matches": matches,
    })
}

fn compact_formula_summary(formula: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": formula.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": formula.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "asm": formula.get("asm").cloned().unwrap_or(serde_json::Value::Null),
        "expression": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
        "semantic": formula.get("semantic").cloned().unwrap_or(serde_json::Value::Null),
    })
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
        "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28";
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
            None,
            regs.to_string(),
            &opts.vm_profile,
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

async fn vm_chains_for_byte_writer_runs(
    app: &axum::Router,
    writer_runs: &[serde_json::Value],
    steps: usize,
    max_runs: usize,
    lookback: usize,
    follow_frontier: bool,
    profile: &VmProfile,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let regs =
        "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28";
    let mut out = Vec::new();
    for run in writer_runs.iter().take(max_runs) {
        let writer = run.get("writer").unwrap_or(&serde_json::Value::Null);
        let Some(idx) = writer.get("idx").and_then(|v| v.as_u64()) else {
            out.push(serde_json::json!({
                "start_offset": run.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
                "end_offset": run.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
                "status": "no_writer_idx",
            }));
            continue;
        };
        let Some(reg) = writer.get("src_reg").and_then(|v| v.as_str()) else {
            out.push(serde_json::json!({
                "start_offset": run.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
                "end_offset": run.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
                "writer_idx": idx,
                "status": "no_source_reg",
                "writer": writer,
            }));
            continue;
        };
        let chain = vm_backchain_value_on(
            app,
            idx as usize,
            Some(reg.to_string()),
            steps,
            120,
            lookback,
            5000,
            follow_frontier,
            byte_lane_from_writer_run(run),
            regs.to_string(),
            profile,
        )
        .await?;
        let seed_byte_lane = byte_lane_from_writer_run(run);
        out.push(serde_json::json!({
            "start_offset": run.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
            "end_offset": run.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
            "size": run.get("size").cloned().unwrap_or(serde_json::Value::Null),
            "bytes_hex": run.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
            "ascii": run.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offsets": run.get("source_byte_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
            "writer_idx": idx,
            "seed": {
                "idx": idx,
                "reg": reg,
                "byte_lane": seed_byte_lane,
                "src_value": writer.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "asm": writer.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "func": writer.get("func").cloned().unwrap_or(serde_json::Value::Null),
            },
            "chain": vm_backchain_summary(&chain),
        }));
    }
    Ok(out)
}

async fn vm_chains_for_byte_writer_entries(
    app: &axum::Router,
    bytes: &[serde_json::Value],
    steps: usize,
    max_bytes: usize,
    lookback: usize,
    follow_frontier: bool,
    profile: &VmProfile,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let regs =
        "x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,x10,x11,x12,x13,x14,x15,x16,x17,x18,x19,x20,x21,x22,x23,x24,x25,x26,x27,x28";
    let mut out = Vec::new();
    for entry in bytes.iter().take(max_bytes) {
        let offset = entry
            .get("offset")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let writer = entry.get("writer").unwrap_or(&serde_json::Value::Null);
        let Some(idx) = writer.get("idx").and_then(|v| v.as_u64()) else {
            out.push(serde_json::json!({
                "start_offset": offset,
                "end_offset": offset,
                "size": 1,
                "status": "no_writer_idx",
            }));
            continue;
        };
        let Some(reg) = writer.get("src_reg").and_then(|v| v.as_str()) else {
            out.push(serde_json::json!({
                "start_offset": offset,
                "end_offset": offset,
                "size": 1,
                "writer_idx": idx,
                "status": "no_source_reg",
                "writer": writer,
            }));
            continue;
        };
        let seed_byte_lane = byte_lane_from_writer_map_entry(entry);
        let chain = vm_backchain_value_on(
            app,
            idx as usize,
            Some(reg.to_string()),
            steps,
            120,
            lookback,
            5000,
            follow_frontier,
            seed_byte_lane,
            regs.to_string(),
            profile,
        )
        .await?;
        let byte_hex = entry
            .get("byte_hex")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.push(serde_json::json!({
            "start_offset": offset,
            "end_offset": offset,
            "size": 1,
            "bytes_hex": byte_hex,
            "ascii": entry.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offset": entry.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offsets": [
                entry.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null)
            ],
            "addr": entry.get("addr").cloned().unwrap_or(serde_json::Value::Null),
            "writer_idx": idx,
            "seed": {
                "idx": idx,
                "reg": reg,
                "byte_lane": seed_byte_lane,
                "src_value": writer.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
                "asm": writer.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "func": writer.get("func").cloned().unwrap_or(serde_json::Value::Null),
            },
            "chain": vm_backchain_summary(&chain),
        }));
    }
    Ok(out)
}

fn byte_lane_from_writer_run(run: &serde_json::Value) -> Option<usize> {
    run.get("source_byte_offset")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            run.get("source_byte_offsets")
                .and_then(|v| v.as_array())
                .and_then(|items| items.first())
                .and_then(|v| v.as_u64())
        })
        .map(|v| v as usize)
}

fn byte_lane_from_writer_map_entry(entry: &serde_json::Value) -> Option<usize> {
    entry
        .get("source_byte_offset")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
}

fn vm_chain_batch_summary(chains: &[serde_json::Value]) -> serde_json::Value {
    let mut semantic_counts = BTreeMap::<String, usize>::new();
    let mut pattern_counts = BTreeMap::<String, usize>::new();
    for chain in chains {
        if let Some(semantics) = chain
            .pointer("/chain/recognized_semantics")
            .and_then(|v| v.as_array())
        {
            for item in semantics {
                if let Some(kind) = item
                    .get("semantic")
                    .and_then(|v| v.get("kind"))
                    .and_then(|v| v.as_str())
                {
                    *semantic_counts.entry(kind.to_string()).or_insert(0) += 1;
                }
            }
        }
        if let Some(patterns) = chain
            .pointer("/chain/recognized_patterns")
            .and_then(|v| v.as_array())
        {
            for item in patterns {
                if let Some(kind) = item.get("kind").and_then(|v| v.as_str()) {
                    *pattern_counts.entry(kind.to_string()).or_insert(0) += 1;
                }
            }
        }
    }
    serde_json::json!({
        "chain_count": chains.len(),
        "semantic_kind_counts": semantic_counts
            .into_iter()
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect::<Vec<_>>(),
        "pattern_counts": pattern_counts
            .into_iter()
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect::<Vec<_>>(),
    })
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
    profile: VmProfile,
) -> anyhow::Result<()> {
    let end = end.unwrap_or_else(|| start.saturating_add(count));
    let (rows, source_returned, inferred_base) =
        load_vm_rows(trace_dir, start, end, regs, only_vm, base_ip, &profile).await?;

    print_pretty(&serde_json::json!({
        "status": "ready",
        "start": start,
        "end": end,
        "vm_profile": profile.to_json(),
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
    chunk_size: usize,
    summary: bool,
    effects_only: bool,
    profile: VmProfile,
) -> anyhow::Result<()> {
    let end = end.unwrap_or_else(|| start.saturating_add(count));
    let loaded = load_vm_rows_chunked(
        trace_dir, start, end, regs, true, base_ip, &profile, chunk_size,
    )
    .await?;
    let source_requested = end.saturating_sub(start);
    let all_ops = vm_ops_from_rows(&loaded.rows);
    let truncated = all_ops.len() > max_ops;
    let ops = all_ops.into_iter().take(max_ops).collect::<Vec<_>>();
    let output = serde_json::json!({
        "status": "ready",
        "start": start,
        "end": end,
        "vm_profile": profile.to_json(),
        "source_requested": source_requested,
        "source_returned": loaded.source_returned,
        "source_maybe_truncated": loaded.source_maybe_truncated,
        "source_chunks": loaded.chunks,
        "chunk_size": chunk_size,
        "vm_rows": loaded.rows.len(),
        "vm_base_ip": loaded.inferred_base.map(|v| format!("{v:#x}")),
        "ops_returned": ops.len(),
        "truncated": truncated,
        "ops": ops,
    });
    if effects_only {
        print_pretty(&vm_ops_effects_only_summary(&output))
    } else if summary {
        print_pretty(&vm_ops_output_summary(&output))
    } else {
        print_pretty(&output)
    }
}

fn vm_ops_output_summary(value: &serde_json::Value) -> serde_json::Value {
    let ops = value
        .get("ops")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(vm_op_summary)
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": value.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "end": value.get("end").cloned().unwrap_or(serde_json::Value::Null),
        "vm_profile": value.get("vm_profile").cloned().unwrap_or(serde_json::Value::Null),
        "source_requested": value.get("source_requested").cloned().unwrap_or(serde_json::Value::Null),
        "source_returned": value.get("source_returned").cloned().unwrap_or(serde_json::Value::Null),
        "source_maybe_truncated": value.get("source_maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
        "source_chunks": value.get("source_chunks").cloned().unwrap_or(serde_json::Value::Null),
        "chunk_size": value.get("chunk_size").cloned().unwrap_or(serde_json::Value::Null),
        "vm_rows": value.get("vm_rows").cloned().unwrap_or(serde_json::Value::Null),
        "vm_base_ip": value.get("vm_base_ip").cloned().unwrap_or(serde_json::Value::Null),
        "ops_returned": value.get("ops_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": value.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "semantic_counts": vm_ops_semantic_counts(&ops),
        "state_updates": vm_ops_state_updates(&ops),
        "ops": ops,
    })
}

fn vm_ops_effects_only_summary(value: &serde_json::Value) -> serde_json::Value {
    let ops = value
        .get("ops")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(vm_op_summary)
        .collect::<Vec<_>>();
    let mut effects = Vec::new();
    let mut byte_load_effects = Vec::new();
    let mut memory_store_effects = Vec::new();
    for op in &ops {
        let idx_start = op
            .get("idx_start")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let idx_end = op
            .get("idx_end")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        for effect in op
            .get("effects")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let mut compact = effect.clone();
            if let Some(obj) = compact.as_object_mut() {
                obj.insert("op_idx_start".to_string(), idx_start.clone());
                obj.insert("op_idx_end".to_string(), idx_end.clone());
            }
            if compact
                .get("source_byte_load")
                .map(|v| !v.is_null())
                .unwrap_or(false)
            {
                byte_load_effects.push(compact.clone());
            }
            if compact.get("kind").and_then(|v| v.as_str()) == Some("memory_store") {
                memory_store_effects.push(compact.clone());
            }
            effects.push(compact);
        }
    }
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": value.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "end": value.get("end").cloned().unwrap_or(serde_json::Value::Null),
        "vm_profile": value.get("vm_profile").cloned().unwrap_or(serde_json::Value::Null),
        "source_requested": value.get("source_requested").cloned().unwrap_or(serde_json::Value::Null),
        "source_returned": value.get("source_returned").cloned().unwrap_or(serde_json::Value::Null),
        "source_maybe_truncated": value.get("source_maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
        "source_chunks": value.get("source_chunks").cloned().unwrap_or(serde_json::Value::Null),
        "chunk_size": value.get("chunk_size").cloned().unwrap_or(serde_json::Value::Null),
        "vm_rows": value.get("vm_rows").cloned().unwrap_or(serde_json::Value::Null),
        "vm_base_ip": value.get("vm_base_ip").cloned().unwrap_or(serde_json::Value::Null),
        "ops_returned": value.get("ops_returned").cloned().unwrap_or(serde_json::Value::Null),
        "truncated": value.get("truncated").cloned().unwrap_or(serde_json::Value::Null),
        "effect_count": effects.len(),
        "byte_load_effect_count": byte_load_effects.len(),
        "memory_store_effect_count": memory_store_effects.len(),
        "semantic_counts": vm_ops_semantic_counts(&ops),
        "state_updates": vm_ops_state_updates(&ops),
        "byte_load_effects": byte_load_effects,
        "memory_store_effects": memory_store_effects,
        "effects": effects,
    })
}

fn vm_ops_semantic_counts(ops: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut semantic_counts = BTreeMap::<String, usize>::new();
    for op in ops {
        if let Some(formulas) = op.get("alu_formulas").and_then(|v| v.as_array()) {
            for formula in formulas {
                if let Some(kind) = formula
                    .get("semantic")
                    .and_then(|v| v.get("kind"))
                    .and_then(|v| v.as_str())
                {
                    *semantic_counts.entry(kind.to_string()).or_default() += 1;
                }
            }
        }
    }
    semantic_counts
        .into_iter()
        .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
        .collect::<Vec<_>>()
}

fn vm_op_summary(op: &serde_json::Value) -> serde_json::Value {
    let bytecode_reads = op
        .get("bytecode_reads")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|item| {
            serde_json::json!({
                "idx": item.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "offset": item.get("offset").cloned().unwrap_or(serde_json::Value::Null),
                "width": item.get("width").cloned().unwrap_or(serde_json::Value::Null),
                "bytes_le_hex": item.get("bytes_le_hex").cloned().unwrap_or(serde_json::Value::Null),
                "value": item.get("value").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    let alu_formulas = op
        .get("alu_formulas")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(|formula| {
            serde_json::json!({
                "idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "asm": formula.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "expression": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
                "semantic": formula.get("semantic").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "idx_start": op.get("idx_start").cloned().unwrap_or(serde_json::Value::Null),
        "idx_end": op.get("idx_end").cloned().unwrap_or(serde_json::Value::Null),
        "rows": op.get("rows").cloned().unwrap_or(serde_json::Value::Null),
        "class_counts": op.get("class_counts").cloned().unwrap_or(serde_json::Value::Null),
        "bytecode_reads": bytecode_reads,
        "vm_slot_reads": op.get("vm_slot_reads").cloned().unwrap_or_else(|| serde_json::json!([])),
        "vm_slot_writes": op.get("vm_slot_writes").cloned().unwrap_or_else(|| serde_json::json!([])),
        "small_byte_loads": op.get("small_byte_loads").cloned().unwrap_or_else(|| serde_json::json!([])),
        "memory_stores": op.get("memory_stores").cloned().unwrap_or_else(|| serde_json::json!([])),
        "alu_formulas": alu_formulas,
        "effects": vm_op_effect_summaries(op),
        "dispatches": op.get("dispatches").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

fn vm_op_effect_summaries(op: &serde_json::Value) -> Vec<serde_json::Value> {
    let mut effects = Vec::new();
    let formulas = op
        .get("alu_formulas")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for write in op
        .get("vm_slot_writes")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let value = write
            .get("value")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let formula = matching_formula_for_value(&formulas, &value);
        let source_byte_load = matching_byte_load_for_value(
            op.get("small_byte_loads")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten(),
            &value,
        );
        let slot = write
            .get("slot")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let rhs = formula
            .as_ref()
            .and_then(|f| f.get("expression"))
            .map(json_display)
            .or_else(|| {
                source_byte_load.as_ref().map(|load| {
                    format!(
                        "byte[{}] ({})",
                        json_display(load.get("mem_addr").unwrap_or(&serde_json::Value::Null)),
                        json_display(load.get("value").unwrap_or(&serde_json::Value::Null))
                    )
                })
            })
            .unwrap_or_else(|| json_display(&value));
        let pseudocode = format!("slot[{}] = {}", json_display(&slot), rhs);
        effects.push(serde_json::json!({
            "kind": "slot_write",
            "idx": write.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "slot": slot,
            "value": value,
            "pseudocode": pseudocode,
            "formula": formula.unwrap_or(serde_json::Value::Null),
            "source_byte_load": source_byte_load.unwrap_or(serde_json::Value::Null),
            "inputs": op.get("vm_slot_reads").cloned().unwrap_or_else(|| serde_json::json!([])),
        }));
    }
    for store in op
        .get("memory_stores")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
    {
        let src = store
            .get("store_src")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let src_value = src.get("value").cloned().unwrap_or(serde_json::Value::Null);
        let src_slot = source_slot_for_value(
            op.get("vm_slot_reads")
                .and_then(|v| v.as_array())
                .into_iter()
                .flatten(),
            &src_value,
        );
        if is_probable_vm_infra_store(store, src_slot.as_ref(), &src) {
            continue;
        }
        let pseudocode = if store.get("class").and_then(|v| v.as_str()) == Some("byte-store") {
            if let Some(slot) = src_slot.as_ref().and_then(|slot| slot.get("slot")) {
                format!(
                    "mem[{}] = low8(slot[{}])",
                    json_display(store.get("mem_addr").unwrap_or(&serde_json::Value::Null)),
                    json_display(slot)
                )
            } else {
                format!(
                    "mem[{}] = low8({})",
                    json_display(store.get("mem_addr").unwrap_or(&serde_json::Value::Null)),
                    json_display(&src_value)
                )
            }
        } else {
            format!(
                "mem[{}] = {}",
                json_display(store.get("mem_addr").unwrap_or(&serde_json::Value::Null)),
                json_display(&src_value)
            )
        };
        effects.push(serde_json::json!({
            "kind": "memory_store",
            "idx": store.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "class": store.get("class").cloned().unwrap_or(serde_json::Value::Null),
            "addr": store.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
            "src": src,
            "source_slot": src_slot.unwrap_or(serde_json::Value::Null),
            "pseudocode": pseudocode,
        }));
    }
    if effects.is_empty() {
        if let Some(formula) = formulas.iter().find(|formula| {
            formula
                .get("asm")
                .and_then(|v| v.as_str())
                .map(|asm| asm.contains("x21"))
                .unwrap_or(false)
        }) {
            effects.push(serde_json::json!({
                "kind": "control",
                "idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "pseudocode": formula.get("expression").cloned().unwrap_or(serde_json::Value::Null),
                "formula": formula,
            }));
        }
    }
    effects
}

fn is_probable_vm_infra_store(
    store: &serde_json::Value,
    src_slot: Option<&serde_json::Value>,
    src: &serde_json::Value,
) -> bool {
    if store.get("class").and_then(|v| v.as_str()) != Some("mem-store") {
        return false;
    }
    if src_slot.is_some() {
        return false;
    }
    matches!(
        src.get("reg").and_then(|v| v.as_str()),
        Some("x21" | "x23" | "x25" | "x27" | "sp" | "fp" | "lr")
    )
}

fn matching_formula_for_value(
    formulas: &[serde_json::Value],
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let wanted = json_u64(value)?;
    formulas
        .iter()
        .find(|formula| {
            formula
                .pointer("/semantic/result")
                .and_then(json_u64)
                .or_else(|| formula.get("expression").and_then(expression_lhs_u64))
                == Some(wanted)
        })
        .cloned()
}

fn source_slot_for_value<'a>(
    mut reads: impl Iterator<Item = &'a serde_json::Value>,
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let wanted = json_u64(value)?;
    reads
        .find(|read| read.get("value").and_then(json_u64) == Some(wanted))
        .cloned()
}

fn matching_byte_load_for_value<'a>(
    mut loads: impl Iterator<Item = &'a serde_json::Value>,
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let wanted = json_u64(value)?;
    loads
        .find(|load| load.get("value").and_then(json_u64) == Some(wanted))
        .cloned()
}

fn expression_lhs_u64(value: &serde_json::Value) -> Option<u64> {
    let text = value.as_str()?;
    let lhs = text.split('=').next()?.trim();
    parse_u64_str(lhs)
}

fn json_display(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| value.to_string())
}

fn vm_ops_state_updates(ops: &[serde_json::Value]) -> serde_json::Value {
    let mut updates = Vec::new();
    for (idx, op) in ops.iter().enumerate() {
        let formulas = op
            .get("alu_formulas")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|formula| {
                formula.pointer("/semantic/kind").and_then(|v| v.as_str()) == Some("add32_mix")
            });
        for formula in formulas {
            let Some(result) = formula.pointer("/semantic/result").and_then(|v| v.as_str()) else {
                continue;
            };
            for candidate in ops.iter().skip(idx).take(3) {
                let stores = candidate
                    .get("memory_stores")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten();
                for store in stores {
                    let Some(src) = memory_store_src_with_value(store, result) else {
                        continue;
                    };
                    updates.push(serde_json::json!({
                        "formula_op_start": op.get("idx_start").cloned().unwrap_or(serde_json::Value::Null),
                        "formula_idx": formula.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                        "formula_asm": formula.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                        "semantic": formula.get("semantic").cloned().unwrap_or(serde_json::Value::Null),
                        "store_op_start": candidate.get("idx_start").cloned().unwrap_or(serde_json::Value::Null),
                        "store_idx": store.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                        "store_asm": store.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                        "store_addr": store.get("mem_addr").cloned().unwrap_or(serde_json::Value::Null),
                        "store_src": src,
                    }));
                }
            }
        }
    }
    serde_json::Value::Array(updates)
}

fn memory_store_src_with_value(
    store: &serde_json::Value,
    value: &str,
) -> Option<serde_json::Value> {
    store
        .get("store_src")?
        .as_array()?
        .iter()
        .find(|src| src.get("value").and_then(|v| v.as_str()) == Some(value))
        .cloned()
}

struct LoadedVmRows {
    rows: Vec<serde_json::Value>,
    source_returned: usize,
    source_maybe_truncated: bool,
    chunks: usize,
    inferred_base: Option<u64>,
}

async fn load_vm_rows_chunked(
    trace_dir: PathBuf,
    start: usize,
    end: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: &VmProfile,
    chunk_size: usize,
) -> anyhow::Result<LoadedVmRows> {
    let total = end.saturating_sub(start);
    if total == 0 {
        return Ok(LoadedVmRows {
            rows: Vec::new(),
            source_returned: 0,
            source_maybe_truncated: false,
            chunks: 0,
            inferred_base: base_ip.as_deref().and_then(parse_u64_str),
        });
    }

    let effective_chunk_size = if chunk_size == 0 {
        total
    } else {
        chunk_size.max(1)
    };
    let mut cursor = start;
    let mut rows = Vec::new();
    let mut source_returned = 0usize;
    let mut source_maybe_truncated = false;
    let mut chunks = 0usize;
    let mut inferred_base = base_ip.as_deref().and_then(parse_u64_str);
    let mut base_arg = base_ip;

    while cursor < end {
        let chunk_end = cursor.saturating_add(effective_chunk_size).min(end);
        let request_end = if chunk_end < end {
            chunk_end.saturating_add(1)
        } else {
            chunk_end
        };
        let requested = request_end.saturating_sub(cursor);
        let non_overlap_requested = chunk_end.saturating_sub(cursor);
        let (mut chunk_rows, returned, chunk_base) = load_vm_rows(
            trace_dir.clone(),
            cursor,
            request_end,
            regs.clone(),
            only_vm,
            base_arg.clone(),
            profile,
        )
        .await?;
        chunks += 1;
        source_returned += returned.min(non_overlap_requested);
        if returned < requested {
            source_maybe_truncated = true;
        }
        if inferred_base.is_none() {
            inferred_base = chunk_base;
            if let Some(base) = chunk_base {
                base_arg = Some(format!("{base:#x}"));
            }
        }
        chunk_rows.retain(|row| {
            row.get("idx")
                .and_then(|v| v.as_u64())
                .map(|idx| {
                    let idx = idx as usize;
                    idx >= cursor && idx < chunk_end
                })
                .unwrap_or(false)
        });
        rows.extend(chunk_rows);
        cursor = chunk_end;
    }

    Ok(LoadedVmRows {
        rows,
        source_returned,
        source_maybe_truncated,
        chunks,
        inferred_base,
    })
}

async fn load_vm_rows(
    trace_dir: PathBuf,
    start: usize,
    end: usize,
    regs: String,
    only_vm: bool,
    base_ip: Option<String>,
    profile: &VmProfile,
) -> anyhow::Result<(Vec<serde_json::Value>, usize, Option<u64>)> {
    let count = end.saturating_sub(start);
    let regs = regs_with_vm_profile(regs, profile);
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
    let inferred_base = base_ip.as_deref().and_then(parse_u64_str).or_else(|| {
        records
            .iter()
            .find_map(|rec| record_reg_u64(rec, &profile.ip_reg))
    });

    let mut rows = Vec::new();
    for (pos, rec) in records.iter().enumerate() {
        let asm = rec.get("asm").and_then(|v| v.as_str()).unwrap_or("");
        let class = classify_vm_asm(asm, profile);
        if only_vm && class == "other" {
            continue;
        }
        let next = records.get(pos + 1);
        rows.push(vm_row_from_record(rec, next, inferred_base, profile));
    }
    Ok((rows, records.len(), inferred_base))
}

fn regs_with_vm_profile(regs: String, profile: &VmProfile) -> String {
    let mut items = split_csv(&regs);
    let mut seen = items
        .iter()
        .map(|reg| register_value_key(reg))
        .collect::<HashSet<_>>();
    for reg in [&profile.ip_reg, &profile.state_reg, &profile.dispatch_reg] {
        if seen.insert(reg.clone()) {
            items.push(reg.clone());
        }
    }
    items.join(",")
}

async fn cmd_vm_backstep(
    trace_dir: PathBuf,
    idx: usize,
    reg: Option<String>,
    context: usize,
    lookback: usize,
    max_writes: usize,
    regs: String,
    profile: VmProfile,
) -> anyhow::Result<()> {
    let app = tracemiku_server::build_router_with_memshadow(trace_dir)?;
    let value = vm_backstep_value_on(
        &app, idx, reg, context, lookback, max_writes, regs, &profile,
    )
    .await?;
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
    byte_lane: Option<usize>,
    regs: String,
    summary: bool,
    profile: VmProfile,
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
        byte_lane,
        regs,
        &profile,
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
    profile: VmProfile,
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
        &profile,
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
    byte_lane: Option<usize>,
    regs: String,
    profile: &VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let mut current_idx = idx;
    let mut current_reg = reg.clone();
    let mut current_byte_lane = byte_lane;
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    for step_idx in 0..steps {
        if !seen.insert(format!(
            "{}:{}:{}",
            current_idx,
            current_reg.as_deref().unwrap_or(""),
            current_byte_lane
                .map(|lane| lane.to_string())
                .unwrap_or_default()
        )) {
            rows.push(serde_json::json!({
                "step": step_idx,
                "status": "cycle",
                "idx": current_idx,
                "reg": current_reg,
                "byte_lane": current_byte_lane,
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
            profile,
        )
        .await?;
        let upstream_next = step
            .get("upstream")
            .and_then(|v| v.get("next"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let lane_next = current_byte_lane
            .and_then(|lane| choose_laned_upstream_next(&step, lane).map(|next| (lane, next)));
        let (chosen_next, decision) = if let Some((lane, next)) = lane_next {
            (
                next.clone(),
                serde_json::json!({
                    "kind": "upstream_byte_lane",
                    "byte_lane": lane,
                    "next": next,
                }),
            )
        } else if upstream_next.get("idx").and_then(|v| v.as_u64()).is_some() {
            (
                upstream_next,
                serde_json::json!({
                    "kind": "upstream_next",
                }),
            )
        } else if follow_frontier {
            match choose_frontier_next_for_lane(&step, current_byte_lane, profile) {
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
        current_byte_lane = chosen_next
            .get("source_byte_offset")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .or(current_byte_lane);
        rows.push(serde_json::json!({
            "step": step_idx,
            "byte_lane": current_byte_lane,
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
            "byte_lane": byte_lane,
        },
        "follow_frontier": follow_frontier,
        "vm_profile": profile.to_json(),
        "steps_requested": steps,
        "steps_returned": rows.len(),
        "chain": rows,
    }))
}

fn choose_laned_upstream_next(
    step: &serde_json::Value,
    byte_lane: usize,
) -> Option<serde_json::Value> {
    upstream_byte_nexts_from_step(step)
        .into_iter()
        .find(|next| next_matches_byte_lane(next, byte_lane))
        .map(|next| next_with_selected_byte_lane(next, byte_lane))
}

fn next_matches_byte_lane(next: &serde_json::Value, byte_lane: usize) -> bool {
    next.get("offset")
        .and_then(|v| v.as_u64())
        .is_some_and(|offset| offset as usize == byte_lane)
        || next
            .get("offsets")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .any(|offset| {
                offset
                    .as_u64()
                    .is_some_and(|offset| offset as usize == byte_lane)
            })
}

fn next_with_selected_byte_lane(
    mut next: serde_json::Value,
    byte_lane: usize,
) -> serde_json::Value {
    let selected_idx = next
        .get("offsets")
        .and_then(|v| v.as_array())
        .and_then(|offsets| {
            offsets
                .iter()
                .position(|offset| offset.as_u64().is_some_and(|v| v as usize == byte_lane))
        });
    if let Some(obj) = next.as_object_mut() {
        obj.insert(
            "selected_byte_lane".to_string(),
            serde_json::json!(byte_lane),
        );
        if let Some(idx) = selected_idx {
            if let Some(source_byte_offset) = obj
                .get("source_byte_offsets")
                .and_then(|v| v.as_array())
                .and_then(|items| items.get(idx))
                .cloned()
            {
                obj.insert("source_byte_offset".to_string(), source_byte_offset);
            }
            if let Some(addr) = obj
                .get("addrs")
                .and_then(|v| v.as_array())
                .and_then(|items| items.get(idx))
                .cloned()
            {
                obj.insert("addr".to_string(), addr);
            }
        }
    }
    next
}

#[cfg(test)]
fn choose_frontier_next(step: &serde_json::Value) -> Option<serde_json::Value> {
    choose_frontier_next_for_lane(step, None, &VmProfile::default_profile())
}

fn choose_frontier_next_for_lane(
    step: &serde_json::Value,
    byte_lane: Option<usize>,
    profile: &VmProfile,
) -> Option<serde_json::Value> {
    if step.pointer("/local_def/class").and_then(|v| v.as_str()) == Some("call-return") {
        return None;
    }
    if let Some(next) = choose_semantic_frontier_next(step, byte_lane) {
        return Some(next);
    }
    let frontiers = step.get("frontier")?.as_array()?;
    let mut candidates = frontiers
        .iter()
        .filter_map(|frontier| {
            let reg = frontier.get("reg")?.as_str()?;
            if profile.is_infrastructure_reg(reg) {
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

fn choose_semantic_frontier_next(
    step: &serde_json::Value,
    byte_lane: Option<usize>,
) -> Option<serde_json::Value> {
    let local_def = step.get("local_def")?;
    if local_def.get("class").and_then(|v| v.as_str()) == Some("call-return") {
        return None;
    }
    let formula = row_alu_formula(local_def)?;
    let op = formula.get("op").and_then(|v| v.as_str());
    if formula
        .pointer("/semantic/input")
        .and_then(|v| v.as_str())
        .is_some()
        && !matches!(op, Some("lsl" | "lsr" | "asr" | "ubfx"))
    {
        let input = formula
            .pointer("/semantic/input")
            .and_then(|v| v.as_str())?;
        return frontier_next_by_value(step, input)
            .map(|next| annotate_next_source_lane(next, byte_lane));
    }
    if formula.get("op").and_then(|v| v.as_str()) == Some("udiv") {
        let numerator = formula
            .get("operands")
            .and_then(|v| v.as_array())
            .and_then(|items| items.first())?;
        return next_for_formula_operand(step, numerator, byte_lane);
    }
    if matches!(
        formula.get("op").and_then(|v| v.as_str()),
        Some("add" | "orr")
    ) {
        let operands = formula.get("operands").and_then(|v| v.as_array())?;
        if operands.len() >= 2 {
            if formula.get("op").and_then(|v| v.as_str()) == Some("orr") {
                if let Some(lane) = byte_lane {
                    if let Some(input) =
                        choose_or_operand_for_lane(&operands[0], &operands[1], lane)
                    {
                        return next_for_formula_operand(step, input, Some(lane));
                    }
                }
            }
            let lhs_value = operands[0]
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let rhs_value = operands[1]
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let chosen = match (lhs_value, rhs_value) {
                (Some(lhs), Some(0)) if lhs != 0 => Some(&operands[0]),
                (Some(0), Some(rhs)) if rhs != 0 => Some(&operands[1]),
                _ => None,
            };
            if let Some(input) = chosen {
                return next_for_formula_operand(step, input, byte_lane);
            }
        }
    }
    if formula.pointer("/semantic/kind").and_then(|v| v.as_str()) == Some("mul_mod64") {
        let operands = formula.get("operands").and_then(|v| v.as_array())?;
        if operands.len() >= 2 {
            let lhs_value = operands[0]
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let rhs_value = operands[1]
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(parse_u64_str);
            let chosen = match (lhs_value, rhs_value) {
                (Some(lhs), Some(rhs)) if lhs > 0xff && rhs <= 0xff => Some(&operands[0]),
                (Some(lhs), Some(rhs)) if rhs > 0xff && lhs <= 0xff => Some(&operands[1]),
                _ => None,
            };
            if let Some(input) = chosen {
                return next_for_formula_operand(step, input, byte_lane);
            }
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
        let source_lane = byte_lane.and_then(|lane| source_lane_for_shift_formula(&formula, lane));
        return next_for_formula_operand(step, input, source_lane.or(byte_lane));
    }
    None
}

fn choose_or_operand_for_lane<'a>(
    lhs: &'a serde_json::Value,
    rhs: &'a serde_json::Value,
    lane: usize,
) -> Option<&'a serde_json::Value> {
    let lhs_byte = operand_value_u64(lhs).map(|value| byte_at_lane(value, lane));
    let rhs_byte = operand_value_u64(rhs).map(|value| byte_at_lane(value, lane));
    match (lhs_byte, rhs_byte) {
        (Some(Some(lhs_byte)), Some(Some(0))) if lhs_byte != 0 => Some(lhs),
        (Some(Some(0)), Some(Some(rhs_byte))) if rhs_byte != 0 => Some(rhs),
        _ => None,
    }
}

fn next_for_formula_operand(
    step: &serde_json::Value,
    operand: &serde_json::Value,
    source_lane: Option<usize>,
) -> Option<serde_json::Value> {
    if let Some(reg) = operand.get("reg").and_then(|v| v.as_str()) {
        return frontier_next_by_reg(step, reg)
            .map(|next| annotate_next_source_lane(next, source_lane));
    }
    if let Some(value) = operand.get("value").and_then(|v| v.as_str()) {
        return frontier_next_by_value(step, value)
            .map(|next| annotate_next_source_lane(next, source_lane));
    }
    None
}

fn annotate_next_source_lane(
    mut next: serde_json::Value,
    source_lane: Option<usize>,
) -> serde_json::Value {
    if let Some(lane) = source_lane {
        if let Some(obj) = next.as_object_mut() {
            obj.insert("source_byte_offset".to_string(), serde_json::json!(lane));
        }
    }
    next
}

fn source_lane_for_shift_formula(formula: &serde_json::Value, result_lane: usize) -> Option<usize> {
    let semantic = formula.get("semantic");
    let op = formula.get("op").and_then(|v| v.as_str());
    let kind = semantic
        .and_then(|v| v.get("kind"))
        .and_then(|v| v.as_str())
        .or(op)?;
    let result_bit = result_lane.checked_mul(8)?;
    let source_bit = match kind {
        "shift_right" | "lsr" | "asr" => {
            let shift = shift_amount_from_formula(formula, semantic)?;
            result_bit.checked_add(shift as usize)?
        }
        "shift_left" | "lsl" => {
            let shift = shift_amount_from_formula(formula, semantic)? as usize;
            result_bit.checked_sub(shift)?
        }
        "ubfx" | "bitmask_extract" => {
            let lsb = semantic
                .and_then(|v| v.get("lsb").or_else(|| v.get("shift")))
                .and_then(value_as_u64)
                .or_else(|| formula_operand_value_u64(formula, 2))? as usize;
            result_bit.checked_add(lsb)?
        }
        _ => return Some(result_lane),
    };
    (source_bit % 8 == 0).then_some(source_bit / 8)
}

fn shift_amount_from_formula(
    formula: &serde_json::Value,
    semantic: Option<&serde_json::Value>,
) -> Option<u64> {
    semantic
        .and_then(|v| v.get("shift"))
        .and_then(value_as_u64)
        .or_else(|| formula_operand_value_u64(formula, 1))
}

fn formula_operand_value_u64(formula: &serde_json::Value, idx: usize) -> Option<u64> {
    formula
        .get("operands")
        .and_then(|v| v.as_array())
        .and_then(|items| items.get(idx))
        .and_then(operand_value_u64)
}

fn operand_value_u64(operand: &serde_json::Value) -> Option<u64> {
    operand
        .get("value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
}

fn value_as_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_u64_str))
}

fn byte_at_lane(value: u64, lane: usize) -> Option<u8> {
    let shift = lane.checked_mul(8)?;
    (shift < 64).then_some(((value >> shift) & 0xff) as u8)
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
    profile: &VmProfile,
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
            profile,
        )
        .await?;
        let node_id = nodes.len();
        let upstream_next = backstep
            .get("upstream")
            .and_then(|v| v.get("next"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let upstream_byte_nexts = upstream_byte_nexts_from_step(&backstep);
        let frontier_nexts = frontier_nexts_from_step(&backstep, profile);
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
        "vm_profile": profile.to_json(),
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
    let bytecode_operands = bytecode_frontiers
        .iter()
        .map(bytecode_operand_summary)
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
        "bytecode_operands": bytecode_operands,
        "terminal_nodes": terminal_nodes,
    })
}

fn bytecode_operand_summary(node: &serde_json::Value) -> serde_json::Value {
    let producer_asm = node.pointer("/producer/asm").and_then(|v| v.as_str());
    serde_json::json!({
        "idx": node.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "depth": node.get("depth").cloned().unwrap_or(serde_json::Value::Null),
        "reg": node.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": node.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "offset": producer_asm.and_then(bytecode_offset_from_asm).map(|off| format!("{off:#x}")),
        "producer_asm": node.pointer("/producer/asm").cloned().unwrap_or(serde_json::Value::Null),
        "producer_addr": node.pointer("/producer/mem_addr").cloned().unwrap_or(serde_json::Value::Null),
        "consumer_asm": node.pointer("/consumer/asm").cloned().unwrap_or(serde_json::Value::Null),
        "consumer_class": node.pointer("/consumer/class").cloned().unwrap_or(serde_json::Value::Null),
    })
}

fn bytecode_offset_from_asm(asm: &str) -> Option<u64> {
    let hash = asm.find('#')?;
    let tail = &asm[hash + 1..];
    let raw = tail
        .split(|c: char| c == ']' || c == ',' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim();
    parse_u64_str(raw)
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
    AddrBefore {
        addr: u64,
        before_idx: usize,
    },
    RegAt {
        idx: usize,
        reg: String,
        byte_lane: Option<usize>,
    },
}

impl LineageSeed {
    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::AddrBefore { addr, before_idx } => serde_json::json!({
                "kind": "addr_before",
                "addr": format!("{addr:#x}"),
                "before_idx": before_idx,
            }),
            Self::RegAt {
                idx,
                reg,
                byte_lane,
            } => serde_json::json!({
                "kind": "reg_at",
                "idx": idx,
                "reg": reg,
                "byte_lane": byte_lane,
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
                let source_byte_offset = source_byte_offset_for_write_at(&write, addr);
                let next_seed = write
                    .get("writer_idx")
                    .and_then(|v| v.as_u64())
                    .zip(write.get("src_reg").and_then(|v| v.as_str()))
                    .map(|(idx, reg)| LineageSeed::RegAt {
                        idx: idx as usize,
                        reg: reg.to_string(),
                        byte_lane: source_byte_offset.map(|lane| lane as usize),
                    });
                let next_json = next_seed.as_ref().map(LineageSeed::to_json);
                steps.push(serde_json::json!({
                    "step": step_idx,
                    "seed": seed_json,
                    "kind": "last_write",
                    "source_byte_offset": source_byte_offset,
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
            LineageSeed::RegAt {
                idx,
                ref reg,
                byte_lane,
            } => {
                let profile = VmProfile::default_profile();
                let backstep = vm_backstep_value_on(
                    app,
                    idx,
                    Some(reg.clone()),
                    context,
                    lookback,
                    max_writes,
                    regs.clone(),
                    &profile,
                )
                .await?;
                let (next_seed, decision) = lineage_next_from_backstep(&backstep, byte_lane);
                let next_json = next_seed.as_ref().map(LineageSeed::to_json);
                steps.push(serde_json::json!({
                    "step": step_idx,
                    "seed": seed_json,
                    "byte_lane": byte_lane,
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
        ("with_external", "true".to_string()),
    ];
    route_get_json_value_on(app, route_path("/api/last-write-of-addr", &params)).await
}

fn lineage_next_from_backstep(
    backstep: &serde_json::Value,
    current_byte_lane: Option<usize>,
) -> (Option<LineageSeed>, serde_json::Value) {
    if let Some(lane) = current_byte_lane {
        if let Some(next) = choose_laned_upstream_next(backstep, lane) {
            return (
                lineage_seed_from_next(&next, Some(lane)),
                serde_json::json!({
                    "kind": "upstream_byte_lane",
                    "byte_lane": lane,
                    "next": next,
                }),
            );
        }
    }
    let upstream_next = backstep
        .get("upstream")
        .and_then(|v| v.get("next"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if let Some(seed) = lineage_seed_from_next(&upstream_next, current_byte_lane) {
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
        if let Some(seed) = lineage_seed_from_next(&next, current_byte_lane) {
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
    let upstream_status = backstep
        .pointer("/upstream/status")
        .and_then(|v| v.as_str());
    if upstream_status == Some("observed_read_without_matching_traced_write") {
        return (
            None,
            serde_json::json!({
                "kind": "observed_read_without_matching_traced_write",
                "upstream": {
                    "addr": backstep.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "addr_hi": backstep.pointer("/upstream/addr_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_bytes_hex": backstep.pointer("/upstream/observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_mismatches": backstep.pointer("/upstream/observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
                    "last_write": backstep.pointer("/upstream/last_write").cloned().unwrap_or(serde_json::Value::Null),
                    "gap_call_candidates": compact_gap_call_candidates(backstep.pointer("/upstream/gap_call_candidates")),
                },
            }),
        );
    }
    if let Some(frontier_next) =
        choose_frontier_next_for_lane(backstep, current_byte_lane, &VmProfile::default_profile())
    {
        return (
            lineage_seed_from_next(&frontier_next, current_byte_lane),
            serde_json::json!({
                "kind": "frontier_auto",
                "next": frontier_next,
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

fn lineage_seed_from_next(
    next: &serde_json::Value,
    fallback_byte_lane: Option<usize>,
) -> Option<LineageSeed> {
    let idx = next.get("idx")?.as_u64()? as usize;
    let reg = next.get("reg")?.as_str()?.to_string();
    let byte_lane = next
        .get("source_byte_offset")
        .and_then(|v| v.as_u64())
        .map(|lane| lane as usize)
        .or(fallback_byte_lane);
    Some(LineageSeed::RegAt {
        idx,
        reg,
        byte_lane,
    })
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
            "idx_lo": upstream.get("idx_lo").cloned().unwrap_or(serde_json::Value::Null),
            "idx_hi": upstream.get("idx_hi").cloned().unwrap_or(serde_json::Value::Null),
            "returned": upstream.get("returned").cloned().unwrap_or(serde_json::Value::Null),
            "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
            "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
            "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
            "observed_mismatches": upstream.get("observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
            "next": upstream.get("next").cloned().unwrap_or(serde_json::Value::Null),
            "last_write": upstream.get("last_write").cloned().unwrap_or(serde_json::Value::Null),
            "byte_nexts": upstream.get("byte_nexts").cloned().unwrap_or_else(|| serde_json::json!([])),
            "gap_call_candidates": compact_gap_call_candidates(upstream.get("gap_call_candidates")),
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
    let memory_boundaries = chain
        .iter()
        .filter_map(|step| {
            let decision = step.get("decision")?;
            if decision.get("kind").and_then(|v| v.as_str())
                != Some("observed_read_without_matching_traced_write")
            {
                return None;
            }
            Some(serde_json::json!({
                "step": step.get("step").cloned().unwrap_or(serde_json::Value::Null),
                "idx": step.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "reg": step.get("reg").cloned().unwrap_or(serde_json::Value::Null),
                "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                "upstream": decision.get("upstream").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": lineage.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": lineage.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "depth_requested": lineage.get("depth_requested").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": lineage.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "stop_reason": compact_lineage_stop_reason(lineage.get("stop_reason")),
        "recognized_semantics": recognized_semantics,
        "memory_boundaries": memory_boundaries,
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
    let stop = vm_backchain_stop_summary(&chain);
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
    let recognized_pattern_summary = recognized_backchain_pattern_summary(&recognized_patterns);
    serde_json::json!({
        "status": backchain.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "start": backchain.get("start").cloned().unwrap_or(serde_json::Value::Null),
        "follow_frontier": backchain.get("follow_frontier").cloned().unwrap_or(serde_json::Value::Null),
        "steps_requested": backchain.get("steps_requested").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": backchain.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "stop": stop,
        "recognized_semantics": recognized_semantics,
        "recognized_patterns": recognized_patterns,
        "recognized_pattern_summary": recognized_pattern_summary,
        "chain": chain,
    })
}

fn vm_backchain_stop_summary(chain: &[serde_json::Value]) -> serde_json::Value {
    let Some(last) = chain.last() else {
        return serde_json::Value::Null;
    };
    let decision = last
        .get("decision")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if decision.get("kind").and_then(|v| v.as_str()) != Some("stop") {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "step": last.get("step").cloned().unwrap_or(serde_json::Value::Null),
        "idx": last.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "reg": last.get("reg").cloned().unwrap_or(serde_json::Value::Null),
        "value": last.get("value").cloned().unwrap_or(serde_json::Value::Null),
        "target": last.get("target").cloned().unwrap_or(serde_json::Value::Null),
        "local_def": last.get("local_def").cloned().unwrap_or(serde_json::Value::Null),
        "upstream": last.get("upstream").cloned().unwrap_or(serde_json::Value::Null),
        "decision": decision,
    })
}

#[derive(Debug, Default)]
struct AffinePatternGroup {
    multiplier: String,
    delta: String,
    multiplier_inverse: serde_json::Value,
    multiplier_odd: serde_json::Value,
    transitions: Vec<serde_json::Value>,
}

fn recognized_backchain_pattern_summary(patterns: &[serde_json::Value]) -> serde_json::Value {
    let mut affine = BTreeMap::<String, AffinePatternGroup>::new();
    let mut kind_counts = BTreeMap::<String, usize>::new();
    let mut static_memory_loads = Vec::new();
    let mut memory_boundary_reads = Vec::new();
    for pattern in patterns {
        let Some(kind) = pattern.get("kind").and_then(|v| v.as_str()) else {
            continue;
        };
        *kind_counts.entry(kind.to_string()).or_insert(0) += 1;
        if kind == "static_memory_load_constant" {
            static_memory_loads.push(pattern.clone());
            continue;
        }
        if kind == "memory_boundary_read" {
            memory_boundary_reads.push(pattern.clone());
            continue;
        }
        if kind != "affine_mod64_state_step" {
            continue;
        }
        let Some(multiplier) = pattern.get("multiplier").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(delta) = pattern.get("delta").and_then(|v| v.as_str()) else {
            continue;
        };
        let key = format!("{multiplier}|{delta}");
        let group = affine.entry(key).or_insert_with(|| AffinePatternGroup {
            multiplier: multiplier.to_string(),
            delta: delta.to_string(),
            multiplier_inverse: pattern
                .get("multiplier_inverse")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            multiplier_odd: pattern
                .get("multiplier_odd")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            ..AffinePatternGroup::default()
        });
        group.transitions.push(serde_json::json!({
            "add_step": pattern.get("add_step").cloned().unwrap_or(serde_json::Value::Null),
            "mul_step": pattern.get("mul_step").cloned().unwrap_or(serde_json::Value::Null),
            "previous_state": pattern.get("previous_state").cloned().unwrap_or(serde_json::Value::Null),
            "state": pattern.get("state").cloned().unwrap_or(serde_json::Value::Null),
        }));
    }
    serde_json::json!({
        "kind_counts": kind_counts
            .into_iter()
            .map(|(kind, count)| serde_json::json!({ "kind": kind, "count": count }))
            .collect::<Vec<_>>(),
        "affine_mod64_recurrences": affine
            .into_values()
            .map(|group| serde_json::json!({
                "kind": "affine_mod64_recurrence",
                "count": group.transitions.len(),
                "multiplier": group.multiplier,
                "delta": group.delta,
                "multiplier_inverse": group.multiplier_inverse,
                "multiplier_odd": group.multiplier_odd,
                "expression": "state == (previous_state * multiplier + delta) mod 2^64",
                "transitions": group.transitions,
            }))
            .collect::<Vec<_>>(),
        "static_memory_loads": static_memory_loads,
        "memory_boundary_reads": memory_boundary_reads,
    })
}

fn recognized_backchain_patterns(chain: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut patterns = Vec::new();
    for (idx, step) in chain.iter().enumerate() {
        if step.pointer("/local_def/class").and_then(|v| v.as_str()) == Some("mem-load")
            && step.pointer("/upstream/status").and_then(|v| v.as_str()) == Some("not_found")
        {
            if let Some(bytes_hex) = step
                .pointer("/upstream/observed_bytes_hex")
                .and_then(|v| v.as_str())
            {
                patterns.push(serde_json::json!({
                    "kind": "static_memory_load_constant",
                    "step": step.get("step").cloned().unwrap_or_else(|| serde_json::json!(idx)),
                    "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                    "addr": step.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "bytes_hex": bytes_hex,
                    "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    "upstream_status": step.pointer("/upstream/status").cloned().unwrap_or(serde_json::Value::Null),
                    "idx_lo": step.pointer("/upstream/idx_lo").cloned().unwrap_or(serde_json::Value::Null),
                    "idx_hi": step.pointer("/upstream/idx_hi").cloned().unwrap_or(serde_json::Value::Null),
                    "returned": step.pointer("/upstream/returned").cloned().unwrap_or(serde_json::Value::Null),
                    "maybe_truncated": step.pointer("/upstream/maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
                    "source_boundary": if step.pointer("/upstream/idx_lo").and_then(|v| v.as_u64()).unwrap_or(0) > 0 {
                        "lookback_window"
                    } else {
                        "trace_start"
                    },
                    "expression": "value loaded from memory with no writer found in current lookback window",
                    "caution": "Increase --lookback before treating this as a true static/pre-trace constant",
                }));
            }
        }
        if step.pointer("/local_def/class").and_then(|v| v.as_str()) == Some("mem-load")
            && step.pointer("/upstream/status").and_then(|v| v.as_str())
                == Some("observed_read_without_matching_traced_write")
        {
            if let Some(bytes_hex) = step
                .pointer("/upstream/observed_bytes_hex")
                .and_then(|v| v.as_str())
            {
                patterns.push(serde_json::json!({
                    "kind": "memory_boundary_read",
                    "step": step.get("step").cloned().unwrap_or_else(|| serde_json::json!(idx)),
                    "idx": step.pointer("/local_def/idx").cloned().unwrap_or(serde_json::Value::Null),
                    "asm": step.pointer("/local_def/asm").cloned().unwrap_or(serde_json::Value::Null),
                    "addr": step.pointer("/upstream/addr").cloned().unwrap_or(serde_json::Value::Null),
                    "bytes_hex": bytes_hex,
                    "value": step.get("value").cloned().unwrap_or(serde_json::Value::Null),
                    "last_write": step.pointer("/upstream/last_write").cloned().unwrap_or(serde_json::Value::Null),
                    "observed_mismatches": step
                        .pointer("/upstream/observed_mismatches")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([])),
                    "expression": "value loaded from memory but latest traced write does not explain observed bytes",
                }));
            }
        }
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
        "byte_lane": step.get("byte_lane").cloned().unwrap_or(serde_json::Value::Null),
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
                "seed": step.get("seed").cloned().unwrap_or(serde_json::Value::Null),
                "kind": "last_write",
                "source_byte_offset": step.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
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
                    "seed": step.get("seed").cloned().unwrap_or(serde_json::Value::Null),
                    "byte_lane": step.get("byte_lane").cloned().unwrap_or(serde_json::Value::Null),
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
                "idx_lo": upstream.get("idx_lo").cloned().unwrap_or(serde_json::Value::Null),
                "idx_hi": upstream.get("idx_hi").cloned().unwrap_or(serde_json::Value::Null),
                "returned": upstream.get("returned").cloned().unwrap_or(serde_json::Value::Null),
                "maybe_truncated": upstream.get("maybe_truncated").cloned().unwrap_or(serde_json::Value::Null),
                "next": upstream.get("next").cloned().unwrap_or(serde_json::Value::Null),
                "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
                "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
                "observed_mismatches": upstream.get("observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
                "last_write": compact_lineage_last_write(upstream.get("last_write")),
                "byte_nexts": compact_lineage_byte_nexts(upstream.get("byte_nexts")),
                "gap_call_candidates": compact_gap_call_candidates(upstream.get("gap_call_candidates")),
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

fn compact_gap_call_candidates(value: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(value) = value else {
        return serde_json::Value::Null;
    };
    if value.is_null() {
        return serde_json::Value::Null;
    }
    let candidates = value
        .get("candidates")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .take(8)
        .map(|candidate| {
            serde_json::json!({
                "idx": candidate.get("idx").cloned().unwrap_or(serde_json::Value::Null),
                "asm": candidate.get("asm").cloned().unwrap_or(serde_json::Value::Null),
                "target_addr": candidate.get("target_addr").cloned().unwrap_or(serde_json::Value::Null),
                "target_module": candidate.get("target_module").cloned().unwrap_or(serde_json::Value::Null),
                "external_to_primary": candidate.get("external_to_primary").cloned().unwrap_or(serde_json::Value::Null),
                "arg_offsets": candidate.get("arg_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
                "span_matches": candidate.get("span_matches").cloned().unwrap_or_else(|| serde_json::json!([])),
                "near_regs": candidate.get("near_regs").cloned().unwrap_or_else(|| serde_json::json!([])),
                "score": candidate.get("score").cloned().unwrap_or(serde_json::Value::Null),
                "score_adjustment_trace_write": candidate.get("score_adjustment_trace_write").cloned().unwrap_or(serde_json::Value::Null),
                "callee_trace": candidate.get("callee_trace").cloned().unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": value.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "scan_idx_lo": value.get("scan_idx_lo").cloned().unwrap_or(serde_json::Value::Null),
        "scan_idx_hi": value.get("scan_idx_hi").cloned().unwrap_or(serde_json::Value::Null),
        "candidate_count_total": value.get("candidate_count_total").cloned().unwrap_or(serde_json::Value::Null),
        "truncated_by_record_cap": value.get("truncated_by_record_cap").cloned().unwrap_or(serde_json::Value::Null),
        "candidates": candidates,
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
                "source_byte_offset": next.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
                "source_byte_offsets": next.get("source_byte_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
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

fn frontier_nexts_from_step(
    step: &serde_json::Value,
    profile: &VmProfile,
) -> Vec<serde_json::Value> {
    step.get("frontier")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|frontier| {
            let reg = frontier.get("reg")?.as_str()?;
            if profile.is_infrastructure_reg(reg) {
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
            "observed_bytes_hex": upstream.get("observed_bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
            "last_write_matches_observed": upstream.get("last_write_matches_observed").cloned().unwrap_or(serde_json::Value::Null),
            "observed_mismatches": upstream.get("observed_mismatches").cloned().unwrap_or_else(|| serde_json::json!([])),
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
    profile: &VmProfile,
) -> anyhow::Result<serde_json::Value> {
    let start = idx.saturating_sub(context);
    let count = context.saturating_add(3);
    let regs = regs_with_vm_profile(regs, profile);
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
    let inferred_base = records
        .iter()
        .find_map(|rec| record_reg_u64(rec, &profile.ip_reg));
    let rows = records
        .iter()
        .enumerate()
        .map(|(pos, rec)| vm_row_from_record(rec, records.get(pos + 1), inferred_base, profile))
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
        "vm_profile": profile.to_json(),
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
    profile: &VmProfile,
) -> serde_json::Value {
    let asm = rec.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let class = classify_vm_asm(asm, profile);
    let vm_ip = record_reg_u64(rec, &profile.ip_reg);
    let vm_off = vm_ip.and_then(|ip| inferred_base.map(|base| ip.wrapping_sub(base)));
    let vm_slot = vm_slot_from_asm(asm, rec, profile);
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
    let observed_bytes = observed_load_bytes(def_row, size);
    let observed_mismatches = observed_bytes
        .as_deref()
        .map(|bytes| observed_byte_writer_mismatches(addr, bytes, &byte_writers))
        .unwrap_or_default();
    let matches_observed = observed_mismatches.is_empty();
    let byte_nexts = if matches_observed {
        dedupe_byte_nexts(&byte_writers)
    } else {
        Vec::new()
    };
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
    let status = if last_write.is_some() && matches_observed {
        "ready"
    } else if last_write.is_some() {
        "observed_read_without_matching_traced_write"
    } else {
        "not_found"
    };
    let gap_call_candidates = if status == "observed_read_without_matching_traced_write" {
        match gap_call_candidates_for_mismatch_on(app, addr, idx, last_write.as_ref()).await {
            Ok(value) => value,
            Err(err) => serde_json::json!({
                "status": "error",
                "error": err.to_string(),
            }),
        }
    } else {
        serde_json::Value::Null
    };
    Ok(serde_json::json!({
        "status": status,
        "kind": kind,
        "addr": format!("{addr:#x}"),
        "addr_hi": format!("{addr_hi:#x}"),
        "idx_lo": idx_lo,
        "idx_hi": idx_hi,
        "returned": writes.len(),
        "maybe_truncated": range_truncated,
        "observed_bytes_hex": observed_bytes.as_ref().map(|bytes| bytes_to_hex(bytes)),
        "last_write_matches_observed": matches_observed,
        "observed_mismatches": observed_mismatches,
        "last_write": last_write,
        "writes_tail": writes_tail,
        "byte_writers": byte_writers,
        "byte_nexts": byte_nexts,
        "gap_call_candidates": gap_call_candidates,
        "next": matches_observed.then(|| last_write.as_ref().and_then(|write| {
            Some(serde_json::json!({
                "idx": write.get("idx")?,
                "reg": write.get("src_reg")?,
                "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            }))
        })).flatten(),
    }))
}

async fn gap_call_candidates_for_mismatch_on(
    app: &axum::Router,
    addr: u64,
    read_idx: usize,
    last_write: Option<&serde_json::Value>,
) -> anyhow::Result<serde_json::Value> {
    let Some(last_write_idx) = last_write
        .and_then(|write| write.get("idx"))
        .and_then(|v| v.as_u64())
        .map(|idx| idx as usize)
    else {
        return Ok(serde_json::json!({
            "status": "no_last_write",
            "addr": format!("{addr:#x}"),
            "read_idx": read_idx,
            "candidates": [],
        }));
    };
    if last_write_idx >= read_idx {
        return Ok(serde_json::json!({
            "status": "empty_gap",
            "addr": format!("{addr:#x}"),
            "read_idx": read_idx,
            "last_write_idx": last_write_idx,
            "candidates": [],
        }));
    }

    let requested_scan_start = last_write_idx.saturating_add(1);
    let gap_len = read_idx.saturating_sub(requested_scan_start);
    let (scan_start, truncated_by_record_cap) = if gap_len > GAP_SCAN_MAX_RECORDS {
        (read_idx.saturating_sub(GAP_SCAN_MAX_RECORDS), true)
    } else {
        (requested_scan_start, false)
    };
    let meta = route_get_json_value_on(app, "/api/meta".to_string()).await?;
    let primary = primary_module_bounds(&meta);
    let mut candidates = Vec::new();
    let mut gap_records = Vec::new();
    let mut cursor = scan_start;
    let mut fetched = 0usize;

    while cursor < read_idx {
        let count = read_idx.saturating_sub(cursor).min(GAP_SCAN_CHUNK);
        if count == 0 {
            break;
        }
        let params = vec![
            ("start", cursor.to_string()),
            ("count", count.to_string()),
            ("regs", GAP_SCAN_REGS.to_string()),
            ("fields", "idx,pc,func,asm,regs".to_string()),
        ];
        let response = route_get_json_value_on(app, route_path("/api/records", &params)).await?;
        let records = response
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if records.is_empty() {
            break;
        }
        fetched = fetched.saturating_add(records.len());
        gap_records.extend(records.iter().cloned());
        for record in &records {
            if let Some(candidate) =
                gap_call_candidate_from_record(record, &meta, primary.as_ref(), addr)
            {
                candidates.push(candidate);
            }
        }
        let last_idx = records
            .last()
            .and_then(|record| record.get("idx"))
            .and_then(|v| v.as_u64())
            .map(|idx| idx as usize);
        cursor = last_idx
            .map(|idx| idx.saturating_add(1))
            .unwrap_or_else(|| cursor.saturating_add(records.len()));
        if records.len() < count {
            break;
        }
    }

    let candidate_count_total = candidates.len();
    for candidate in &mut candidates {
        enrich_gap_call_candidate_trace_writes(candidate, &gap_records, addr);
    }
    candidates.sort_by(|a, b| {
        let ascore = a.get("score").and_then(|v| v.as_i64()).unwrap_or(0);
        let bscore = b.get("score").and_then(|v| v.as_i64()).unwrap_or(0);
        let aidx = a.get("idx").and_then(|v| v.as_u64()).unwrap_or(0);
        let bidx = b.get("idx").and_then(|v| v.as_u64()).unwrap_or(0);
        bscore.cmp(&ascore).then_with(|| aidx.cmp(&bidx))
    });
    if candidates.len() > GAP_SCAN_MAX_CANDIDATES {
        candidates.truncate(GAP_SCAN_MAX_CANDIDATES);
    }

    Ok(serde_json::json!({
        "status": "ready",
        "addr": format!("{addr:#x}"),
        "read_idx": read_idx,
        "last_write_idx": last_write_idx,
        "scan_idx_lo": scan_start,
        "scan_idx_hi": read_idx,
        "requested_scan_idx_lo": requested_scan_start,
        "fetched_records": fetched,
        "truncated_by_record_cap": truncated_by_record_cap,
        "candidate_count_total": candidate_count_total,
        "candidate_count_returned": candidates.len(),
        "candidates": candidates,
    }))
}

fn enrich_gap_call_candidate_trace_writes(
    candidate: &mut serde_json::Value,
    records: &[serde_json::Value],
    addr: u64,
) {
    if candidate
        .get("external_to_primary")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        if let Some(obj) = candidate.as_object_mut() {
            obj.insert(
                "callee_trace".to_string(),
                serde_json::json!({ "status": "external_or_untraced" }),
            );
        }
        return;
    }
    let Some(call_idx) = candidate
        .get("idx")
        .and_then(|v| v.as_u64())
        .map(|idx| idx as usize)
    else {
        return;
    };
    let Some(call_pc) = candidate
        .get("pc")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)
    else {
        return;
    };
    let return_pc = call_pc.wrapping_add(4);
    let mut rows = 0usize;
    let mut return_idx = None;
    let mut target_writes = Vec::new();
    for record in records {
        let Some(idx) = record
            .get("idx")
            .and_then(|v| v.as_u64())
            .map(|idx| idx as usize)
        else {
            continue;
        };
        if idx <= call_idx {
            continue;
        }
        if record
            .get("pc")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
            == Some(return_pc)
        {
            return_idx = Some(idx);
            break;
        }
        rows = rows.saturating_add(1);
        if let Some(write) = store_touch_for_addr(record, addr) {
            target_writes.push(write);
        }
    }
    let status = if !target_writes.is_empty() {
        "traced_callee_target_write"
    } else if return_idx.is_some() {
        "traced_callee_no_target_write"
    } else {
        "traced_callee_return_not_seen"
    };
    let score_adjustment = match status {
        "traced_callee_target_write" => 80,
        "traced_callee_no_target_write" => -50,
        _ => 0,
    };
    if let Some(obj) = candidate.as_object_mut() {
        let score = obj.get("score").and_then(|v| v.as_i64()).unwrap_or(0);
        obj.insert(
            "score".to_string(),
            serde_json::Value::from(score.saturating_add(score_adjustment)),
        );
        obj.insert(
            "score_adjustment_trace_write".to_string(),
            serde_json::Value::from(score_adjustment),
        );
        obj.insert(
            "callee_trace".to_string(),
            serde_json::json!({
                "status": status,
                "rows": rows,
                "return_pc": format!("{return_pc:#x}"),
                "return_idx": return_idx,
                "target_writes": target_writes,
            }),
        );
    }
}

fn store_touch_for_addr(record: &serde_json::Value, addr: u64) -> Option<serde_json::Value> {
    let asm = record.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let source_regs = store_source_regs_from_asm(asm);
    if source_regs.is_empty() {
        return None;
    }
    let mem_addr = mem_addr_from_asm(asm, record)?;
    let width = store_access_width(asm, &source_regs);
    let end = mem_addr.saturating_add(width);
    if !(mem_addr..end).contains(&addr) {
        return None;
    }
    Some(serde_json::json!({
        "idx": record.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "mem_addr": format!("{mem_addr:#x}"),
        "width": width,
        "offset": addr.saturating_sub(mem_addr),
    }))
}

fn store_access_width(asm: &str, source_regs: &[String]) -> u64 {
    let mnemonic = asm
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(mnemonic.as_str(), "stp" | "stnp" | "stxp" | "stlxp") {
        return source_regs
            .iter()
            .map(|reg| register_load_width(reg))
            .sum::<u64>()
            .max(1);
    }
    if mnemonic.ends_with('b') {
        return 1;
    }
    if mnemonic.ends_with('h') {
        return 2;
    }
    source_regs
        .first()
        .map(|reg| register_load_width(reg))
        .unwrap_or_else(|| memory_access_width(asm))
}

fn gap_call_candidate_from_record(
    record: &serde_json::Value,
    meta: &serde_json::Value,
    primary: Option<&(u64, u64, String)>,
    addr: u64,
) -> Option<serde_json::Value> {
    let asm = record.get("asm").and_then(|v| v.as_str()).unwrap_or("");
    let (call_kind, target_addr) = call_target_from_asm_record(asm, record)?;
    let target_module = module_for_addr(meta, target_addr);
    let external_to_primary = primary
        .map(|(start, end, _)| target_addr < *start || target_addr >= *end)
        .unwrap_or(false);
    let arg_offsets = call_arg_offsets(record, addr);
    let span_matches = call_arg_span_matches(record, addr);
    let near_regs = call_near_regs(record, addr);

    if !external_to_primary
        && arg_offsets.is_empty()
        && span_matches.is_empty()
        && near_regs.is_empty()
    {
        return None;
    }

    let mut score = 0i64;
    if external_to_primary {
        score += 1000;
    }
    score += (span_matches.len() as i64) * 40;
    score += (arg_offsets.len() as i64) * 16;
    score += (near_regs.len() as i64) * 4;
    if target_module
        .get("name")
        .and_then(|v| v.as_str())
        .map(|name| name.contains("libc"))
        .unwrap_or(false)
    {
        score += 6;
    }

    let args = (0..=7)
        .map(|idx| {
            let reg = format!("x{idx}");
            serde_json::json!({
                "reg": reg,
                "value": record_reg_value(record, &reg)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            })
        })
        .collect::<Vec<_>>();

    Some(serde_json::json!({
        "idx": record.get("idx").cloned().unwrap_or(serde_json::Value::Null),
        "pc": record.get("pc").cloned().unwrap_or(serde_json::Value::Null),
        "func": record.get("func").cloned().unwrap_or(serde_json::Value::Null),
        "asm": asm,
        "call_kind": call_kind,
        "target_addr": format!("{target_addr:#x}"),
        "target_module": target_module,
        "external_to_primary": external_to_primary,
        "arg_offsets": arg_offsets,
        "span_matches": span_matches,
        "near_regs": near_regs,
        "args": args,
        "score": score,
    }))
}

fn call_target_from_asm_record(asm: &str, record: &serde_json::Value) -> Option<(String, u64)> {
    let mut parts = asm.trim().split_whitespace();
    let op = parts.next()?;
    match op {
        "bl" => {
            let operand = parts.next()?.trim_start_matches('#').trim_end_matches(',');
            parse_u64_str(operand).map(|target| ("bl".to_string(), target))
        }
        "blr" => {
            let reg = parts.next()?.trim_end_matches(',');
            record_reg_u64(record, reg).map(|target| ("blr".to_string(), target))
        }
        _ => None,
    }
}

fn call_arg_offsets(record: &serde_json::Value, addr: u64) -> Vec<serde_json::Value> {
    (0..=7)
        .filter_map(|idx| {
            let reg = format!("x{idx}");
            let value = record_reg_u64(record, &reg)?;
            let offset = addr.checked_sub(value)?;
            (offset <= GAP_ARG_STRUCT_SPAN).then(|| {
                serde_json::json!({
                    "reg": reg,
                    "base": format!("{value:#x}"),
                    "offset": format!("{offset:#x}"),
                    "addr": format!("{addr:#x}"),
                })
            })
        })
        .collect()
}

fn call_arg_span_matches(record: &serde_json::Value, addr: u64) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    const PAIRS: &[(usize, usize)] = &[(0, 1), (0, 2), (1, 2), (1, 3), (2, 3), (3, 2)];
    for (base_idx, len_idx) in PAIRS {
        let base_reg = format!("x{base_idx}");
        let Some(base) = record_reg_u64(record, &base_reg) else {
            continue;
        };
        let len_reg = format!("x{len_idx}");
        let Some(len) = record_reg_u64(record, &len_reg) else {
            continue;
        };
        if len == 0 || len > GAP_SMALL_LEN_MAX {
            continue;
        }
        let end = base.saturating_add(len);
        if addr >= base && addr < end {
            out.push(serde_json::json!({
                "base_reg": base_reg,
                "base": format!("{base:#x}"),
                "len_reg": len_reg,
                "len": format!("{len:#x}"),
                "offset": format!("{:#x}", addr.saturating_sub(base)),
            }));
        }
    }
    out
}

fn call_near_regs(record: &serde_json::Value, addr: u64) -> Vec<serde_json::Value> {
    const REGS: &[&str] = &[
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x19", "x20", "x21", "x22", "x23", "x25",
    ];
    REGS.iter()
        .filter_map(|reg| {
            let value = record_reg_u64(record, reg)?;
            let delta = value.abs_diff(addr);
            (delta <= GAP_NEAR_REG_SPAN).then(|| {
                let signed = if value <= addr {
                    format!("+{:#x}", addr - value)
                } else {
                    format!("-{:#x}", value - addr)
                };
                serde_json::json!({
                    "reg": reg,
                    "value": format!("{value:#x}"),
                    "delta_to_addr": signed,
                })
            })
        })
        .collect()
}

fn primary_module_bounds(meta: &serde_json::Value) -> Option<(u64, u64, String)> {
    let module = meta.get("module")?;
    module_bounds(module)
}

fn module_bounds(module: &serde_json::Value) -> Option<(u64, u64, String)> {
    let base = module.get("base").and_then(json_u64)?;
    let end = module.get("end").and_then(json_u64).or_else(|| {
        module
            .get("size")
            .and_then(json_u64)
            .map(|size| base.saturating_add(size))
    })?;
    let name = module
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some((base, end, name))
}

fn module_for_addr(meta: &serde_json::Value, addr: u64) -> serde_json::Value {
    let Some(modules) = meta.get("modules").and_then(|v| v.as_array()) else {
        return serde_json::Value::Null;
    };
    for module in modules {
        let Some((base, end, name)) = module_bounds(module) else {
            continue;
        };
        if addr >= base && addr < end {
            return serde_json::json!({
                "name": name,
                "base": format!("{base:#x}"),
                "end": format!("{end:#x}"),
                "offset": format!("{:#x}", addr.saturating_sub(base)),
            });
        }
    }
    serde_json::Value::Null
}

fn json_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_u64_str))
}

fn observed_load_bytes(def_row: &serde_json::Value, size: u64) -> Option<Vec<u8>> {
    let value = def_row
        .pointer("/def/value_after")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    let width = (size as usize).min(8);
    Some(value.to_le_bytes()[..width].to_vec())
}

fn observed_byte_writer_mismatches(
    addr: u64,
    observed_bytes: &[u8],
    byte_writers: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    observed_bytes
        .iter()
        .enumerate()
        .filter_map(|(offset, observed)| {
            let writer = byte_writers.iter().find(|writer| {
                writer.get("offset").and_then(|v| v.as_u64()) == Some(offset as u64)
            });
            let writer_byte =
                writer
                    .and_then(|writer| writer.get("last_write"))
                    .and_then(|write| {
                        source_byte_for_write_at(write, addr.saturating_add(offset as u64))
                    });
            (writer_byte != Some(*observed)).then(|| {
                serde_json::json!({
                    "offset": offset,
                    "addr": format!("{:#x}", addr.saturating_add(offset as u64)),
                    "observed_byte": format!("{observed:02x}"),
                    "writer_byte": writer_byte.map(|byte| format!("{byte:02x}")),
                    "writer_idx": writer
                        .and_then(|writer| writer.pointer("/last_write/idx"))
                        .cloned()
                        .unwrap_or(serde_json::Value::Null),
                })
            })
        })
        .collect()
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
                "dst_addr": response
                    .get("dst_addr")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(format!("{byte_addr:#x}"))),
                "size": response
                    .get("size")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(1)),
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

fn byte_writer_map_output(
    addr: u64,
    size: usize,
    response: &serde_json::Value,
) -> serde_json::Value {
    let writes = response
        .get("writes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let bytes = byte_writer_map_entries_from_range_writes(addr, size, &writes);
    let missing_offsets = bytes
        .iter()
        .filter(|entry| entry.get("status").and_then(|v| v.as_str()) != Some("ready"))
        .filter_map(|entry| entry.get("offset").cloned())
        .collect::<Vec<_>>();
    let byte_values = bytes
        .iter()
        .map(|entry| {
            entry
                .get("byte_hex")
                .and_then(|v| v.as_str())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        })
        .collect::<Vec<_>>();
    let bytes_hex = if byte_values.iter().all(Option::is_some) {
        Some(
            byte_values
                .iter()
                .flatten()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
    } else {
        None
    };
    let ascii = byte_values
        .iter()
        .map(|byte| {
            byte.and_then(printable_ascii_char)
                .unwrap_or_else(|| ".".to_string())
        })
        .collect::<String>();
    let truncated = response
        .get("truncated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    serde_json::json!({
        "status": if missing_offsets.is_empty() && !truncated { "ready" } else { "partial" },
        "addr": format!("{addr:#x}"),
        "size": size,
        "idx_range": response.get("idx_range").cloned().unwrap_or(serde_json::Value::Null),
        "source": {
            "endpoint": "/api/mem-writes-in-range",
            "matched": response.get("matched").cloned().unwrap_or(serde_json::Value::Null),
            "returned": response.get("returned").cloned().unwrap_or(serde_json::Value::Null),
            "truncated": truncated,
        },
        "complete": missing_offsets.is_empty() && !truncated,
        "bytes_hex": bytes_hex,
        "ascii": ascii,
        "missing_offsets": missing_offsets,
        "writer_runs": byte_writer_runs(&bytes),
        "bytes": bytes,
        "warning": if truncated {
            serde_json::Value::String(
                "source writes were truncated; increase --max or narrow --idx-lo/--idx-hi before trusting latest writers".to_string(),
            )
        } else {
            serde_json::Value::Null
        },
    })
}

fn byte_writer_map_summary(output: &serde_json::Value) -> serde_json::Value {
    let bytes = output
        .get("bytes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let ready_count = bytes
        .iter()
        .filter(|entry| entry.get("status").and_then(|v| v.as_str()) == Some("ready"))
        .count();
    let writer_runs = output
        .get("writer_runs")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_byte_writer_run)
        .collect::<Vec<_>>();
    let vm_chains = output
        .get("vm_chains")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .map(compact_byte_writer_chain)
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": output.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "addr": output.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "size": output.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "idx_range": output.get("idx_range").cloned().unwrap_or(serde_json::Value::Null),
        "source": output.get("source").cloned().unwrap_or(serde_json::Value::Null),
        "complete": output.get("complete").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": output.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": output.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "byte_count": bytes.len(),
        "ready_byte_count": ready_count,
        "missing_offsets": output.get("missing_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
        "writer_run_count": writer_runs.len(),
        "writer_runs": writer_runs,
        "vm_chain_summary": output.get("vm_chain_summary").cloned().unwrap_or(serde_json::Value::Null),
        "vm_chains": vm_chains,
        "warning": output.get("warning").cloned().unwrap_or(serde_json::Value::Null),
    })
}

fn compact_byte_writer_run(run: &serde_json::Value) -> serde_json::Value {
    let writer = run.get("writer").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "start_offset": run.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
        "end_offset": run.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
        "size": run.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": run.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": run.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offset": run.get("source_byte_offset").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offsets": run.get("source_byte_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
        "writer": {
            "idx": writer.get("idx").cloned().unwrap_or(serde_json::Value::Null),
            "func": writer.get("func").cloned().unwrap_or(serde_json::Value::Null),
            "asm": writer.get("asm").cloned().unwrap_or(serde_json::Value::Null),
            "dst_addr": writer.get("dst_addr").cloned().unwrap_or(serde_json::Value::Null),
            "size": writer.get("size").cloned().unwrap_or(serde_json::Value::Null),
            "src_reg": writer.get("src_reg").cloned().unwrap_or(serde_json::Value::Null),
            "src_value": writer.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
        }
    })
}

fn compact_byte_writer_chain(chain: &serde_json::Value) -> serde_json::Value {
    let inner = chain.get("chain").unwrap_or(&serde_json::Value::Null);
    serde_json::json!({
        "start_offset": chain.get("start_offset").cloned().unwrap_or(serde_json::Value::Null),
        "end_offset": chain.get("end_offset").cloned().unwrap_or(serde_json::Value::Null),
        "size": chain.get("size").cloned().unwrap_or(serde_json::Value::Null),
        "bytes_hex": chain.get("bytes_hex").cloned().unwrap_or(serde_json::Value::Null),
        "ascii": chain.get("ascii").cloned().unwrap_or(serde_json::Value::Null),
        "source_byte_offsets": chain.get("source_byte_offsets").cloned().unwrap_or_else(|| serde_json::json!([])),
        "writer_idx": chain.get("writer_idx").cloned().unwrap_or(serde_json::Value::Null),
        "seed": chain.get("seed").cloned().unwrap_or(serde_json::Value::Null),
        "chain_status": inner.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "steps_returned": inner.get("steps_returned").cloned().unwrap_or(serde_json::Value::Null),
        "recognized_pattern_summary": inner.get("recognized_pattern_summary").cloned().unwrap_or(serde_json::Value::Null),
        "recognized_semantics": inner.get("recognized_semantics").cloned().unwrap_or_else(|| serde_json::json!([])),
    })
}

fn mem_dump_summary(response: &serde_json::Value, cstr: bool) -> serde_json::Value {
    let bytes = response
        .get("bytes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let byte_values = bytes
        .iter()
        .map(|entry| entry.get("byte").and_then(|v| v.as_u64()).map(|b| b as u8))
        .collect::<Vec<_>>();
    let known_count = byte_values.iter().filter(|byte| byte.is_some()).count();
    let bytes_hex = byte_values
        .iter()
        .map(|byte| {
            byte.map(|value| format!("{value:02x}"))
                .unwrap_or_else(|| "..".to_string())
        })
        .collect::<String>();
    let ascii = byte_values
        .iter()
        .map(|byte| {
            byte.and_then(printable_ascii_char)
                .unwrap_or_else(|| ".".to_string())
        })
        .collect::<String>();
    let nul_offset = byte_values.iter().position(|byte| matches!(byte, Some(0)));
    let c_string = if cstr {
        let raw = byte_values
            .iter()
            .take(nul_offset.unwrap_or(byte_values.len()))
            .filter_map(|byte| *byte)
            .collect::<Vec<_>>();
        serde_json::Value::String(String::from_utf8_lossy(&raw).into_owned())
    } else {
        serde_json::Value::Null
    };
    serde_json::json!({
        "status": response.get("status").cloned().unwrap_or(serde_json::Value::Null),
        "addr": response.get("addr").cloned().unwrap_or(serde_json::Value::Null),
        "count": response.get("count").cloned().unwrap_or(serde_json::Value::Null),
        "cursor": response.get("cursor").cloned().unwrap_or(serde_json::Value::Null),
        "known_byte_count": known_count,
        "bytes_hex": bytes_hex,
        "ascii": ascii,
        "c_string": c_string,
        "c_string_terminated": if cstr {
            serde_json::Value::Bool(nul_offset.is_some())
        } else {
            serde_json::Value::Null
        },
        "nul_offset": nul_offset
            .map(serde_json::Value::from)
            .unwrap_or(serde_json::Value::Null),
    })
}

async fn hash_candidate_byte_map(
    app: &axum::Router,
    candidate: &serde_json::Value,
    target_hex: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let addr_raw = candidate
        .get("addr")
        .and_then(|v| v.as_str())
        .context("hash candidate missing addr")?;
    let addr =
        parse_u64_str(addr_raw).with_context(|| format!("invalid candidate addr {addr_raw:?}"))?;
    let size = candidate
        .get("size")
        .and_then(|v| v.as_u64())
        .context("hash candidate missing size")?;
    let size_usize = usize::try_from(size).context("candidate size does not fit in usize")?;
    let enter_idx = candidate
        .get("enter_idx")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let exit_idx = candidate
        .get("exit_idx")
        .and_then(|v| v.as_u64())
        .unwrap_or(enter_idx as u64) as usize;
    let addr_hi = addr
        .checked_add(size)
        .context("candidate addr + size overflowed u64")?;
    let params = vec![
        ("idx_lo", enter_idx.to_string()),
        ("idx_hi", exit_idx.saturating_add(1).to_string()),
        ("addr_lo", format!("{addr:#x}")),
        ("addr_hi", format!("{addr_hi:#x}")),
        ("max", "5000".to_string()),
    ];
    let response =
        route_get_json_value_on(app, route_path("/api/mem-writes-in-range", &params)).await?;
    let map = byte_writer_map_output(addr, size_usize, &response);
    let bytes_hex = map
        .get("bytes_hex")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let all_zero = bytes_hex
        .as_deref()
        .is_some_and(|hex| !hex.is_empty() && hex.as_bytes().iter().all(|&b| b == b'0'));
    let target_hits = target_hex
        .zip(bytes_hex.as_deref())
        .map(|(target, needle)| {
            if all_zero {
                Vec::new()
            } else {
                find_hex_byte_offsets(target, needle)
            }
        })
        .unwrap_or_default();
    Ok(serde_json::json!({
        "candidate": candidate,
        "bytes_hex": bytes_hex,
        "all_zero": all_zero,
        "target_hits": target_hits,
        "map": map,
    }))
}

fn byte_writer_map_entries_from_range_writes(
    addr: u64,
    size: usize,
    writes: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let mut latest: Vec<Option<serde_json::Value>> = vec![None; size];
    for write in writes {
        let Some(start) = write
            .get("dst_addr")
            .and_then(|v| v.as_str())
            .and_then(parse_u64_str)
        else {
            continue;
        };
        let write_size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
        let Some(write_end) = start.checked_add(write_size) else {
            continue;
        };
        let Some(range_end) = addr.checked_add(size as u64) else {
            continue;
        };
        let overlap_start = start.max(addr);
        let overlap_end = write_end.min(range_end);
        if overlap_start >= overlap_end {
            continue;
        }
        for byte_addr in overlap_start..overlap_end {
            let offset = (byte_addr - addr) as usize;
            latest[offset] = Some(write.clone());
        }
    }

    latest
        .into_iter()
        .enumerate()
        .map(|(offset, write)| byte_writer_map_entry(addr + offset as u64, offset, write))
        .collect()
}

fn byte_writer_map_entry(
    byte_addr: u64,
    offset: usize,
    last_write: Option<serde_json::Value>,
) -> serde_json::Value {
    let byte = last_write
        .as_ref()
        .and_then(|write| source_byte_for_write_at(write, byte_addr));
    let source_byte_offset = last_write
        .as_ref()
        .and_then(|write| source_byte_offset_for_write_at(write, byte_addr));
    let next = last_write.as_ref().and_then(|write| {
        Some(serde_json::json!({
            "idx": write.get("idx")?,
            "reg": write.get("src_reg")?,
            "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offset": source_byte_offset,
            "reason": "buffer_byte_last_writer",
            "offset": offset,
            "addr": format!("{byte_addr:#x}"),
            "byte_hex": byte.map(|b| format!("{b:02x}")),
        }))
    });
    serde_json::json!({
        "offset": offset,
        "addr": format!("{byte_addr:#x}"),
        "status": if last_write.is_some() && byte.is_some() { "ready" } else { "not_found" },
        "byte_hex": byte.map(|b| format!("{b:02x}")),
        "ascii": byte.and_then(printable_ascii_char),
        "source_byte_offset": source_byte_offset,
        "writer": last_write,
        "next": next,
    })
}

fn source_byte_offset_for_write_at(write: &serde_json::Value, byte_addr: u64) -> Option<u64> {
    let start = write
        .get("dst_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    let size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
    if byte_addr < start || byte_addr >= start.saturating_add(size) {
        return None;
    }
    let offset = byte_addr - start;
    (offset < 8).then_some(offset)
}

fn source_byte_for_write_at(write: &serde_json::Value, byte_addr: u64) -> Option<u8> {
    let start = write
        .get("dst_addr")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    let size = write.get("size").and_then(|v| v.as_u64()).unwrap_or(1);
    if byte_addr < start || byte_addr >= start.saturating_add(size) {
        return None;
    }
    let offset = byte_addr - start;
    let shift = offset.checked_mul(8)?;
    if shift >= 64 {
        return None;
    }
    let value = write
        .get("src_value")
        .and_then(|v| v.as_str())
        .and_then(parse_u64_str)?;
    Some(((value >> shift) & 0xff) as u8)
}

fn byte_writer_runs(bytes: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut runs = Vec::new();
    let mut current: Option<ByteWriterRun> = None;
    for entry in bytes {
        let Some(byte_hex) = entry.get("byte_hex").and_then(|v| v.as_str()) else {
            if let Some(run) = current.take() {
                runs.push(run.into_json());
            }
            continue;
        };
        let Some(writer) = entry.get("writer").filter(|v| !v.is_null()) else {
            if let Some(run) = current.take() {
                runs.push(run.into_json());
            }
            continue;
        };
        let offset = entry
            .get("offset")
            .and_then(|v| v.as_u64())
            .unwrap_or_default() as usize;
        let source_byte_offset = entry
            .get("source_byte_offset")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let identity = byte_writer_identity(writer);
        if let Some(run) = current.as_mut() {
            if run.identity == identity && run.end_offset + 1 == offset {
                run.end_offset = offset;
                run.bytes_hex.push_str(byte_hex);
                run.source_byte_offsets.push(source_byte_offset);
                run.ascii.push_str(
                    &u8::from_str_radix(byte_hex, 16)
                        .ok()
                        .and_then(printable_ascii_char)
                        .unwrap_or_else(|| ".".to_string()),
                );
                continue;
            }
            runs.push(current.take().unwrap().into_json());
        }
        current = Some(ByteWriterRun {
            identity,
            start_offset: offset,
            end_offset: offset,
            bytes_hex: byte_hex.to_string(),
            ascii: u8::from_str_radix(byte_hex, 16)
                .ok()
                .and_then(printable_ascii_char)
                .unwrap_or_else(|| ".".to_string()),
            source_byte_offsets: vec![source_byte_offset],
            writer: writer.clone(),
        });
    }
    if let Some(run) = current {
        runs.push(run.into_json());
    }
    runs
}

#[derive(Debug)]
struct ByteWriterRun {
    identity: String,
    start_offset: usize,
    end_offset: usize,
    bytes_hex: String,
    ascii: String,
    source_byte_offsets: Vec<serde_json::Value>,
    writer: serde_json::Value,
}

impl ByteWriterRun {
    fn into_json(self) -> serde_json::Value {
        let source_byte_offset = if self.source_byte_offsets.len() == 1 {
            self.source_byte_offsets
                .first()
                .cloned()
                .unwrap_or(serde_json::Value::Null)
        } else {
            serde_json::Value::Null
        };
        serde_json::json!({
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "size": self.end_offset.saturating_sub(self.start_offset) + 1,
            "bytes_hex": self.bytes_hex,
            "ascii": self.ascii,
            "source_byte_offset": source_byte_offset,
            "source_byte_offsets": self.source_byte_offsets,
            "writer": self.writer,
        })
    }
}

fn byte_writer_identity(writer: &serde_json::Value) -> String {
    [
        writer
            .get("idx")
            .and_then(|v| v.as_u64())
            .map(|v| v.to_string()),
        writer
            .get("dst_addr")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        writer
            .get("size")
            .and_then(|v| v.as_u64())
            .map(|v| v.to_string()),
        writer
            .get("src_reg")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        writer
            .get("src_value")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("|")
}

fn byte_writer_entry(
    offset: u64,
    byte_addr: u64,
    last_write: Option<serde_json::Value>,
) -> serde_json::Value {
    let source_byte_offset = last_write
        .as_ref()
        .and_then(|write| source_byte_offset_for_write_at(write, byte_addr));
    let next = last_write.as_ref().and_then(|write| {
        Some(serde_json::json!({
            "idx": write.get("idx")?,
            "reg": write.get("src_reg")?,
            "src_value": write.get("src_value").cloned().unwrap_or(serde_json::Value::Null),
            "source_byte_offset": source_byte_offset,
            "reason": "memory_load_byte",
            "offset": offset,
            "addr": format!("{byte_addr:#x}"),
        }))
    });
    serde_json::json!({
        "offset": offset,
        "addr": format!("{byte_addr:#x}"),
        "status": if last_write.is_some() { "ready" } else { "not_found" },
        "source_byte_offset": source_byte_offset,
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
        let source_byte_offset = writer
            .get("source_byte_offset")
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
            if let Some(source_byte_offsets) = existing
                .get_mut("source_byte_offsets")
                .and_then(|v| v.as_array_mut())
            {
                source_byte_offsets.push(source_byte_offset);
            }
            continue;
        }
        let mut item = next.clone();
        if let Some(obj) = item.as_object_mut() {
            obj.insert("offsets".to_string(), serde_json::json!([offset]));
            obj.insert("addrs".to_string(), serde_json::json!([addr]));
            obj.insert(
                "source_byte_offsets".to_string(),
                serde_json::json!([source_byte_offset]),
            );
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
        "orr" | "eor" | "and" | "lsl" | "lsr" | "add" | "sub" | "ubfx" | "udiv"
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
        "orr" | "eor" | "and" | "add" | "sub" | "mul" if values.len() >= 2 => {
            if mnemonic == "mul" {
                return Some(format!(
                    "{result} = ({} * {}) mod 2^64",
                    values[0], values[1]
                ));
            }
            let op = match mnemonic.as_str() {
                "orr" => "|",
                "eor" => "^",
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
    let result = parse_u64_str(result)?;
    match mnemonic.as_str() {
        "add" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            mod255_fold_semantic(lhs, rhs, result)
                .or_else(|| mod255_fold_semantic(rhs, lhs, result))
                .or_else(|| add_known_constant_semantic(lhs, rhs, result))
                .or_else(|| add_known_constant_semantic(rhs, lhs, result))
                .or_else(|| add_small_delta_semantic(lhs, rhs, result))
                .or_else(|| add_small_delta_semantic(rhs, lhs, result))
                .or_else(|| add32_mix_semantic(lhs, rhs, result))
        }
        "and" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            and_identity_semantic(lhs, rhs, result)
                .or_else(|| and_identity_semantic(rhs, lhs, result))
                .or_else(|| bitmask_extract_semantic(lhs, rhs, result))
                .or_else(|| bitmask_extract_semantic(rhs, lhs, result))
        }
        "orr" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            or_identity_semantic(lhs, rhs, result)
                .or_else(|| or_identity_semantic(rhs, lhs, result))
                .or_else(|| bitwise_or_merge_semantic(lhs, rhs, result))
        }
        "eor" => {
            let (lhs, rhs) = parse_binary_values_or_immediate(asm, values)?;
            xor_identity_semantic(lhs, rhs, result).or_else(|| xor_mix_semantic(lhs, rhs, result))
        }
        "lsl" | "lsr" | "asr" => {
            let input = values.first().and_then(|value| parse_u64_str(value))?;
            let shift = shift_amount_from_asm_or_values(asm, values)?;
            shift_extract_semantic(asm, &mnemonic, input, shift, result)
        }
        "ubfx" => {
            let input = values.first().and_then(|value| parse_u64_str(value))?;
            ubfx_semantic(asm, input, result)
        }
        "mul" => {
            let (lhs, rhs) = parse_binary_values(values)?;
            mul_mod64_semantic(lhs, rhs, result)
        }
        _ => None,
    }
}

fn parse_binary_values(values: &[String]) -> Option<(u64, u64)> {
    Some((
        parse_u64_str(values.first()?)?,
        parse_u64_str(values.get(1)?)?,
    ))
}

fn parse_binary_values_or_immediate(asm: &str, values: &[String]) -> Option<(u64, u64)> {
    parse_binary_values(values).or_else(|| {
        Some((
            parse_u64_str(values.first()?)?,
            last_immediate_operand_u64(asm)?,
        ))
    })
}

fn last_immediate_operand_u64(asm: &str) -> Option<u64> {
    asm.split_once(char::is_whitespace)
        .map(|(_, operands)| split_operands(operands))
        .into_iter()
        .flatten()
        .skip(1)
        .filter_map(|op| immediate_operand_value(&op))
        .filter_map(|value| parse_u64_str(&value))
        .last()
}

fn xor_identity_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    let input = match (lhs, rhs) {
        (lhs, 0) if lhs != 0 && result == lhs => lhs,
        (0, rhs) if rhs != 0 && result == rhs => rhs,
        _ => return None,
    };
    Some(serde_json::json!({
        "kind": "xor_identity",
        "input": format!("{input:#x}"),
        "zero_operand": "0x0",
        "result": format!("{result:#x}"),
        "expression": "result == input ^ 0",
    }))
}

fn xor_mix_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    if lhs == 0 || rhs == 0 || (lhs ^ rhs) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "xor_mix",
        "lhs": format!("{lhs:#x}"),
        "rhs": format!("{rhs:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == lhs ^ rhs",
    }))
}

fn and_identity_semantic(input: u64, mask: u64, result: u64) -> Option<serde_json::Value> {
    if input == 0 || mask <= 0xfff || input & mask != result || result != input {
        return None;
    }
    Some(serde_json::json!({
        "kind": "and_identity",
        "input": format!("{input:#x}"),
        "mask": format!("{mask:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == input & mask",
    }))
}

fn or_identity_semantic(input: u64, zero: u64, result: u64) -> Option<serde_json::Value> {
    if input == 0 || zero != 0 || result != input {
        return None;
    }
    Some(serde_json::json!({
        "kind": "or_identity",
        "input": format!("{input:#x}"),
        "zero_operand": "0x0",
        "result": format!("{result:#x}"),
        "expression": "result == input | 0",
    }))
}

fn mod255_fold_semantic(input: u64, quotient: u64, result: u64) -> Option<serde_json::Value> {
    if input <= 0xff || quotient == 0 {
        return None;
    }
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

fn bitmask_extract_semantic(input: u64, mask: u64, result: u64) -> Option<serde_json::Value> {
    if mask == 0 || mask > 0xfff || input & mask != result {
        return None;
    }
    let low_bit = mask.trailing_zeros();
    let contiguous_width = contiguous_mask_width(mask);
    Some(serde_json::json!({
        "kind": "bitmask_extract",
        "input": format!("{input:#x}"),
        "mask": format!("{mask:#x}"),
        "result": format!("{result:#x}"),
        "low_bit": low_bit,
        "width": contiguous_width,
        "expression": "result == input & mask",
    }))
}

fn contiguous_mask_width(mask: u64) -> Option<u32> {
    let shifted = mask >> mask.trailing_zeros();
    ((shifted + 1).is_power_of_two()).then_some(shifted.count_ones())
}

fn bitwise_or_merge_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    if lhs | rhs != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "bitwise_or_merge",
        "lhs": format!("{lhs:#x}"),
        "rhs": format!("{rhs:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == lhs | rhs",
    }))
}

fn shift_amount_from_asm_or_values(asm: &str, values: &[String]) -> Option<u64> {
    values
        .get(1)
        .and_then(|value| parse_u64_str(value))
        .or_else(|| {
            let operands = asm
                .split_once(char::is_whitespace)
                .map(|(_, operands)| split_operands(operands))
                .unwrap_or_default();
            operands
                .get(2)
                .and_then(|op| immediate_operand_value(op))
                .and_then(|value| parse_u64_str(&value))
        })
}

fn shift_extract_semantic(
    asm: &str,
    mnemonic: &str,
    input: u64,
    shift: u64,
    result: u64,
) -> Option<serde_json::Value> {
    if shift >= 64 {
        return None;
    }
    let width = alu_result_width(asm);
    let computed = if width == 32 {
        let input = input as u32;
        if mnemonic == "lsl" {
            input.wrapping_shl(shift as u32) as u64
        } else {
            input.wrapping_shr(shift as u32) as u64
        }
    } else if mnemonic == "lsl" {
        input.wrapping_shl(shift as u32)
    } else {
        input.wrapping_shr(shift as u32)
    };
    if computed != result {
        return None;
    }
    let kind = if mnemonic == "lsl" {
        "shift_left"
    } else {
        "shift_right"
    };
    let op = if mnemonic == "lsl" { "<<" } else { ">>" };
    Some(serde_json::json!({
        "kind": kind,
        "input": format!("{input:#x}"),
        "shift": format!("{shift:#x}"),
        "result": format!("{result:#x}"),
        "width": width,
        "expression": format!("result == input {op} shift"),
    }))
}

fn alu_result_width(asm: &str) -> u32 {
    asm.split_once(char::is_whitespace)
        .map(|(_, operands)| split_operands(operands))
        .and_then(|operands| operands.first().cloned())
        .and_then(|operand| first_register_token(&operand))
        .filter(|reg| reg.starts_with('w'))
        .map(|_| 32)
        .unwrap_or(64)
}

fn ubfx_semantic(asm: &str, input: u64, result: u64) -> Option<serde_json::Value> {
    let operands = asm
        .split_once(char::is_whitespace)
        .map(|(_, operands)| split_operands(operands))
        .unwrap_or_default();
    let lsb = operands
        .get(2)
        .and_then(|op| immediate_operand_value(op))
        .and_then(|value| parse_u64_str(&value))?;
    let width = operands
        .get(3)
        .and_then(|op| immediate_operand_value(op))
        .and_then(|value| parse_u64_str(&value))?;
    if lsb >= 64 || width == 0 || width > 64 {
        return None;
    }
    let mask = if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    if ((input >> lsb) & mask) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "ubfx",
        "input": format!("{input:#x}"),
        "lsb": format!("{lsb:#x}"),
        "width": format!("{width:#x}"),
        "result": format!("{result:#x}"),
        "expression": "result == (input >> lsb) & ((1 << width) - 1)",
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

fn add_known_constant_semantic(
    input: u64,
    constant: u64,
    result: u64,
) -> Option<serde_json::Value> {
    let constant_name = known_algorithm_constant_name(constant)?;
    if input.wrapping_add(constant) != result {
        return None;
    }
    Some(serde_json::json!({
        "kind": "add_known_constant",
        "input": format!("{input:#x}"),
        "constant": format!("{constant:#x}"),
        "constant_name": constant_name,
        "result": format!("{result:#x}"),
        "expression": "result == input + known_constant",
    }))
}

fn add32_mix_semantic(lhs: u64, rhs: u64, result: u64) -> Option<serde_json::Value> {
    if !is_plausible_u32_mix_value(lhs)
        || !is_plausible_u32_mix_value(rhs)
        || !is_plausible_u32_mix_value(result)
    {
        return None;
    }
    if lhs <= 0xff && rhs <= 0xff && result <= 0xff {
        return None;
    }
    if (lhs as u32).wrapping_add(rhs as u32) != result as u32 {
        return None;
    }
    let lhs_low32 = lhs as u32;
    let rhs_low32 = rhs as u32;
    let result_low32 = result as u32;
    Some(serde_json::json!({
        "kind": "add32_mix",
        "lhs": format!("{lhs:#x}"),
        "rhs": format!("{rhs:#x}"),
        "result": format!("{result:#x}"),
        "lhs_low32": format!("{lhs_low32:#x}"),
        "rhs_low32": format!("{rhs_low32:#x}"),
        "result_low32": format!("{result_low32:#x}"),
        "modulus": "2^32",
        "expression": "low32(result) == (low32(lhs) + low32(rhs)) mod 2^32",
    }))
}

fn is_plausible_u32_mix_value(value: u64) -> bool {
    value <= 0xf_ffff_ffff
}

fn known_algorithm_constant_name(value: u64) -> Option<&'static str> {
    match value {
        0x6745_2301 => Some("md5_iv_a"),
        0xefcd_ab89 => Some("md5_iv_b"),
        0x98ba_dcfe => Some("md5_iv_c"),
        0x1032_5476 => Some("md5_iv_d"),
        _ => None,
    }
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

fn classify_vm_asm(asm: &str, profile: &VmProfile) -> &'static str {
    let asm = asm.trim().to_ascii_lowercase();
    let bracket_regs = bracket_registers(&asm).unwrap_or_default();
    let bracket_base = bracket_regs.first().map(String::as_str);
    if asm.starts_with("br ") {
        return "dispatch-branch";
    }
    if asm.starts_with("blr ") {
        return "call-indirect";
    }
    if bracket_base == Some(profile.dispatch_reg.as_str()) {
        return "dispatch-table-load";
    }
    if bracket_base == Some(profile.ip_reg.as_str()) {
        return "bytecode-read";
    }
    if bracket_base == Some(profile.state_reg.as_str()) {
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

fn vm_slot_from_asm(
    asm: &str,
    record: &serde_json::Value,
    profile: &VmProfile,
) -> Option<serde_json::Value> {
    let lower = asm.to_ascii_lowercase();
    let regs = bracket_registers(&lower)?;
    if regs.first().map(String::as_str) != Some(profile.state_reg.as_str()) {
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

fn cmd_resolve_elf_symbol(elf_file: PathBuf, offset: String) -> anyhow::Result<()> {
    let offset = parse_u64_str(&offset).with_context(|| format!("invalid offset: {offset}"))?;
    let (tool, symbols) = elf_symbols_from_nm(&elf_file)
        .with_context(|| format!("failed to read ELF symbols: {}", elf_file.display()))?;
    let out = resolve_elf_symbol_json(&symbols, offset).unwrap_or_else(|| {
        serde_json::json!({
            "status": "miss",
            "elf_file": elf_file.display().to_string(),
            "offset": format!("{offset:#x}"),
            "symbol_count": symbols.len(),
            "source_tool": tool,
        })
    });
    let mut obj = out.as_object().cloned().unwrap_or_default();
    obj.insert(
        "elf_file".to_string(),
        serde_json::Value::String(elf_file.display().to_string()),
    );
    obj.insert("source_tool".to_string(), serde_json::Value::String(tool));
    print_pretty(&serde_json::Value::Object(obj))
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ElfSymbol {
    addr: u64,
    size: Option<u64>,
    kind: String,
    name: String,
}

fn elf_symbols_from_nm(elf_file: &Path) -> anyhow::Result<(String, Vec<ElfSymbol>)> {
    let attempts: &[(&str, &[&str])] = &[
        ("llvm-nm", &["-D", "--defined-only", "--print-size"]),
        ("llvm-nm", &["--defined-only", "--print-size"]),
        ("nm", &["-D", "--defined-only", "--print-size"]),
        ("nm", &["--defined-only", "--print-size"]),
    ];
    let mut errors = Vec::new();
    for (tool, args) in attempts {
        match run_nm_command(tool, args, elf_file) {
            Ok(text) => {
                let mut symbols = parse_nm_symbols(&text);
                if !symbols.is_empty() {
                    symbols.sort_by_key(|sym| sym.addr);
                    return Ok((format!("{} {}", tool, args.join(" ")), symbols));
                }
                errors.push(format!(
                    "{} {} returned no defined symbols",
                    tool,
                    args.join(" ")
                ));
            }
            Err(err) => errors.push(format!("{} {}: {err}", tool, args.join(" "))),
        }
    }
    bail!("{}", errors.join("; "))
}

fn run_nm_command(tool: &str, args: &[&str], elf_file: &Path) -> anyhow::Result<String> {
    let output = Command::new(tool)
        .args(args)
        .arg(elf_file)
        .output()
        .with_context(|| format!("failed to execute {tool}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        bail!(
            "exit status {}{}",
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_nm_symbols(text: &str) -> Vec<ElfSymbol> {
    text.lines()
        .filter_map(parse_nm_symbol_line)
        .collect::<Vec<_>>()
}

fn parse_nm_symbol_line(line: &str) -> Option<ElfSymbol> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 3 {
        return None;
    }
    let addr = u64::from_str_radix(parts[0].trim_start_matches("0x"), 16).ok()?;
    let (size, kind_idx, name_idx) = if parts.len() >= 4 && is_nm_kind(parts[2]) {
        (
            u64::from_str_radix(parts[1].trim_start_matches("0x"), 16).ok(),
            2usize,
            3usize,
        )
    } else if is_nm_kind(parts[1]) {
        (None, 1usize, 2usize)
    } else {
        return None;
    };
    let kind = parts[kind_idx].to_string();
    if kind.eq_ignore_ascii_case("U") {
        return None;
    }
    let name = parts[name_idx..].join(" ");
    (!name.is_empty()).then_some(ElfSymbol {
        addr,
        size,
        kind,
        name,
    })
}

fn is_nm_kind(s: &str) -> bool {
    s.len() == 1 && s.as_bytes()[0].is_ascii_alphabetic()
}

fn resolve_elf_symbol_json(symbols: &[ElfSymbol], offset: u64) -> Option<serde_json::Value> {
    let sym = symbols.iter().rev().find(|sym| sym.addr <= offset)?;
    let delta = offset.saturating_sub(sym.addr);
    let next = symbols.iter().find(|next| next.addr > sym.addr);
    let in_size = sym
        .size
        .map(|size| delta < size)
        .or_else(|| next.map(|next| offset < next.addr));
    Some(serde_json::json!({
        "status": if delta == 0 { "exact" } else { "nearest" },
        "offset": format!("{offset:#x}"),
        "symbol_addr": format!("{:#x}", sym.addr),
        "symbol_size": sym.size.map(|size| format!("{size:#x}")),
        "delta": format!("{delta:#x}"),
        "name": sym.name,
        "base_name": elf_symbol_base_name(&sym.name),
        "kind": sym.kind,
        "in_symbol_range": in_size,
        "next_symbol_addr": next.map(|sym| format!("{:#x}", sym.addr)),
        "next_symbol": next.map(|sym| sym.name.clone()),
        "symbol_count": symbols.len(),
    }))
}

fn elf_symbol_base_name(name: &str) -> String {
    name.split("@@")
        .next()
        .unwrap_or(name)
        .split('@')
        .next()
        .unwrap_or(name)
        .to_string()
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

fn find_hex_byte_offsets(haystack_hex: &str, needle_hex: &str) -> Vec<usize> {
    let mut haystack = haystack_hex.trim().to_ascii_lowercase();
    let mut needle = needle_hex.trim().to_ascii_lowercase();
    haystack.retain(|ch| !ch.is_ascii_whitespace() && ch != '_' && ch != ':');
    needle.retain(|ch| !ch.is_ascii_whitespace() && ch != '_' && ch != ':');
    if needle.is_empty() || needle.len() % 2 != 0 || haystack.len() < needle.len() {
        return Vec::new();
    }
    (0..=haystack.len() - needle.len())
        .step_by(2)
        .filter(|&idx| haystack[idx..idx + needle.len()] == needle)
        .map(|idx| idx / 2)
        .collect()
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
        alu_expression_from_asm, base64_decoded_bytes, byte_lane_from_writer_map_entry,
        byte_lineage_summary, byte_writer_map_output, byte_writer_map_summary,
        byte_writers_from_range_writes, choose_frontier_next, choose_frontier_next_for_lane,
        choose_laned_upstream_next, classify_vm_asm, compact_gap_call_candidates,
        dedupe_byte_nexts, def_entries_from_asm, def_source_regs_from_asm,
        enrich_gap_call_candidate_trace_writes, find_hex_byte_offsets,
        gap_call_candidate_from_record, lineage_next_from_backstep, mem_addr_from_asm,
        mem_dump_summary, memory_access_width, observed_byte_writer_mismatches, odd_u64_inverse,
        output_map_summary, output_semantic_byte_equation,
        output_semantic_byte_equation_input_summary, output_semantic_byte_equation_summary,
        output_semantic_xor_word_run_templates, output_semantic_xor_word_state_source_summary,
        output_semantic_xor_word_state_sources, output_semantic_xor_word_templates,
        parse_nm_symbol_line, recognize_alu_semantic, recognized_backchain_pattern_summary,
        recognized_backchain_patterns, resolve_addr_in_maps_text, resolve_elf_symbol_json,
        source_byte_for_write_at, source_byte_offset_for_write_at, store_source_regs_from_asm,
        store_touch_for_addr, vm_backchain_stop_summary, vm_op_effect_summaries,
        vm_ops_effects_only_summary, vm_ops_state_updates, vm_slot_from_asm, ElfSymbol, VmProfile,
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
        let profile = VmProfile::default_profile();
        let record = serde_json::json!({
            "regs": {
                "x25": "0x1000",
                "x19": "0x19",
                "x1": "0xe0",
            }
        });
        assert_eq!(
            classify_vm_asm("ldr x4, [x25, x19, lsl #3]", &profile),
            "vm-reg-load"
        );
        assert_eq!(
            classify_vm_asm("ldp x9, x10, [x25, #0xc0]", &profile),
            "mem-load"
        );
        assert_eq!(
            mem_addr_from_asm("ldr x4, [x25, x19, lsl #3]", &record),
            Some(0x10c8)
        );
        let slot = vm_slot_from_asm("ldr x4, [x25, x19, lsl #3]", &record, &profile).unwrap();
        assert_eq!(slot["slot"], serde_json::json!(25));
        assert_eq!(
            mem_addr_from_asm("str x3, [x25, x1]", &record),
            Some(0x10e0)
        );
        let slot = vm_slot_from_asm("str x3, [x25, x1]", &record, &profile).unwrap();
        assert_eq!(slot["slot"], serde_json::json!(28));
    }

    #[test]
    fn vm_profile_allows_non_default_role_registers() {
        let profile = VmProfile::new(
            "x9".to_string(),
            "x20".to_string(),
            "x22".to_string(),
            "x26".to_string(),
        );
        let record = serde_json::json!({
            "regs": {
                "x20": "0x4000",
                "x3": "0x5",
            }
        });
        assert_eq!(
            classify_vm_asm("ldrb w1, [x9, #0x4]", &profile),
            "bytecode-read"
        );
        assert_eq!(
            classify_vm_asm("ldr x1, [x22, x8, lsl #3]", &profile),
            "dispatch-table-load"
        );
        assert_eq!(
            classify_vm_asm("ldr x4, [x20, x3, lsl #3]", &profile),
            "vm-reg-load"
        );
        let slot = vm_slot_from_asm("ldr x4, [x20, x3, lsl #3]", &record, &profile).unwrap();
        assert_eq!(slot["slot"], serde_json::json!(5));
        assert!(profile.is_infrastructure_reg("x26"));
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
    fn detects_external_gap_call_candidates() {
        let meta = serde_json::json!({
            "module": {"name": "libtarget.so", "base": "0x1000", "end": "0x2000"},
            "modules": [
                {"name": "libtarget.so", "base": "0x1000", "end": "0x2000"},
                {"name": "libc.so", "base": "0x7000", "end": "0x9000"}
            ]
        });
        let record = serde_json::json!({
            "idx": 42,
            "pc": "0x1500",
            "func": "sub_500",
            "asm": "blr x22",
            "regs": {
                "x0": "0x5000",
                "x1": "0x6000",
                "x2": "0x8",
                "x3": "0x0",
                "x4": "0x0",
                "x5": "0x0",
                "x6": "0x0",
                "x7": "0x0",
                "x22": "0x8120"
            }
        });
        let primary = super::primary_module_bounds(&meta);
        let candidate =
            gap_call_candidate_from_record(&record, &meta, primary.as_ref(), 0x6058).unwrap();
        assert_eq!(candidate["external_to_primary"], serde_json::json!(true));
        assert_eq!(
            candidate.pointer("/target_module/name"),
            Some(&serde_json::json!("libc.so"))
        );
        assert_eq!(
            candidate.pointer("/arg_offsets/0/reg"),
            Some(&serde_json::json!("x1"))
        );
        assert_eq!(
            candidate.pointer("/arg_offsets/0/offset"),
            Some(&serde_json::json!("0x58"))
        );

        let compact = compact_gap_call_candidates(Some(&serde_json::json!({
            "status": "ready",
            "scan_idx_lo": 40,
            "scan_idx_hi": 50,
            "candidate_count_total": 1,
            "truncated_by_record_cap": false,
            "candidates": [candidate]
        })));
        assert_eq!(
            compact.pointer("/candidates/0/target_module/offset"),
            Some(&serde_json::json!("0x1120"))
        );
    }

    #[test]
    fn enriches_internal_gap_call_without_target_write_as_weak() {
        let mut candidate = serde_json::json!({
            "idx": 10,
            "pc": "0x1500",
            "asm": "bl #0x1600",
            "external_to_primary": false,
            "score": 60,
        });
        let records = vec![
            serde_json::json!({"idx": 10, "pc": "0x1500", "asm": "bl #0x1600", "regs": {}}),
            serde_json::json!({"idx": 11, "pc": "0x1600", "asm": "stp x29, x30, [sp, #-0x20]!", "regs": {"sp": "0x7000"}}),
            serde_json::json!({"idx": 12, "pc": "0x1604", "asm": "ret", "regs": {}}),
            serde_json::json!({"idx": 13, "pc": "0x1504", "asm": "mov x0, x0", "regs": {}}),
        ];
        enrich_gap_call_candidate_trace_writes(&mut candidate, &records, 0x6058);
        assert_eq!(
            candidate["callee_trace"]["status"],
            serde_json::json!("traced_callee_no_target_write")
        );
        assert_eq!(
            candidate["score_adjustment_trace_write"],
            serde_json::json!(-50)
        );
        assert_eq!(candidate["score"], serde_json::json!(10));
        let compact = compact_gap_call_candidates(Some(&serde_json::json!({
            "status": "ready",
            "candidates": [candidate],
        })));
        assert_eq!(
            compact["candidates"][0]["callee_trace"]["status"],
            serde_json::json!("traced_callee_no_target_write")
        );
    }

    #[test]
    fn enriches_internal_gap_call_with_target_write() {
        let mut candidate = serde_json::json!({
            "idx": 10,
            "pc": "0x1500",
            "asm": "bl #0x1600",
            "external_to_primary": false,
            "score": 20,
        });
        let records = vec![
            serde_json::json!({"idx": 10, "pc": "0x1500", "asm": "bl #0x1600", "regs": {"x3": "0x6050"}}),
            serde_json::json!({"idx": 11, "pc": "0x1600", "asm": "strb w1, [x3, #8]", "regs": {"x1": "0x51", "x3": "0x6050"}}),
            serde_json::json!({"idx": 12, "pc": "0x1604", "asm": "ret", "regs": {}}),
            serde_json::json!({"idx": 13, "pc": "0x1504", "asm": "mov x0, x0", "regs": {}}),
        ];
        enrich_gap_call_candidate_trace_writes(&mut candidate, &records, 0x6058);
        assert_eq!(
            candidate["callee_trace"]["status"],
            serde_json::json!("traced_callee_target_write")
        );
        assert_eq!(
            candidate["score_adjustment_trace_write"],
            serde_json::json!(80)
        );
        assert_eq!(candidate["score"], serde_json::json!(100));
        assert_eq!(
            candidate["callee_trace"]["target_writes"][0]["idx"],
            serde_json::json!(11)
        );

        let touch = store_touch_for_addr(&records[1], 0x6058).unwrap();
        assert_eq!(touch["width"], serde_json::json!(1));
        assert_eq!(touch["offset"], serde_json::json!(0));
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
        assert!(recognize_alu_semantic(
            "add x5, x3, x4",
            "0x3",
            &["0x3".to_string(), "0x0".to_string()],
        )
        .is_none());
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
        let semantic = recognize_alu_semantic(
            "and x19, x17, x13",
            "0x28",
            &["0x28".to_string(), "0x3c".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("bitmask_extract"));
        assert_eq!(semantic["mask"], serde_json::json!("0x3c"));
        assert_eq!(semantic["low_bit"], serde_json::json!(2));
        assert_eq!(semantic["width"], serde_json::json!(4));
        let semantic = recognize_alu_semantic(
            "orr x4, x14, x17",
            "0x29",
            &["0x28".to_string(), "0x1".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("bitwise_or_merge"));
        let semantic = recognize_alu_semantic(
            "lsr w4, w20, w1",
            "0x1",
            &["0x62".to_string(), "0x6".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("shift_right"));
        assert_eq!(semantic["input"], serde_json::json!("0x62"));
        let semantic =
            recognize_alu_semantic("lsl w16, w2, #2", "0x28", &["0xa".to_string()]).unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("shift_left"));
        assert_eq!(semantic["shift"], serde_json::json!("0x2"));
        let semantic = recognize_alu_semantic(
            "lsl w16, w1, w11",
            "0x78000000",
            &["0x6f783e78".to_string(), "0x18".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("shift_left"));
        assert_eq!(semantic["width"], serde_json::json!(32));
        let semantic = recognize_alu_semantic(
            "eor x16, x20, x5",
            "0x62",
            &["0x0".to_string(), "0x62".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("xor_identity"));
        assert_eq!(semantic["input"], serde_json::json!("0x62"));
        let semantic = recognize_alu_semantic(
            "eor x16, x20, x5",
            "0x5",
            &["0x67".to_string(), "0x62".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("xor_mix"));
        assert_eq!(semantic["lhs"], serde_json::json!("0x67"));
        let semantic = recognize_alu_semantic(
            "orr x5, x1, x2",
            "0x561d4e18",
            &["0x0".to_string(), "0x561d4e18".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("or_identity"));
        assert_eq!(semantic["input"], serde_json::json!("0x561d4e18"));
        let semantic = recognize_alu_semantic(
            "and x8, x11, x15",
            "0x561d4e18",
            &["0x561d4e18".to_string(), "0x561d4e1b".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("and_identity"));
        let semantic =
            recognize_alu_semantic("and x2, x16, #0xffffffff", "0x1a", &["0x1a".to_string()])
                .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("and_identity"));
        assert_eq!(semantic["mask"], serde_json::json!("0xffffffff"));
        let semantic = recognize_alu_semantic(
            "add x13, x8, x12",
            "0x1b2345fc4",
            &["0x14aef3cc3".to_string(), "0x67452301".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("add_known_constant"));
        assert_eq!(semantic["constant_name"], serde_json::json!("md5_iv_a"));
        let semantic = recognize_alu_semantic(
            "add x13, x8, x12",
            "0x783e786f",
            &["0x561d4e18".to_string(), "0x22212a57".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("add32_mix"));
        let semantic = recognize_alu_semantic(
            "add x13, x8, x12",
            "0x267b44ad8",
            &["0x1b57feb14".to_string(), "0xb2345fc4".to_string()],
        )
        .unwrap();
        assert_eq!(semantic["kind"], serde_json::json!("add32_mix"));
        assert_eq!(semantic["result_low32"], serde_json::json!("0x67b44ad8"));
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

        let mul_small = serde_json::json!({
            "local_def": {
                "asm": "mul x12, x2, x15",
                "class": "alu",
                "def": {
                    "reg": "x12",
                    "src": [
                        {"reg": "x2", "value": "0xc87"},
                        {"reg": "x15", "value": "0x3"}
                    ],
                    "value_after": "0x2595"
                }
            },
            "frontier": [
                {"idx": 60, "reg": "x2", "value": "0xc87"},
                {"idx": 60, "reg": "x15", "value": "0x3"}
            ]
        });
        let next = choose_frontier_next(&mul_small).unwrap();
        assert_eq!(next["reg"], serde_json::json!("x2"));
        assert_eq!(next["src_value"], serde_json::json!("0xc87"));

        let add_identity = serde_json::json!({
            "local_def": {
                "asm": "add x13, x8, x12",
                "class": "alu",
                "def": {
                    "reg": "x13",
                    "src": [
                        {"reg": "x8", "value": "0xc87"},
                        {"reg": "x12", "value": "0x0"}
                    ],
                    "value_after": "0xc87"
                }
            },
            "frontier": [
                {"idx": 70, "reg": "x8", "value": "0xc87"},
                {"idx": 70, "reg": "x12", "value": "0x0"}
            ]
        });
        let next = choose_frontier_next(&add_identity).unwrap();
        assert_eq!(next["reg"], serde_json::json!("x8"));
        assert_eq!(next["src_value"], serde_json::json!("0xc87"));

        let eor_identity = serde_json::json!({
            "local_def": {
                "asm": "eor x16, x20, x5",
                "class": "alu",
                "def": {
                    "reg": "x16",
                    "src": [
                        {"reg": "x20", "value": "0x0"},
                        {"reg": "x5", "value": "0x62"}
                    ],
                    "value_after": "0x62"
                }
            },
            "frontier": [
                {"idx": 80, "reg": "x20", "value": "0x0"},
                {"idx": 80, "reg": "x5", "value": "0x62"}
            ]
        });
        let next = choose_frontier_next(&eor_identity).unwrap();
        assert_eq!(next["reg"], serde_json::json!("x5"));
        assert_eq!(next["src_value"], serde_json::json!("0x62"));
    }

    #[test]
    fn frontier_auto_uses_byte_lane_for_or_merge_and_shifts() {
        let profile = VmProfile::default_profile();
        let or_merge = serde_json::json!({
            "local_def": {
                "asm": "orr x4, x14, x17",
                "class": "alu",
                "def": {
                    "reg": "x4",
                    "src": [
                        {"reg": "x14", "value": "0x78000000"},
                        {"reg": "x17", "value": "0xd84ab4"}
                    ],
                    "value_after": "0x78d84ab4"
                }
            },
            "frontier": [
                {"idx": 90, "reg": "x14", "value": "0x78000000"},
                {"idx": 90, "reg": "x17", "value": "0xd84ab4"}
            ]
        });
        let lane1 = choose_frontier_next_for_lane(&or_merge, Some(1), &profile).unwrap();
        assert_eq!(lane1["reg"], serde_json::json!("x17"));
        assert_eq!(lane1["src_value"], serde_json::json!("0xd84ab4"));
        assert_eq!(lane1["source_byte_offset"], serde_json::json!(1));

        let lane3 = choose_frontier_next_for_lane(&or_merge, Some(3), &profile).unwrap();
        assert_eq!(lane3["reg"], serde_json::json!("x14"));
        assert_eq!(lane3["src_value"], serde_json::json!("0x78000000"));
        assert_eq!(lane3["source_byte_offset"], serde_json::json!(3));

        let shift_left = serde_json::json!({
            "local_def": {
                "asm": "lsl w16, w1, w11",
                "class": "alu",
                "def": {
                    "reg": "w16",
                    "src": [
                        {"reg": "w1", "value": "0x6f783e78"},
                        {"reg": "w11", "value": "0x18"}
                    ],
                    "value_after": "0x78000000"
                }
            },
            "frontier": [
                {"idx": 91, "reg": "w1", "value": "0x6f783e78"},
                {"idx": 91, "reg": "w11", "value": "0x18"}
            ]
        });
        let shifted = choose_frontier_next_for_lane(&shift_left, Some(3), &profile).unwrap();
        assert_eq!(shifted["reg"], serde_json::json!("w1"));
        assert_eq!(shifted["source_byte_offset"], serde_json::json!(0));
    }

    #[test]
    fn extracts_compact_byte_equations_from_semantic_chains() {
        let item = serde_json::json!({
            "start_offset": 4,
            "bytes_hex": "d5",
            "chain": {
                "recognized_semantics": [
                    {
                        "step": 4,
                        "idx": 14704232,
                        "asm": "eor x16, x20, x5",
                        "semantic": {
                            "kind": "xor_mix",
                            "lhs": "0xb4",
                            "rhs": "0x61",
                            "result": "0xd5"
                        }
                    }
                ]
            }
        });
        let equation = output_semantic_byte_equation(&item).unwrap();
        assert_eq!(equation["offset"], serde_json::json!(4));
        assert_eq!(equation["kind"], serde_json::json!("xor_mix"));
        assert_eq!(equation["idx"], serde_json::json!(14704232));
        assert_eq!(
            equation["expression"],
            serde_json::json!("result == (lhs ^ rhs) & 0xff")
        );
        assert_eq!(equation["matches_first_byte"], serde_json::json!(true));
    }

    #[test]
    fn extracts_byte_lane_equation_from_word_load_chain() {
        let item = serde_json::json!({
            "start_offset": 0,
            "bytes_hex": "0a",
            "chain": {
                "recognized_semantics": [],
                "chain": [
                    {
                        "step": 5,
                        "idx": 13781975,
                        "local_def": {
                            "asm": "ldrb w1, [x0, x4]"
                        },
                        "next": {
                            "reason": "memory_load_byte",
                            "source_byte_offset": 3,
                            "src_value": "0xa000142"
                        }
                    }
                ]
            }
        });
        let equation = output_semantic_byte_equation(&item).unwrap();
        assert_eq!(equation["offset"], serde_json::json!(0));
        assert_eq!(equation["kind"], serde_json::json!("byte_lane_extract"));
        assert_eq!(equation["source_value"], serde_json::json!("0xa000142"));
        assert_eq!(equation["source_byte_offset"], serde_json::json!(3));
        assert_eq!(equation["result"], serde_json::json!("0xa"));
        assert_eq!(equation["matches_first_byte"], serde_json::json!(true));
    }

    #[test]
    fn extracts_mod255_byte_equation_with_trace_idx() {
        let item = serde_json::json!({
            "start_offset": 1,
            "bytes_hex": "62",
            "chain": {
                "recognized_semantics": [
                    {
                        "step": 3,
                        "idx": 14712345,
                        "asm": "add x15, x13, x14",
                        "semantic": {
                            "kind": "mod255_low_byte",
                            "input": "0x74ffafca73",
                            "quotient": "0x757524ef",
                            "output_byte": "0x62"
                        }
                    }
                ]
            }
        });
        let equation = output_semantic_byte_equation(&item).unwrap();
        assert_eq!(equation["offset"], serde_json::json!(1));
        assert_eq!(equation["kind"], serde_json::json!("mod255_low_byte"));
        assert_eq!(equation["idx"], serde_json::json!(14712345));
        assert_eq!(equation["result"], serde_json::json!("0x62"));
        assert_eq!(
            equation["expression"],
            serde_json::json!("result == (input + floor(input / 0xff)) & 0xff")
        );
        assert_eq!(equation["matches_first_byte"], serde_json::json!(true));
    }

    #[test]
    fn falls_back_to_writer_byte_lane_when_first_semantic_mismatches() {
        let item = serde_json::json!({
            "start_offset": 44,
            "bytes_hex": "00",
            "source_byte_offset": 1,
            "seed": {
                "idx": 8320257,
                "asm": "str w16, [x2, x5]",
                "src_value": "0xb71300fd",
                "byte_lane": 1
            },
            "chain": {
                "recognized_semantics": [
                    {
                        "step": 9,
                        "idx": 8301779,
                        "asm": "eor x16, x20, x5",
                        "semantic": {
                            "kind": "xor_mix",
                            "lhs": "0x79",
                            "rhs": "0x84",
                            "result": "0xfd"
                        }
                    }
                ]
            }
        });

        let equation = output_semantic_byte_equation(&item).unwrap();
        assert_eq!(
            equation["kind"],
            serde_json::json!("writer_byte_lane_extract")
        );
        assert_eq!(equation["source_value"], serde_json::json!("0xb71300fd"));
        assert_eq!(equation["source_byte_offset"], serde_json::json!(1));
        assert_eq!(equation["result"], serde_json::json!("0x0"));
        assert_eq!(
            equation["rejected_semantic"]["kind"],
            serde_json::json!("xor_mix")
        );
        assert_eq!(
            equation["rejected_semantic"]["matches_first_byte"],
            serde_json::json!(false)
        );
    }

    #[test]
    fn summarizes_xor_word_templates_from_byte_equations() {
        let equations = serde_json::json!([
            {
                "offset": 1,
                "kind": "mod255_low_byte",
                "output_byte": "0x62",
                "result": "0x62"
            },
            {
                "offset": 2,
                "kind": "mod255_low_byte",
                "output_byte": "0x61",
                "result": "0x61"
            },
            {
                "offset": 3,
                "kind": "xor_mix",
                "lhs": "0x67",
                "rhs": "0x62",
                "result": "0x05"
            },
            {
                "offset": 4,
                "kind": "xor_mix",
                "lhs": "0xb4",
                "rhs": "0x61",
                "result": "0xd5"
            },
            {
                "offset": 5,
                "kind": "xor_mix",
                "lhs": "0x4a",
                "rhs": "0x62",
                "result": "0x28"
            },
            {
                "offset": 6,
                "kind": "xor_mix",
                "lhs": "0xd8",
                "rhs": "0x61",
                "result": "0xb9"
            }
        ]);
        let templates = output_semantic_xor_word_templates(&equations);
        let first = templates.as_array().unwrap().first().unwrap();
        assert_eq!(first["semantic_range"], serde_json::json!([3, 7]));
        assert_eq!(first["lhs_word_le"], serde_json::json!("0xd84ab467"));
        assert_eq!(
            first["rhs_pattern"]["kind"],
            serde_json::json!("alternating_two_byte_mask")
        );
        assert_eq!(
            first["rhs_pattern"]["source_offsets"],
            serde_json::json!([1, 2])
        );
        assert_eq!(first["result_bytes_hex"], serde_json::json!("05d528b9"));

        let summary = output_semantic_byte_equation_summary(&equations);
        let chunk = summary["xor_lhs_word_chunks"][0].clone();
        assert_eq!(chunk["kind"], serde_json::json!("word32"));
        assert_eq!(chunk["run_range"], serde_json::json!([3, 7]));
        assert_eq!(chunk["run_chunk"], serde_json::json!(0));
        assert_eq!(chunk["semantic_range"], serde_json::json!([3, 7]));
        assert_eq!(chunk["lhs_word_le"], serde_json::json!("0xd84ab467"));

        let run_templates = output_semantic_xor_word_run_templates(&equations);
        assert_eq!(run_templates.as_array().unwrap().len(), 1);
        assert_eq!(run_templates[0]["run_range"], serde_json::json!([3, 7]));
        assert_eq!(
            run_templates[0]["lhs_word_le"],
            serde_json::json!("0xd84ab467")
        );
    }

    #[test]
    fn excludes_mismatched_byte_equations_from_compact_summaries() {
        let equations = serde_json::json!([
            {
                "offset": 3,
                "kind": "xor_mix",
                "lhs": "0x67",
                "rhs": "0x62",
                "result": "0x05",
                "matches_first_byte": true
            },
            {
                "offset": 4,
                "kind": "xor_mix",
                "lhs": "0xb4",
                "rhs": "0x61",
                "result": "0xd5",
                "bytes_hex": "00",
                "matches_first_byte": false
            },
            {
                "offset": 5,
                "kind": "xor_mix",
                "lhs": "0x4a",
                "rhs": "0x62",
                "result": "0x28",
                "matches_first_byte": true
            },
            {
                "offset": 6,
                "kind": "xor_mix",
                "lhs": "0xd8",
                "rhs": "0x61",
                "result": "0xb9",
                "matches_first_byte": true
            }
        ]);

        let summary = output_semantic_byte_equation_summary(&equations);
        assert_eq!(summary["count"], serde_json::json!(3));
        assert_eq!(
            summary["missing_offsets_in_covered_range"],
            serde_json::json!([4])
        );
        assert_eq!(summary["xor_lhs_word_chunks"].as_array().unwrap().len(), 2);
        assert!(summary["xor_lhs_word_chunks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|chunk| chunk["kind"] != serde_json::json!("word32")));

        let templates = output_semantic_xor_word_run_templates(&equations);
        assert!(templates.as_array().unwrap().is_empty());
    }

    #[test]
    fn summarizes_byte_equation_parity_masks() {
        let equations = serde_json::json!([
            {
                "offset": 1,
                "kind": "mod255_low_byte",
                "output_byte": "0x62",
                "result": "0x62"
            },
            {
                "offset": 3,
                "kind": "xor_mix",
                "lhs": "0x67",
                "rhs": "0x62",
                "result": "0x05"
            },
            {
                "offset": 4,
                "kind": "xor_mix",
                "lhs": "0xb4",
                "rhs": "0x61",
                "result": "0xd5"
            }
        ]);
        let summary = output_semantic_byte_equation_summary(&equations);
        assert_eq!(summary["count"], serde_json::json!(3));
        assert_eq!(
            summary["missing_offsets_in_covered_range"],
            serde_json::json!([2])
        );
        assert_eq!(
            summary["xor_rhs_pattern"]["kind"],
            serde_json::json!("offset_parity_mask")
        );
        assert_eq!(
            summary["xor_rhs_pattern"]["odd_byte"],
            serde_json::json!("0x62")
        );
        assert_eq!(
            summary["xor_rhs_pattern"]["even_byte"],
            serde_json::json!("0x61")
        );
        assert_eq!(
            summary["xor_lhs_runs"][0]["range"],
            serde_json::json!([3, 5])
        );
        assert_eq!(
            summary["xor_lhs_runs"][0]["lhs_hex"],
            serde_json::json!("67b4")
        );
        assert_eq!(
            summary["xor_lhs_runs"][0]["result_hex"],
            serde_json::json!("05d5")
        );
        assert_eq!(
            summary["xor_lhs_run_chunks"],
            summary["xor_lhs_word_chunks"]
        );
    }

    #[test]
    fn summarizes_semantic_byte_equation_inputs() {
        let equations = serde_json::json!([
            {
                "offset": 0,
                "kind": "byte_lane_extract",
                "bytes_hex": "0a",
                "source_value": "0xa000142",
                "source_byte_offset": 3,
                "result": "0xa"
            },
            {
                "offset": 1,
                "kind": "mod255_low_byte",
                "input": "0x74ffafca73",
                "output_byte": "0x62",
                "quotient": "0x757524ef"
            },
            {
                "offset": 13,
                "kind": "mod255_low_byte",
                "input": "0x74ffafca73",
                "output_byte": "0x62",
                "quotient": "0x757524ef"
            },
            {
                "offset": 3,
                "kind": "xor_mix",
                "lhs": "0x67",
                "rhs": "0x62",
                "result": "0x05"
            }
        ]);
        let summary = output_semantic_byte_equation_input_summary(&equations);
        assert_eq!(
            summary["byte_lane_sources"][0]["source_value"],
            serde_json::json!("0xa000142")
        );
        assert_eq!(
            summary["byte_lane_sources"][0]["source_byte_offsets"],
            serde_json::json!([3])
        );
        assert_eq!(
            summary["byte_lane_sources"][0]["result_hex"],
            serde_json::json!("0a")
        );
        assert_eq!(
            summary["mod255_inputs"][0]["offsets"],
            serde_json::json!([1, 13])
        );
        assert_eq!(summary["xor_lhs_offsets"], serde_json::json!([3]));
    }

    #[test]
    fn output_map_summary_exposes_top_level_semantic_byte_summary() {
        let output = serde_json::json!({
            "status": "ready",
            "strategy": "output_base64_group_map",
            "semantic_writer_map": {
                "status": "ready",
                "semantic_context": {
                    "semantic_offset": 3,
                    "semantic_count": 2
                },
                "vm_chain_summary": {
                    "chain_count": 1
                },
                "vm_chains": [
                    {
                        "start_offset": 3,
                        "bytes_hex": "05",
                        "chain": {
                            "recognized_semantics": [
                                {
                                    "step": 1,
                                    "asm": "eor w0, w1, w2",
                                    "semantic": {
                                        "kind": "xor_mix",
                                        "lhs": "0x67",
                                        "rhs": "0x62",
                                        "result": "0x05"
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
            "groups": []
        });
        let summary = output_map_summary(&output);
        assert_eq!(
            summary["semantic_byte_equation_summary"],
            summary["semantic_writer_map"]["byte_equation_summary"]
        );
        assert_eq!(
            summary["semantic_byte_input_summary"],
            summary["semantic_writer_map"]["byte_equation_input_summary"]
        );
        assert_eq!(summary["semantic_byte_equation_summary"]["count"], 1);
        assert_eq!(
            summary["semantic_byte_equation_summary"]["requested_range"],
            serde_json::json!([3, 5])
        );
        assert_eq!(
            summary["semantic_byte_equation_summary"]["missing_offsets_in_requested_range"],
            serde_json::json!([4])
        );
        assert_eq!(
            summary["semantic_byte_equation_summary"]["requested_coverage_status"],
            serde_json::json!("partial_in_requested_range")
        );
        assert_eq!(
            summary["semantic_vm_chain_summary"]["chain_count"],
            serde_json::json!(1)
        );
        assert_eq!(
            summary["semantic_writer_map"]["xor_word_template_count"],
            serde_json::json!(0)
        );
    }

    #[test]
    fn summarizes_xor_word_state_sources_from_vm_chain() {
        let templates = serde_json::json!([
            {
                "semantic_range": [3, 7],
                "lhs_word_le": "0xd84ab467"
            }
        ]);
        let value = serde_json::json!({
            "vm_chains": [
                {
                    "start_offset": 3,
                    "chain": {
                        "recognized_semantics": [
                            {
                                "step": 3,
                                "idx": 14678410,
                                "asm": "lsr w12, w7, w3",
                                "semantic": {
                                    "kind": "shift_right",
                                    "input": "0x1ab928d5",
                                    "result": "0x1a",
                                    "shift": "0x18"
                                }
                            },
                            {
                                "step": 15,
                                "idx": 14678420,
                                "asm": "lsr w0, w13, w4",
                                "semantic": {
                                    "kind": "shift_right",
                                    "input": "0x67b44ad8",
                                    "result": "0x67",
                                    "shift": "0x18"
                                }
                            },
                            {
                                "step": 19,
                                "idx": 14678154,
                                "asm": "add x13, x8, x12",
                                "semantic": {
                                    "kind": "add32_mix",
                                    "result": "0x267b44ad8",
                                    "result_low32": "0x67b44ad8"
                                }
                            }
                        ]
                    }
                }
            ]
        });
        let sources = output_semantic_xor_word_state_sources(&value, &templates);
        let first = sources.as_array().unwrap().first().unwrap();
        assert_eq!(
            first["source_status"],
            serde_json::json!("state_update_found")
        );
        assert_eq!(first["source_word_be"], serde_json::json!("0x67b44ad8"));
        assert_eq!(first["state_update"]["idx"], serde_json::json!(14678154));
    }

    #[test]
    fn summarizes_xor_word_state_source_coverage() {
        let templates = serde_json::json!([
            {"semantic_range": [0, 4], "lhs_word_le": "0x6f783e78"},
            {"semantic_range": [4, 8], "lhs_word_le": "0xb9f37778"}
        ]);
        let sources = serde_json::json!([
            {
                "semantic_range": [0, 4],
                "source_word_be": "0x783e786f",
                "source_status": "state_update_found"
            }
        ]);
        let summary = output_semantic_xor_word_state_source_summary(&templates, &sources);
        assert_eq!(summary["template_count"], serde_json::json!(2));
        assert_eq!(summary["source_count"], serde_json::json!(1));
        assert_eq!(summary["missing_count"], serde_json::json!(1));
        assert_eq!(summary["coverage_status"], serde_json::json!("partial"));
        assert_eq!(
            summary["source_status_counts"],
            serde_json::json!([{"status": "state_update_found", "count": 1}])
        );
        assert_eq!(
            summary["source_status_ranges"][0],
            serde_json::json!({
                "status": "state_update_found",
                "ranges": [
                    {
                        "semantic_range": [0, 4],
                        "lhs_word_le": null,
                        "source_word": null
                    }
                ]
            })
        );
        assert_eq!(
            summary["missing_templates"][0]["semantic_range"],
            serde_json::json!([4, 8])
        );
    }

    #[test]
    fn keeps_xor_word_sources_without_state_update() {
        let templates = serde_json::json!([
            {
                "semantic_range": [0, 4],
                "lhs_word_le": "0x69f2e9fb"
            }
        ]);
        let value = serde_json::json!({
            "vm_chains": [
                {
                    "start_offset": 0,
                    "chain": {
                        "recognized_semantics": [
                            {
                                "step": 15,
                                "idx": 14695079,
                                "asm": "orr x3, x19, x8",
                                "semantic": {
                                    "kind": "bitwise_or_merge",
                                    "lhs": "0x69000000",
                                    "rhs": "0xf2e9fb",
                                    "result": "0x69f2e9fb"
                                }
                            }
                        ]
                    }
                }
            ]
        });
        let sources = output_semantic_xor_word_state_sources(&value, &templates);
        let first = sources.as_array().unwrap().first().unwrap();
        assert_eq!(
            first["source_status"],
            serde_json::json!("word_source_only")
        );
        assert_eq!(first["source_word"], serde_json::json!("0x69f2e9fb"));
        assert_eq!(first["state_update"], serde_json::Value::Null);
    }

    #[test]
    fn pairs_vm_state_update_formula_with_following_store() {
        let ops = vec![
            serde_json::json!({
                "idx_start": 14678147,
                "alu_formulas": [
                    {
                        "idx": 14678154,
                        "asm": "add x13, x8, x12",
                        "semantic": {
                            "kind": "add32_mix",
                            "result": "0x267b44ad8",
                            "result_low32": "0x67b44ad8"
                        }
                    }
                ],
                "memory_stores": []
            }),
            serde_json::json!({
                "idx_start": 14678158,
                "alu_formulas": [],
                "memory_stores": [
                    {
                        "idx": 14678167,
                        "asm": "str w1, [x19, x6]",
                        "mem_addr": "0x74b68bb6a8",
                        "store_src": [
                            {"reg": "w1", "value": "0x267b44ad8"}
                        ]
                    }
                ]
            }),
        ];
        let updates = vm_ops_state_updates(&ops);
        let first = updates.as_array().unwrap().first().unwrap();
        assert_eq!(first["formula_idx"], serde_json::json!(14678154));
        assert_eq!(first["store_idx"], serde_json::json!(14678167));
        assert_eq!(first["store_addr"], serde_json::json!("0x74b68bb6a8"));
        assert_eq!(
            first["semantic"]["result_low32"],
            serde_json::json!("0x67b44ad8")
        );
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
        let summary = recognized_backchain_pattern_summary(&patterns);
        assert_eq!(
            summary["affine_mod64_recurrences"][0]["count"],
            serde_json::json!(1)
        );
        assert_eq!(
            summary["affine_mod64_recurrences"][0]["multiplier"],
            serde_json::json!("0x5851f42d4c957f2d")
        );
        assert_eq!(
            summary["affine_mod64_recurrences"][0]["transitions"][0]["state"],
            serde_json::json!("0x52c36263893da50d")
        );
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
    fn summarizes_vm_backchain_stop_reason() {
        let chain = vec![serde_json::json!({
            "step": 12,
            "idx": 10616024,
            "reg": "x21",
            "value": "0x75ebae5d80",
            "target": {
                "asm": "ldr x13, [x21, #8]",
                "class": "bytecode-read"
            },
            "upstream": {
                "status": "no_local_def",
                "searched_context": 120
            },
            "decision": {
                "kind": "stop",
                "reason": "no_upstream_next_or_frontier"
            }
        })];
        let stop = vm_backchain_stop_summary(&chain);
        assert_eq!(stop["idx"], serde_json::json!(10616024));
        assert_eq!(
            stop["decision"]["reason"],
            serde_json::json!("no_upstream_next_or_frontier")
        );
        assert_eq!(stop["target"]["class"], serde_json::json!("bytecode-read"));
    }

    #[test]
    fn summarizes_vm_op_slot_write_effects() {
        let op = serde_json::json!({
            "vm_slot_reads": [
                {"slot": 18, "value": "0x7a"}
            ],
            "vm_slot_writes": [
                {"idx": 10616058, "slot": 19, "value": "0x39"}
            ],
            "memory_stores": [],
            "alu_formulas": [
                {
                    "idx": 10616056,
                    "asm": "add x2, x0, x1",
                    "expression": "0x39 = 0x7a + 0xffffffffffffffbf",
                    "semantic": {
                        "kind": "add_small_delta",
                        "result": "0x39"
                    }
                }
            ]
        });
        let effects = vm_op_effect_summaries(&op);
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0]["kind"], serde_json::json!("slot_write"));
        assert_eq!(
            effects[0]["pseudocode"],
            serde_json::json!("slot[19] = 0x39 = 0x7a + 0xffffffffffffffbf")
        );
        assert_eq!(
            effects[0]["formula"]["semantic"]["kind"],
            serde_json::json!("add_small_delta")
        );
    }

    #[test]
    fn summarizes_vm_op_byte_load_effects() {
        let op = serde_json::json!({
            "vm_slot_reads": [
                {"slot": 24, "value": "0x753ddd7fd0"},
                {"slot": 25, "value": "0xc"}
            ],
            "vm_slot_writes": [
                {"idx": 10616037, "slot": 18, "value": "0x7a"}
            ],
            "small_byte_loads": [
                {"idx": 10616034, "mem_addr": "0x753ddd7fdc", "value": "0x7a"}
            ],
            "memory_stores": [],
            "alu_formulas": []
        });
        let effects = vm_op_effect_summaries(&op);
        assert_eq!(
            effects[0]["pseudocode"],
            serde_json::json!("slot[18] = byte[0x753ddd7fdc] (0x7a)")
        );
        assert_eq!(
            effects[0]["source_byte_load"]["idx"],
            serde_json::json!(10616034)
        );
    }

    #[test]
    fn vm_ops_effects_only_summary_lifts_effects_to_top_level() {
        let output = serde_json::json!({
            "status": "ready",
            "start": 10616026,
            "end": 10616041,
            "source_requested": 15,
            "source_returned": 15,
            "source_maybe_truncated": false,
            "vm_rows": 15,
            "ops_returned": 1,
            "truncated": false,
            "ops": [
                {
                    "idx_start": 10616026,
                    "idx_end": 10616041,
                    "vm_slot_reads": [
                        {"slot": 24, "value": "0x753ddd7fd0"},
                        {"slot": 25, "value": "0xc"}
                    ],
                    "vm_slot_writes": [
                        {"idx": 10616037, "slot": 18, "value": "0x7a"}
                    ],
                    "small_byte_loads": [
                        {"idx": 10616034, "mem_addr": "0x753ddd7fdc", "value": "0x7a"}
                    ],
                    "memory_stores": [
                        {
                            "idx": 10616038,
                            "class": "mem-store",
                            "mem_addr": "0x753ddd7fd0",
                            "store_src": [{"reg": "x1", "value": "0xab"}]
                        }
                    ],
                    "alu_formulas": []
                }
            ]
        });
        let summary = vm_ops_effects_only_summary(&output);
        assert!(summary.get("ops").is_none());
        assert_eq!(summary["effect_count"], serde_json::json!(2));
        assert_eq!(summary["source_maybe_truncated"], serde_json::json!(false));
        assert_eq!(summary["byte_load_effect_count"], serde_json::json!(1));
        assert_eq!(summary["memory_store_effect_count"], serde_json::json!(1));
        assert_eq!(
            summary["effects"][0]["pseudocode"],
            serde_json::json!("slot[18] = byte[0x753ddd7fdc] (0x7a)")
        );
        assert_eq!(
            summary["effects"][0]["op_idx_start"],
            serde_json::json!(10616026)
        );
        assert_eq!(
            summary["byte_load_effects"][0]["source_byte_load"]["idx"],
            serde_json::json!(10616034)
        );
        assert_eq!(
            summary["memory_store_effects"][0]["pseudocode"],
            serde_json::json!("mem[0x753ddd7fd0] = 0xab")
        );
    }

    #[test]
    fn recognizes_static_memory_load_constants() {
        let chain = vec![serde_json::json!({
            "step": 7,
            "idx": 13720349,
            "value": "0xa000142",
            "local_def": {
                "idx": 13720346,
                "asm": "ldr w16, [x8, x20]",
                "class": "mem-load"
            },
            "upstream": {
                "status": "not_found",
                "addr": "0x74fbf2dc7c",
                "idx_lo": 13520349,
                "idx_hi": 13720349,
                "returned": 0,
                "maybe_truncated": false,
                "observed_bytes_hex": "4201000a"
            }
        })];
        let patterns = recognized_backchain_patterns(&chain);
        assert_eq!(patterns.len(), 1);
        assert_eq!(
            patterns[0]["kind"],
            serde_json::json!("static_memory_load_constant")
        );
        assert_eq!(patterns[0]["bytes_hex"], serde_json::json!("4201000a"));
        assert_eq!(
            patterns[0]["source_boundary"],
            serde_json::json!("lookback_window")
        );
        assert_eq!(patterns[0]["maybe_truncated"], serde_json::json!(false));
        assert_eq!(
            patterns[0]["expression"],
            serde_json::json!(
                "value loaded from memory with no writer found in current lookback window"
            )
        );
        let summary = recognized_backchain_pattern_summary(&patterns);
        assert_eq!(
            summary["static_memory_loads"][0]["value"],
            serde_json::json!("0xa000142")
        );
    }

    #[test]
    fn recognizes_memory_boundary_reads() {
        let chain = vec![serde_json::json!({
            "step": 16,
            "idx": 14082318,
            "value": "0x30312e30",
            "local_def": {
                "idx": 14082318,
                "asm": "ldr w19, [x14, x13]",
                "class": "mem-load"
            },
            "upstream": {
                "status": "observed_read_without_matching_traced_write",
                "addr": "0x756649a2d4",
                "observed_bytes_hex": "302e3130",
                "observed_mismatches": [{"offset": 0, "observed": 0x30, "last_write": 0x30}],
                "last_write": {
                    "idx": 14062790,
                    "asm": "str x0, [x19]",
                    "src_value": "0x756649a730"
                }
            }
        })];
        let patterns = recognized_backchain_patterns(&chain);
        assert_eq!(patterns.len(), 1);
        assert_eq!(
            patterns[0]["kind"],
            serde_json::json!("memory_boundary_read")
        );
        assert_eq!(patterns[0]["bytes_hex"], serde_json::json!("302e3130"));
        let summary = recognized_backchain_pattern_summary(&patterns);
        assert_eq!(
            summary["memory_boundary_reads"][0]["addr"],
            serde_json::json!("0x756649a2d4")
        );
    }

    #[test]
    fn expands_byte_writer_map_from_little_endian_writes() {
        let response = serde_json::json!({
            "idx_range": [100, 300],
            "matched": 3,
            "returned": 3,
            "truncated": false,
            "writes": [
                {
                    "idx": 110,
                    "pc": "0x1000",
                    "rel": "0x0",
                    "func": "sub_old",
                    "asm": "strb w0, [x1]",
                    "dst_addr": "0x2001",
                    "size": 1,
                    "src_reg": "x0",
                    "src_value": "0xaa",
                    "byte0": 170
                },
                {
                    "idx": 120,
                    "pc": "0x1004",
                    "rel": "0x4",
                    "func": "sub_pack",
                    "asm": "str w16, [x2]",
                    "dst_addr": "0x2000",
                    "size": 4,
                    "src_reg": "x16",
                    "src_value": "0x616260af",
                    "byte0": 175
                },
                {
                    "idx": 130,
                    "pc": "0x1008",
                    "rel": "0x8",
                    "func": "sub_tail",
                    "asm": "strb w19, [x8, x14]",
                    "dst_addr": "0x2004",
                    "size": 1,
                    "src_reg": "x19",
                    "src_value": "0x62",
                    "byte0": 98
                }
            ]
        });
        let out = byte_writer_map_output(0x2000, 5, &response);
        assert_eq!(out["status"], serde_json::json!("ready"));
        assert_eq!(out["bytes_hex"], serde_json::json!("af60626162"));
        assert_eq!(out["bytes"][1]["byte_hex"], serde_json::json!("60"));
        assert_eq!(out["bytes"][1]["source_byte_offset"], serde_json::json!(1));
        assert_eq!(
            out["writer_runs"][0]["bytes_hex"],
            serde_json::json!("af606261")
        );
        assert_eq!(
            out["writer_runs"][0]["writer"]["idx"],
            serde_json::json!(120)
        );
        assert_eq!(
            out["writer_runs"][0]["source_byte_offsets"],
            serde_json::json!([0, 1, 2, 3])
        );
        assert_eq!(
            out["writer_runs"][0]["source_byte_offset"],
            serde_json::Value::Null
        );
        assert_eq!(out["writer_runs"][1]["bytes_hex"], serde_json::json!("62"));
        assert_eq!(byte_lane_from_writer_map_entry(&out["bytes"][2]), Some(2));
        let summary = byte_writer_map_summary(&out);
        assert_eq!(summary["byte_count"], serde_json::json!(5));
        assert_eq!(summary["ready_byte_count"], serde_json::json!(5));
        assert_eq!(summary["writer_run_count"], serde_json::json!(2));
        assert_eq!(
            summary["writer_runs"][0]["writer"]["asm"],
            serde_json::json!("str w16, [x2]")
        );
        assert!(summary.get("bytes").is_none());
    }

    #[test]
    fn summarizes_mem_dump_as_c_string() {
        let response = serde_json::json!({
            "status": "ready",
            "addr": "0x1000",
            "count": 4,
            "cursor": 10,
            "bytes": [
                {"addr": "0x1000", "byte": 47, "kind": "r", "src_idx": 1},
                {"addr": "0x1001", "byte": 0, "kind": "r", "src_idx": 1},
                {"addr": "0x1002", "byte": null, "kind": "missing", "src_idx": null},
                {"addr": "0x1003", "byte": 65, "kind": "r", "src_idx": 2}
            ]
        });
        let summary = mem_dump_summary(&response, true);
        assert_eq!(summary["bytes_hex"], serde_json::json!("2f00..41"));
        assert_eq!(summary["ascii"], serde_json::json!("/..A"));
        assert_eq!(summary["c_string"], serde_json::json!("/"));
        assert_eq!(summary["c_string_terminated"], serde_json::json!(true));
        assert_eq!(summary["nul_offset"], serde_json::json!(1));
    }

    #[test]
    fn extracts_source_byte_for_byte_addresses_inside_word_write() {
        let write = serde_json::json!({
            "dst_addr": "0x3000",
            "size": 4,
            "src_value": "0xd528b905"
        });
        assert_eq!(source_byte_for_write_at(&write, 0x3000), Some(0x05));
        assert_eq!(source_byte_for_write_at(&write, 0x3001), Some(0xb9));
        assert_eq!(source_byte_for_write_at(&write, 0x3002), Some(0x28));
        assert_eq!(source_byte_for_write_at(&write, 0x3003), Some(0xd5));
        assert_eq!(source_byte_for_write_at(&write, 0x3004), None);
        assert_eq!(source_byte_offset_for_write_at(&write, 0x3000), Some(0));
        assert_eq!(source_byte_offset_for_write_at(&write, 0x3003), Some(3));
        assert_eq!(source_byte_offset_for_write_at(&write, 0x3004), None);
    }

    #[test]
    fn chooses_matching_byte_lane_from_deduped_upstream_writers() {
        let write = serde_json::json!({
            "idx": 120,
            "pc": "0x1004",
            "rel": "0x4",
            "func": "sub_pack",
            "asm": "str w16, [x2]",
            "dst_addr": "0x4000",
            "size": 4,
            "src_reg": "x16",
            "src_value": "0xd528b905",
            "byte0": 5
        });
        let byte_writers = byte_writers_from_range_writes(0x4000, 4, &[write]);
        let step = serde_json::json!({
            "upstream": {
                "byte_nexts": dedupe_byte_nexts(&byte_writers)
            }
        });
        let lane0 = choose_laned_upstream_next(&step, 0).unwrap();
        assert_eq!(lane0["selected_byte_lane"], serde_json::json!(0));
        assert_eq!(lane0["source_byte_offset"], serde_json::json!(0));
        assert_eq!(lane0["addr"], serde_json::json!("0x4000"));

        let lane3 = choose_laned_upstream_next(&step, 3).unwrap();
        assert_eq!(lane3["selected_byte_lane"], serde_json::json!(3));
        assert_eq!(lane3["source_byte_offset"], serde_json::json!(3));
        assert_eq!(lane3["addr"], serde_json::json!("0x4003"));
    }

    #[test]
    fn detects_observed_load_bytes_that_do_not_match_traced_writers() {
        let stale_zero_write = serde_json::json!({
            "idx": 120,
            "pc": "0x1004",
            "rel": "0x4",
            "func": "sub_stale",
            "asm": "str x6, [x19, x20]",
            "dst_addr": "0x4000",
            "size": 8,
            "src_reg": "x6",
            "src_value": "0x0",
            "byte0": 0
        });
        let byte_writers = byte_writers_from_range_writes(0x4000, 4, &[stale_zero_write]);
        let observed = 0x4433_2211u64.to_le_bytes();
        let mismatches = observed_byte_writer_mismatches(0x4000, &observed[..4], &byte_writers);
        assert_eq!(mismatches.len(), 4);
        assert_eq!(mismatches[0]["observed_byte"], serde_json::json!("11"));
        assert_eq!(mismatches[0]["writer_byte"], serde_json::json!("00"));
        assert_eq!(mismatches[0]["writer_idx"], serde_json::json!(120));
    }

    #[test]
    fn lineage_prefers_matching_byte_lane_from_upstream_writers() {
        let write = serde_json::json!({
            "idx": 120,
            "pc": "0x1004",
            "rel": "0x4",
            "func": "sub_pack",
            "asm": "str w16, [x2]",
            "dst_addr": "0x4000",
            "size": 4,
            "src_reg": "x16",
            "src_value": "0xd528b905",
            "byte0": 5
        });
        let byte_writers = byte_writers_from_range_writes(0x4000, 4, &[write]);
        let backstep = serde_json::json!({
            "upstream": {
                "next": {
                    "idx": 120,
                    "reg": "x16",
                    "src_value": "0xd528b905"
                },
                "byte_nexts": dedupe_byte_nexts(&byte_writers)
            }
        });
        let (seed, decision) = lineage_next_from_backstep(&backstep, Some(2));
        let seed = seed.unwrap().to_json();
        assert_eq!(decision["kind"], serde_json::json!("upstream_byte_lane"));
        assert_eq!(seed["idx"], serde_json::json!(120));
        assert_eq!(seed["reg"], serde_json::json!("x16"));
        assert_eq!(seed["byte_lane"], serde_json::json!(2));
        assert_eq!(decision["next"]["addr"], serde_json::json!("0x4002"));
    }

    #[test]
    fn lineage_stops_at_observed_memory_boundary_before_frontier() {
        let backstep = serde_json::json!({
            "local_def": {
                "idx": 7572808,
                "asm": "ldr x8, [x1, x5]",
                "class": "mem-load",
                "def": {
                    "reg": "x8",
                    "src": [
                        {"reg": "x1", "value": "0x74974cca00"},
                        {"reg": "x5", "value": "0xfffffffffffffc48"}
                    ],
                    "value_after": "0x69f2e9fb"
                }
            },
            "upstream": {
                "status": "observed_read_without_matching_traced_write",
                "addr": "0x74974cc648",
                "addr_hi": "0x74974cc650",
                "observed_bytes_hex": "fbe9f26900000000",
                "observed_mismatches": [
                    {
                        "addr": "0x74974cc648",
                        "observed_byte": "fb",
                        "writer_byte": "00",
                        "writer_idx": 7571629
                    }
                ],
                "last_write": {
                    "idx": 7571629,
                    "asm": "str x6, [x19, x20]",
                    "src_value": "0x0"
                },
                "gap_call_candidates": {
                    "candidate_count_total": 1,
                    "candidates": [
                        {
                            "idx": 7572198,
                            "asm": "blr x22",
                            "target_module": {"name": "libc.so"}
                        }
                    ]
                }
            },
            "frontier": [
                {
                    "idx": 7572808,
                    "reason": "local_def_source_reg",
                    "reg": "x1",
                    "value": "0x74974cca00"
                }
            ]
        });
        let (seed, decision) = lineage_next_from_backstep(&backstep, Some(0));
        assert!(seed.is_none());
        assert_eq!(
            decision["kind"],
            serde_json::json!("observed_read_without_matching_traced_write")
        );
        assert_eq!(
            decision["upstream"]["observed_bytes_hex"],
            serde_json::json!("fbe9f26900000000")
        );
        assert_eq!(
            decision["upstream"]["gap_call_candidates"]["candidate_count_total"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn byte_lineage_summary_promotes_memory_boundaries() {
        let lineage = serde_json::json!({
            "status": "ready",
            "start": {"addr": "0x4000", "before_idx": 200},
            "depth_requested": 8,
            "steps_returned": 1,
            "stop_reason": {
                "kind": "terminal",
                "decision": {
                    "kind": "observed_read_without_matching_traced_write"
                }
            },
            "steps": [
                {
                    "step": 0,
                    "kind": "reg_source",
                    "seed": {"kind": "reg_at", "idx": 200, "reg": "x8"},
                    "backstep": {
                        "idx": 200,
                        "source_reg": "x8",
                        "source_value": "0x69f2e9fb",
                        "target": {"idx": 200, "asm": "str x8, [x25]", "class": "vm-reg-store"},
                        "local_def": {"idx": 199, "asm": "ldr x8, [x1]", "class": "mem-load"},
                        "upstream": {
                            "status": "observed_read_without_matching_traced_write",
                            "addr": "0x4000",
                            "addr_hi": "0x4008",
                            "observed_bytes_hex": "fbe9f26900000000",
                            "observed_mismatches": [
                                {"addr": "0x4000", "observed_byte": "fb", "writer_byte": "00"}
                            ],
                            "last_write": {"idx": 120, "asm": "str x6, [x19]", "src_value": "0x0"}
                        }
                    },
                    "decision": {
                        "kind": "observed_read_without_matching_traced_write",
                        "upstream": {
                            "addr": "0x4000",
                            "addr_hi": "0x4008",
                            "observed_bytes_hex": "fbe9f26900000000"
                        }
                    },
                    "next": null
                }
            ]
        });
        let summary = byte_lineage_summary(&lineage);
        assert_eq!(summary["memory_boundaries"].as_array().unwrap().len(), 1);
        assert_eq!(
            summary["memory_boundaries"][0]["upstream"]["observed_bytes_hex"],
            serde_json::json!("fbe9f26900000000")
        );
        assert_eq!(
            summary["memory_boundaries"][0]["value"],
            serde_json::json!("0x69f2e9fb")
        );
    }

    #[test]
    fn lineage_uses_byte_lane_when_following_shift_frontier() {
        let backstep = serde_json::json!({
            "local_def": {
                "idx": 14165576,
                "asm": "lsr x13, x17, x5",
                "class": "alu",
                "def": {
                    "reg": "x13",
                    "src": [
                        {"reg": "x17", "value": "0x74b68bbdff"},
                        {"reg": "x5", "value": "0x10"}
                    ],
                    "value_after": "0x74b68b"
                }
            },
            "upstream": {
                "status": "not_memory_backed"
            },
            "frontier": [
                {
                    "idx": 14165576,
                    "reason": "local_def_source_reg",
                    "reg": "x17",
                    "value": "0x74b68bbdff"
                },
                {
                    "idx": 14165576,
                    "reason": "local_def_source_reg",
                    "reg": "x5",
                    "value": "0x10"
                }
            ]
        });
        let (seed, decision) = lineage_next_from_backstep(&backstep, Some(0));
        let seed = seed.unwrap().to_json();
        assert_eq!(decision["kind"], serde_json::json!("frontier_auto"));
        assert_eq!(seed["reg"], serde_json::json!("x17"));
        assert_eq!(seed["byte_lane"], serde_json::json!(2));
    }

    #[test]
    fn finds_hex_byte_offsets_on_byte_boundaries() {
        assert_eq!(
            find_hex_byte_offsets("aa 62:61_62 bb 62 61 62", "626162"),
            vec![1, 5]
        );
        assert!(find_hex_byte_offsets("0626162", "626162").is_empty());
        assert!(find_hex_byte_offsets("626162", "00").is_empty());
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
    fn resolves_nm_symbols_by_nearest_preceding_offset() {
        let target = parse_nm_symbol_line("0000000000001200 0000000000000038 T target_func@@LIB")
            .expect("parse symbol");
        assert_eq!(target.addr, 0x1200);
        assert_eq!(target.size, Some(0x38));
        assert_eq!(target.name, "target_func@@LIB");

        let symbols = vec![
            ElfSymbol {
                addr: 0x1000,
                size: Some(0x20),
                kind: "T".to_string(),
                name: "helper_func@@LIB".to_string(),
            },
            target,
        ];
        let hit = resolve_elf_symbol_json(&symbols, 0x1204).unwrap();
        assert_eq!(hit["status"], serde_json::json!("nearest"));
        assert_eq!(hit["symbol_addr"], serde_json::json!("0x1200"));
        assert_eq!(hit["delta"], serde_json::json!("0x4"));
        assert_eq!(hit["name"], serde_json::json!("target_func@@LIB"));
        assert_eq!(hit["base_name"], serde_json::json!("target_func"));
        assert_eq!(hit["in_symbol_range"], serde_json::json!(true));
    }

    #[test]
    fn base64_decoder_accepts_unpadded_output() {
        let decoded = base64_decoded_bytes("SGVsbG8sIHdvcmxkIQ").unwrap();
        assert_eq!(decoded, b"Hello, world!");
    }
}

fn print_pretty(value: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
