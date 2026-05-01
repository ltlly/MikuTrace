"""Pydantic response models for traceMiku Web API.

Strict per-endpoint schemas matching actual server.py returns. Multi-shape
endpoints (ready vs pending vs error) use Union types — Pydantic tries each
arm in order. OpenAPI schema (`/openapi.json`) reflects exact field
requirements per state, so LLM/MCP/frontend codegen can rely on it.

Backward-compat aliases (CfgReadyResponse, CfgBuildingResponse) preserved at
the bottom for old import sites.
"""
from __future__ import annotations
from typing import Optional, Union, Literal, Any
from pydantic import BaseModel, Field


# ── /api/meta ────────────────────────────────────────────────────────────────

class ModuleInfo(BaseModel):
    name: str
    base: str        # hex "0x..."
    size: int
    end: str         # hex "0x..."

class MetaResponse(BaseModel):
    path: str
    records: int
    module: Optional[ModuleInfo] = None
    modules: list[ModuleInfo] = []
    method: str = ""
    cmd: Optional[int] = None
    fn_addr: Optional[str] = None
    regs: list[str]


# ── /api/records ─────────────────────────────────────────────────────────────

class RecordRow(BaseModel):
    idx: int
    pc: str
    rel: Optional[str] = None
    module: Optional[str] = None         # SO name; for multi-SO traces enables UI filter
    func: Optional[str] = None
    off: Optional[str] = None
    asm: str
    annotation: Optional[str] = None
    exec_count: Optional[int] = None
    is_branch: bool
    is_call: bool
    is_ret: bool
    regs: Optional[dict[str, str]] = None

class RecordsResponse(BaseModel):
    """Always returns start/end/count/records. Empty when start out of range."""
    start: int
    end: int
    count: int
    records: list[RecordRow]


# ── /api/record/{idx} ────────────────────────────────────────────────────────

class RecordDetail(BaseModel):
    idx: int
    pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    off: Optional[str] = None
    asm: str
    regs: dict[str, str]
    prev_regs: Optional[dict[str, str]] = None
    regs_annotated: dict[str, str] = {}
    regs_def: list[str]
    regs_use: list[str]
    exec_count: Optional[int] = None
    block_pc: Optional[str] = None
    cfg_status: str
    is_branch: bool
    is_call: bool
    is_ret: bool


# ── /api/cfg ─────────────────────────────────────────────────────────────────

class CfgBlock(BaseModel):
    id: str
    start: str
    end: str
    rel: Optional[str] = None
    func: Optional[str] = None
    insns: int
    executions: int
    label: str

class CfgEdge(BaseModel):
    id: str
    src: str
    dst: str
    kind: str
    count: int

class CfgFuncSummary(BaseModel):
    name: str
    blocks: int

class CfgBuildingResponse(BaseModel):
    """CFG/pc_inst not ready yet."""
    status: Literal["building"]
    cfg: str
    pc_inst: str
    elapsed: dict[str, float]
    errors: dict[str, Optional[str]]

class CfgReadyResponse(BaseModel):
    status: Literal["ready"]
    blocks: list[CfgBlock]
    edges: list[CfgEdge]
    entry: str
    block_count: int
    edge_count: int
    total_block_count: int
    fn: Optional[str] = None
    funcs: list[CfgFuncSummary]

CfgResponse = Union[CfgReadyResponse, CfgBuildingResponse]


# ── /api/block-for-pc ────────────────────────────────────────────────────────

class BlockForPcResponse(BaseModel):
    pc: str
    block: Optional[str] = None
    cfg_status: Optional[str] = None


# ── /api/reg-timeline (5.4) ─────────────────────────────────────────────────

class RegTimelinePoint(BaseModel):
    idx: int
    value: str        # hex

class RegTimelineResponse(BaseModel):
    """All distinct values of a register across [start_idx, end_idx).
    Each entry is the first idx where that value appeared."""
    reg: str
    start: int
    end: int
    count: int
    points: list[RegTimelinePoint]
    truncated: bool


# ── /api/mem-diff (5.4) ─────────────────────────────────────────────────────

class MemDiffByte(BaseModel):
    addr: str
    before: Optional[int] = None     # byte value before idx (None = ??)
    after: Optional[int] = None      # byte value at/after idx
    changed: bool

class MemDiffResponse(BaseModel):
    """Memory state difference at trace cursor `idx` for [addr, addr+size)."""
    idx: int
    addr: str
    size: int
    bytes: list[MemDiffByte]
    changed_count: int


# ── /api/fn-summary (5.4) ───────────────────────────────────────────────────

class FnSummaryHotBlock(BaseModel):
    pc: str
    rel: Optional[str] = None
    insns: int
    executions: int

class FnSummaryCallee(BaseModel):
    pc: str
    func: Optional[str] = None
    count: int

class FnSummaryReadyResponse(BaseModel):
    status: Literal["ready"]
    fn: str
    pc: str                          # canonical entry pc
    rel: Optional[str] = None
    block_count: int
    total_executions: int            # sum of block executions
    entry_idxs: list[int]            # trace idxs where fn was entered
    entry_idxs_total: int
    hot_blocks: list[FnSummaryHotBlock]
    callees: list[FnSummaryCallee]   # bl/blr targets reached from this fn

class FnSummaryPendingResponse(BaseModel):
    status: str        # "building" | "idle" — CFG not ready

class FnSummaryNotFoundResponse(BaseModel):
    status: Literal["not-found"]
    fn: str

FnSummaryResponse = Union[FnSummaryReadyResponse, FnSummaryNotFoundResponse,
                          FnSummaryPendingResponse]


# ── /api/cfg-svg (5 shapes: building/ready-fresh/ready-cached/empty/error) ──

class CfgSvgBuildingResponse(BaseModel):
    status: Literal["building"]
    cfg: str
    pc_inst: str

class CfgSvgEmptyResponse(BaseModel):
    status: Literal["empty"]
    fn: Optional[str] = None
    svg: Optional[str] = None    # always null for empty

class CfgSvgErrorResponse(BaseModel):
    status: Literal["error"]
    err: str

class CfgSvgReadyResponse(BaseModel):
    """status='ready' covers both fresh-render and cached-hit. `cached` flag
    distinguishes them (None on fresh render, True on cache hit)."""
    status: Literal["ready"]
    fn: Optional[str] = None
    svg: str
    block_count: int
    total_block_count: int
    cached: Optional[bool] = None    # only set to True on cache hit

CfgSvgResponse = Union[CfgSvgReadyResponse, CfgSvgEmptyResponse,
                       CfgSvgErrorResponse, CfgSvgBuildingResponse]


# ── /api/block ───────────────────────────────────────────────────────────────

class BlockInsn(BaseModel):
    pc: str
    rel: Optional[str] = None
    asm: str
    is_branch: bool
    is_call: bool
    is_ret: bool

class BlockExit(BaseModel):
    to: str
    kind: str

class BlockPendingResponse(BaseModel):
    status: str        # "building" | "idle" | "error"

class BlockDetail(BaseModel):
    start: str
    end: str
    func: Optional[str] = None
    off: Optional[str] = None
    executions: int
    insns: list[BlockInsn]
    exits: list[BlockExit]

BlockResponse = Union[BlockDetail, BlockPendingResponse]


# ── /api/loops ───────────────────────────────────────────────────────────────

class LoopInfo(BaseModel):
    members: list[str]
    size: int

class LoopsPendingResponse(BaseModel):
    status: str
    loops: list[LoopInfo] = []

class LoopsReadyResponse(BaseModel):
    status: Literal["ready"]
    loops: list[LoopInfo]
    count: int

LoopsResponse = Union[LoopsReadyResponse, LoopsPendingResponse]


# ── /api/backtrace ───────────────────────────────────────────────────────────

class BacktraceFrame(BaseModel):
    call_site_idx: int
    call_pc: str
    call_pc_fmt: Optional[str] = None
    callee_pc: Optional[str] = None
    callee_pc_fmt: Optional[str] = None
    fn: Optional[str] = None

class BacktracePendingResponse(BaseModel):
    status: str
    stack: list[BacktraceFrame] = []
    depth: int = 0

class BacktraceReadyResponse(BaseModel):
    status: Literal["ready"]
    idx: int
    stack: list[BacktraceFrame]
    depth: int

BacktraceResponse = Union[BacktraceReadyResponse, BacktracePendingResponse]


# ── /api/idxs-for-pc ─────────────────────────────────────────────────────────

class IdxsForPcResponse(BaseModel):
    """Single shape (always ready): cursor-relative neighborhood of PC hits."""
    status: Literal["ready"]
    pc: str
    cursor: int
    before: list[int]
    after: list[int]
    total_before: int
    total_after: int
    before_capped: bool
    after_capped: bool


# ── /api/idxs-for-block ──────────────────────────────────────────────────────

class IdxsForBlockPendingResponse(BaseModel):
    status: str
    idxs: list[int] = []

class IdxsForBlockReadyResponse(BaseModel):
    block: str
    idxs: list[int]
    truncated: bool
    total: int

IdxsForBlockResponse = Union[IdxsForBlockReadyResponse, IdxsForBlockPendingResponse]


# ── /api/search ──────────────────────────────────────────────────────────────

class SearchHit(BaseModel):
    idx: int
    pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    off: Optional[str] = None
    asm: str

class SearchResponse(BaseModel):
    count: int
    pattern: str
    hits: list[SearchHit]


# ── /api/forward-taint ───────────────────────────────────────────────────────

class TaintHit(BaseModel):
    idx: int
    pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    asm: str
    why: Optional[str] = None
    via: Optional[str] = None        # only on backward-taint

class ForwardTaintPendingResponse(BaseModel):
    status: str
    hits: list[TaintHit] = []

class ForwardTaintReadyResponse(BaseModel):
    count: int
    from_: int = Field(alias="from")
    reg: str
    hits: list[TaintHit]

    model_config = {"populate_by_name": True}

ForwardTaintResponse = Union[ForwardTaintReadyResponse, ForwardTaintPendingResponse]


# ── /api/backward-taint ──────────────────────────────────────────────────────

class BackwardTaintPendingResponse(BaseModel):
    status: str
    chain: list[TaintHit] = []

class BackwardTaintReadyResponse(BaseModel):
    count: int
    from_: int = Field(alias="from")
    reg: str
    chain: list[TaintHit]

    model_config = {"populate_by_name": True}

BackwardTaintResponse = Union[BackwardTaintReadyResponse, BackwardTaintPendingResponse]

# 老 import 的兜底名 — 实际 server.py 用的是这个
TaintResponse = Union[ForwardTaintReadyResponse, ForwardTaintPendingResponse,
                      BackwardTaintReadyResponse, BackwardTaintPendingResponse]


# ── /api/strings ─────────────────────────────────────────────────────────────

class StringEntry(BaseModel):
    addr: str
    len: int
    str: str

class StringsPendingResponse(BaseModel):
    status: str
    strings: list[StringEntry] = []

class StringsReadyResponse(BaseModel):
    status: Literal["ready"]
    count: int
    cursor: int
    strings: list[StringEntry]

StringsResponse = Union[StringsReadyResponse, StringsPendingResponse]


# ── /api/string-provenance ───────────────────────────────────────────────────

class StringProvByte(BaseModel):
    addr: str
    byte: Optional[int] = None
    kind: str             # "r" | "w" | "??"
    writers: list[int]
    readers: list[int]
    writers_total: int
    readers_total: int

class StringProvPendingResponse(BaseModel):
    status: str
    bytes: list[StringProvByte] = []

class StringProvReadyResponse(BaseModel):
    status: Literal["ready"]
    addr: str
    length: int
    bytes: list[StringProvByte]

StringProvenanceResponse = Union[StringProvReadyResponse, StringProvPendingResponse]


# ── /api/mem-dump ────────────────────────────────────────────────────────────

class MemDumpByte(BaseModel):
    addr: str
    byte: Optional[int] = None
    kind: str
    src_idx: Optional[int] = None

class MemDumpPendingResponse(BaseModel):
    status: str
    bytes: list[MemDumpByte] = []

class MemDumpReadyResponse(BaseModel):
    status: Literal["ready"]
    addr: str
    count: int
    bytes: list[MemDumpByte]

MemDumpResponse = Union[MemDumpReadyResponse, MemDumpPendingResponse]


# ── /api/last-write-of-reg ───────────────────────────────────────────────────

class LastWriteErrorResponse(BaseModel):
    status: Literal["error"]
    err: str

class LastWriteReadyResponse(BaseModel):
    status: Literal["ready"]
    idx: Optional[int] = None
    value: Optional[str] = None     # hex or null

LastWriteResponse = Union[LastWriteReadyResponse, LastWriteErrorResponse]


# ── /api/reg-value-at ────────────────────────────────────────────────────────

class RegValueResponse(BaseModel):
    status: Literal["ready"]
    idx: int
    reg: str
    value: Optional[str] = None     # hex


# ── /api/idxs-touching-range ─────────────────────────────────────────────────

class TouchingRangePendingResponse(BaseModel):
    status: str
    writers_before: list[int] = []
    writers_after: list[int] = []
    writers_total: int = 0
    readers_before: list[int] = []
    readers_after: list[int] = []
    readers_total: int = 0

class TouchingRangeReadyResponse(BaseModel):
    status: Literal["ready"]
    addr: str
    size: int
    cursor: int
    writers_before: list[int]
    writers_after: list[int]
    writers_total: int
    readers_before: list[int]
    readers_after: list[int]
    readers_total: int

TouchingRangeResponse = Union[TouchingRangeReadyResponse, TouchingRangePendingResponse]


# ── /api/idxs-touching-addr ──────────────────────────────────────────────────

class TouchingAddrEntry(BaseModel):
    idx: int
    kind: str        # "r" | "w"

class TouchingAddrPendingResponse(BaseModel):
    status: str
    before: list[TouchingAddrEntry] = []
    after: list[TouchingAddrEntry] = []

class TouchingAddrEmptyResponse(BaseModel):
    status: Literal["ready"]
    addr: str
    before: list[TouchingAddrEntry]   # empty
    after: list[TouchingAddrEntry]    # empty
    total_before: int
    total_after: int

class TouchingAddrReadyResponse(BaseModel):
    status: Literal["ready"]
    addr: str
    cursor: int
    before: list[TouchingAddrEntry]
    after: list[TouchingAddrEntry]
    total_before: int
    total_after: int

TouchingAddrResponse = Union[TouchingAddrReadyResponse, TouchingAddrEmptyResponse,
                              TouchingAddrPendingResponse]

# 老 import 兜底 — server.py 现在两个 endpoint 共用 TouchingResponse 名
TouchingResponse = Union[TouchingRangeReadyResponse, TouchingRangePendingResponse,
                          TouchingAddrReadyResponse, TouchingAddrEmptyResponse,
                          TouchingAddrPendingResponse]


# ── /api/bg-status ───────────────────────────────────────────────────────────

class BgTaskStatus(BaseModel):
    status: str
    started_at: Optional[float] = None
    ready_at: Optional[float] = None
    err: Optional[str] = None

class BgStatusResponse(BaseModel):
    """Dynamic key set (one per BG task + 'decomp'). Defined as dict alias."""
    # 字典形式动态键, Pydantic root_model 太重 — 直接接 dict[str, dict]
    pass

    model_config = {"extra": "allow"}    # bg_status returns flat dict


# ── /api/decomp-status ───────────────────────────────────────────────────────

class DecompStatusResponse(BaseModel):
    """{name, status, err, started_at, ready_at, so_path, elapsed?}"""
    status: str
    name: Optional[str] = None
    err: Optional[str] = None
    started_at: Optional[float] = None
    ready_at: Optional[float] = None
    so_path: Optional[str] = None
    elapsed: Optional[float] = None


# ── /api/asm-tokens-for-pcs ──────────────────────────────────────────────────

class AsmTokenWire(BaseModel):
    """Compact wire form: t=text, c=cls, a?=addr."""
    t: str
    c: str
    a: Optional[str] = None

class AsmTokensResponse(BaseModel):
    ready: bool
    status: str
    tokens: dict[str, list[AsmTokenWire]]


# ── /api/data-chase (Gap-F) ──────────────────────────────────────────────────

class DataChaseStep(BaseModel):
    idx: int
    pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    asm: str
    via: str             # "mem-load" | "mem-store-src" | "reg" | "terminal"
    src: str             # reg name OR hex addr OR "(no data deps)"

class DataChaseResponse(BaseModel):
    from_: int = Field(alias="from")
    reg: str
    count: int
    steps: list[DataChaseStep]
    model_config = {"populate_by_name": True}


# ── /api/last-write-of-addr (Gap-B) ──────────────────────────────────────────

class LastWriteOfAddrFoundResponse(BaseModel):
    status: Literal["found"]
    addr: str
    before_idx: int
    writer_idx: int
    writer_pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    asm: str
    src_reg: Optional[str] = None
    src_value: Optional[str] = None
    writes_before: int
    writes_after: int

class LastWriteOfAddrNotFoundResponse(BaseModel):
    status: Literal["not-found"]
    addr: str
    before_idx: int
    writes_total: int

LastWriteOfAddrResponse = Union[LastWriteOfAddrFoundResponse,
                                 LastWriteOfAddrNotFoundResponse]


# ── /api/find-mem-pattern (Gap-H) ────────────────────────────────────────────

class MemPatternHit(BaseModel):
    addr: str
    first_idx: Optional[int] = None

class FindMemPatternResponse(BaseModel):
    pattern: str
    since_idx: int
    count: int
    hits: list[MemPatternHit]


# ── /api/jni-calls (Gap-J) ──────────────────────────────────────────────────

class JniCallHit(BaseModel):
    idx: int
    pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    jni_fn: str
    vtable_offset: str
    args: dict[str, str]

class JniCallsResponse(BaseModel):
    in_fn: Optional[str] = None
    count: int
    hits: list[JniCallHit]
    vtable_size: int


# ── /api/jobj-history (Gap-K) ───────────────────────────────────────────────

class JobjHistoryHit(BaseModel):
    idx: int
    pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    jni_fn: str
    vtable_offset: str
    match_arg: str          # which arg (x1..x4) the jobject matched
    args: dict[str, str]

class JobjHistoryResponse(BaseModel):
    jobject: str
    start: int
    end: int
    count: int
    hits: list[JobjHistoryHit]


# ── /api/so-stats (multi-SO) ────────────────────────────────────────────────

class SoStatsModule(BaseModel):
    name: str
    base: str
    end: str
    size: int
    records: int
    percent: float

class SoStatsResponse(BaseModel):
    records: int
    modules_total: int
    unknown_records: int
    unknown_percent: float
    modules: list[SoStatsModule]


# ── /api/jni-strings (Gap-L) ────────────────────────────────────────────────

class JniStringHit(BaseModel):
    idx: int
    pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    jni_fn: str
    arg_name: str
    direction: str          # "in" | "out_x0" | "out_x4"
    x1: str
    x2: str
    buffer_addr: Optional[str] = None
    observed_bytes: Optional[int] = None
    string: Optional[str] = None

class JniStringsResponse(BaseModel):
    count: int
    with_observed_string: int
    without_observed_string: int
    note: str
    hits: list[JniStringHit]


# ── /api/field-at ────────────────────────────────────────────────────────────

class FieldAtResponse(BaseModel):
    pc: str
    reg: str
    offset: int
    hit: bool = False
    struct: Optional[str] = None
    field: Optional[str] = None
    type_name: Optional[str] = None


# ── /api/hlil-for-pc ─────────────────────────────────────────────────────────

class HlilFnInfo(BaseModel):
    name: str
    start: str
    end: str

class HlilTraceFnInfo(BaseModel):
    name: str
    off: str

class HlilLineWire(BaseModel):
    pc: str
    text: str
    indent: int = 0
    tokens: Optional[list[AsmTokenWire]] = None

class HlilVarInfo(BaseModel):
    name: str
    type: Optional[str] = None
    storage: Optional[str] = None

class HlilNotReadyResponse(BaseModel):
    ready: Literal[False]
    status: str
    err: Optional[str] = None
    elapsed: Optional[float] = None

class HlilNoFunctionResponse(BaseModel):
    ready: Literal[True]
    status: Literal["no-function"]
    pc: str

class HlilOkResponse(BaseModel):
    ready: Literal[True]
    status: Literal["ok"]
    backend: str
    pc: str
    in_range: bool
    fn: HlilFnInfo
    trace_fn: Optional[HlilTraceFnInfo] = None
    vars: list[HlilVarInfo]
    lines: list[HlilLineWire]
    current_line_idx: int

HlilResponse = Union[HlilOkResponse, HlilNoFunctionResponse, HlilNotReadyResponse]


# ── /api/bn-cfg-svg-for-pc ──────────────────────────────────────────────────

class BnCfgFnInfo(BaseModel):
    name: str
    start: str
    end: str

class BnCfgSvgPendingResponse(BaseModel):
    status: str        # any of: "loading"|"idle"|"disabled"|"no-function"|"empty-cfg"

class BnCfgSvgTooLargeResponse(BaseModel):
    status: Literal["too-large"]
    fn: BnCfgFnInfo
    block_count: int
    edge_count: int
    err: str

class BnCfgSvgErrorResponse(BaseModel):
    status: Literal["error"]
    err: str

class BnCfgSvgOkResponse(BaseModel):
    status: Literal["ok"]
    fn: BnCfgFnInfo
    block_count: int
    total_block_count: int
    edge_count: int
    dyn_only_count: int
    fn_total_exec: int
    current_bb: Optional[str] = None
    svg: str

BnCfgSvgResponse = Union[BnCfgSvgOkResponse, BnCfgSvgTooLargeResponse,
                         BnCfgSvgErrorResponse, BnCfgSvgPendingResponse]


# ── /api/bn-cfg-for-pc ──────────────────────────────────────────────────────

class BnCfgFnNameOnly(BaseModel):
    name: str

class BnCfgLineWire(BaseModel):
    pc: str
    text: str
    tokens: Optional[list[AsmTokenWire]] = None

class BnCfgBlock(BaseModel):
    start: str
    end: str
    exec_count: int
    lines: list[BnCfgLineWire]

class BnCfgEdge(BaseModel):
    src: str
    dst: str
    kind: str
    seen_in_trace: bool

class BnCfgPendingResponse(BaseModel):
    ready: Literal[False]
    status: str

class BnCfgNoFunctionResponse(BaseModel):
    ready: Literal[True]
    status: Literal["no-function"]

class BnCfgEmptyResponse(BaseModel):
    ready: Literal[True]
    status: Literal["empty-cfg"]
    fn: BnCfgFnNameOnly

class BnCfgOkResponse(BaseModel):
    ready: Literal[True]
    status: Literal["ok"]
    backend: str
    mode: str
    pc: str
    fn: BnCfgFnInfo
    current_bb: Optional[str] = None
    fn_total_exec: int
    blocks: list[BnCfgBlock]
    edges: list[BnCfgEdge]

BnCfgForPcResponse = Union[BnCfgOkResponse, BnCfgEmptyResponse,
                            BnCfgNoFunctionResponse, BnCfgPendingResponse]


# ── Backwards-compat aliases (server.py imports these names) ────────────────

# Old single-name imports map to the Union types or specific models
# so existing `response_model=XYZ` keep working with no change.
