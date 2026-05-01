"""Pydantic response models for traceMiku Web API.

These models drive the auto-generated OpenAPI schema at /openapi.json,
making the API self-documenting for LLM consumers and frontend codegen.

NOTE on permissiveness:
    Many endpoints return either a "ready" shape (full data) or a "pending"
    shape (`{"status": "building"|"error"|"empty", ...}`) depending on
    background-task readiness. Rather than building strict Union types for
    every endpoint, we set `extra='allow'` and mark most non-essential fields
    Optional so Pydantic accepts both shapes. The OpenAPI schema still lists
    the canonical "ready" fields for LLM clients to discover.

    If you need strict validation of a specific endpoint's contract, build
    a per-endpoint Union[Building, Ready] response_model.
"""
from __future__ import annotations
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict


class _Permissive(BaseModel):
    """Base model allowing extra fields. Use this for response models that
    accept multi-shape returns (ready vs building/error/empty)."""
    model_config = ConfigDict(extra='allow')


# ── Generic pending-state response ──────────────────────────────────────────

class BgPendingResponse(_Permissive):
    """Response shape when a background task is not ready yet.
    Returned by many endpoints when CFG / index / mem / decomp is building."""
    status: str       # "building" | "error" | "empty" | "idle"


# ── /api/meta ────────────────────────────────────────────────────────────────

class ModuleInfo(_Permissive):
    name: str
    base: str        # hex "0x..."
    size: int
    end: str         # hex "0x..."

class MetaResponse(_Permissive):
    path: str
    records: int
    module: Optional[ModuleInfo] = None
    modules: list[ModuleInfo] = []
    method: str = ""
    cmd: Optional[int] = None
    fn_addr: Optional[str] = None     # hex "0x..." or None
    regs: list[str] = []


# ── /api/records ─────────────────────────────────────────────────────────────

class RecordRow(_Permissive):
    idx: int
    pc: str           # hex "0x..."
    rel: Optional[str] = None
    func: Optional[str] = None
    off: Optional[str] = None
    asm: str
    annotation: Optional[str] = None
    exec_count: Optional[int] = None
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False
    regs: Optional[dict[str, str]] = None

class RecordsResponse(_Permissive):
    """May return empty `{count:0, records:[]}` for out-of-range start, or
    full `{start, end, count, records}` for a valid window."""
    start: Optional[int] = None
    end: Optional[int] = None
    count: int = 0
    records: list[RecordRow] = []


# ── /api/record/{idx} ────────────────────────────────────────────────────────

class RecordDetail(_Permissive):
    idx: int
    pc: str
    rel: Optional[str] = None
    func: Optional[str] = None
    off: Optional[str] = None
    asm: str
    regs: dict[str, str] = {}
    prev_regs: Optional[dict[str, str]] = None
    regs_annotated: dict[str, str] = {}
    regs_def: list[str] = []
    regs_use: list[str] = []
    exec_count: Optional[int] = None
    block_pc: Optional[str] = None
    cfg_status: str = ""
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False


# ── /api/cfg ─────────────────────────────────────────────────────────────────

class CfgBlock(_Permissive):
    id: str           # hex
    start: str        # hex
    end: str          # hex
    rel: Optional[str] = None
    func: Optional[str] = None
    insns: int = 0
    executions: int = 0
    label: str = ""

class CfgEdge(_Permissive):
    id: str
    src: str
    dst: str
    kind: str
    count: int = 0

class CfgFuncSummary(_Permissive):
    name: str
    blocks: int

class CfgResponse(_Permissive):
    """Either ready (with blocks/edges/...) or building (with cfg/pc_inst/...)."""
    status: str
    # Ready fields (Optional, present when status == "ready")
    blocks: Optional[list[CfgBlock]] = None
    edges: Optional[list[CfgEdge]] = None
    entry: Optional[str] = None
    block_count: Optional[int] = None
    edge_count: Optional[int] = None
    total_block_count: Optional[int] = None
    fn: Optional[str] = None
    funcs: Optional[list[CfgFuncSummary]] = None
    # Building fields (Optional, present when status == "building")
    cfg: Optional[str] = None
    pc_inst: Optional[str] = None
    elapsed: Optional[dict[str, float]] = None
    errors: Optional[dict[str, Optional[str]]] = None


# ── /api/block ───────────────────────────────────────────────────────────────

class BlockInsn(_Permissive):
    pc: str
    rel: Optional[str] = None
    asm: str
    is_branch: bool = False
    is_call: bool = False
    is_ret: bool = False

class BlockExit(_Permissive):
    to: str
    kind: str

class BlockDetail(_Permissive):
    """May be either ready (start/end/insns/...) or building ({status})."""
    status: Optional[str] = None
    start: Optional[str] = None
    end: Optional[str] = None
    func: Optional[str] = None
    off: Optional[str] = None
    executions: Optional[int] = None
    insns: Optional[list[BlockInsn]] = None
    exits: Optional[list[BlockExit]] = None


# ── /api/loops ───────────────────────────────────────────────────────────────

class LoopInfo(_Permissive):
    members: list[str] = []
    size: int = 0

class LoopsResponse(_Permissive):
    status: str
    loops: list[LoopInfo] = []
    count: Optional[int] = None


# ── /api/search ──────────────────────────────────────────────────────────────

class SearchHit(_Permissive):
    idx: int
    pc: str
    asm: str

class SearchResponse(_Permissive):
    count: int = 0
    pattern: str = ""
    hits: list[SearchHit] = []


# ── /api/strings ─────────────────────────────────────────────────────────────

class StringEntry(_Permissive):
    addr: str         # hex
    value: str
    length: Optional[int] = None

class StringsResponse(_Permissive):
    """May be ready ({status:'ready', count, cursor, ...}) or pending."""
    status: str
    strings: list[StringEntry] = []
    count: Optional[int] = None
    cursor: Optional[int] = None


# ── /api/forward-taint ───────────────────────────────────────────────────────

class TaintHit(_Permissive):
    idx: int
    pc: str
    why: Optional[str] = None

class TaintResponse(_Permissive):
    """forward-taint returns hits[]; backward-taint returns chain[]."""
    status: Optional[str] = None
    count: Optional[int] = None
    hits: Optional[list[TaintHit]] = None
    chain: Optional[list[TaintHit]] = None
    reg: Optional[str] = None


# ── /api/mem-dump ────────────────────────────────────────────────────────────

class MemDumpResponse(_Permissive):
    """May be ready (addr/bytes/count) or pending ({status})."""
    status: Optional[str] = None
    addr: Optional[str] = None
    bytes: Optional[list[Any]] = None
    count: Optional[int] = None


# ── /api/idxs-for-pc, /api/idxs-for-block ────────────────────────────────────

class IdxsResponse(_Permissive):
    """idxs-for-pc returns {idxs, kinds}; idxs-for-block returns {block, idxs, total, truncated} or pending {status, idxs:[]}."""
    status: Optional[str] = None
    idxs: list[int] = []
    kinds: Optional[list[str]] = None
    block: Optional[str] = None
    total: Optional[int] = None
    truncated: Optional[bool] = None
    pc: Optional[str] = None
    cursor: Optional[int] = None


# ── /api/backtrace ───────────────────────────────────────────────────────────

class BacktraceFrame(_Permissive):
    idx: int
    pc: str
    func: Optional[str] = None

class BacktraceResponse(_Permissive):
    status: Optional[str] = None
    idx: Optional[int] = None
    stack: list[BacktraceFrame] = []
    depth: int = 0


# ── /api/bg-status ───────────────────────────────────────────────────────────

class BgTaskStatus(_Permissive):
    status: str
    started_at: Optional[float] = None
    elapsed: Optional[float] = None
    err: Optional[str] = None

class BgStatusResponse(_Permissive):
    """One field per BG task; permissive — actual key set may evolve."""


# ── /api/last-write-of-reg ───────────────────────────────────────────────────

class LastWriteResponse(_Permissive):
    status: Optional[str] = None
    idx: Optional[int] = None
    pc: Optional[str] = None
    func: Optional[str] = None
    err: Optional[str] = None


# ── /api/reg-value-at ────────────────────────────────────────────────────────

class RegValueResponse(_Permissive):
    status: Optional[str] = None
    idx: Optional[int] = None
    reg: Optional[str] = None
    value: Optional[str] = None        # hex


# ── /api/idxs-touching-range, /api/idxs-touching-addr ────────────────────────

class TouchingResponse(_Permissive):
    """Either pending ({status,...}) or various ready shapes — kept permissive."""
    status: Optional[str] = None
    addr: Optional[str] = None
    cursor: Optional[int] = None
    size: Optional[int] = None
    before: Optional[list[Any]] = None
    after: Optional[list[Any]] = None
    writers_before: Optional[list[Any]] = None
    writers_after: Optional[list[Any]] = None


# ── /api/string-provenance ───────────────────────────────────────────────────

class StringProvenanceResponse(_Permissive):
    status: Optional[str] = None
    addr: Optional[str] = None
    length: Optional[int] = None
    bytes: Optional[list[Any]] = None


# ── /api/decomp-status ───────────────────────────────────────────────────────

class DecompStatusResponse(_Permissive):
    """Backend status — fields vary; kept permissive."""


# ── /api/asm-tokens-for-pcs ──────────────────────────────────────────────────

class AsmToken(_Permissive):
    cls: str
    text: str

class AsmTokensResponse(_Permissive):
    status: Optional[str] = None
    ready: Optional[bool] = None
    tokens: Optional[dict[str, list[AsmToken]]] = None


# ── /api/hlil-for-pc ─────────────────────────────────────────────────────────

class HlilLine(_Permissive):
    pc_lo: Optional[str] = None
    pc_hi: Optional[str] = None
    text: str = ""
    tokens: list[AsmToken] = []

class HlilResponse(_Permissive):
    status: Optional[str] = None
    ready: Optional[bool] = None
    pc: Optional[str] = None
    lines: Optional[list[HlilLine]] = None


# ── /api/bn-cfg-svg-for-pc ──────────────────────────────────────────────────

class BnCfgSvgResponse(_Permissive):
    status: Optional[str] = None
    svg: Optional[str] = None
    err: Optional[str] = None


# ── /api/bn-cfg-for-pc ──────────────────────────────────────────────────────

class BnCfgBlock(_Permissive):
    start: str
    end: str
    label: str = ""

class BnCfgEdge(_Permissive):
    src: str
    dst: str
    kind: str
    style: Optional[str] = None

class BnCfgForPcResponse(_Permissive):
    status: Optional[str] = None
    ready: Optional[bool] = None
    fn: Optional[str] = None
    name: Optional[str] = None
    blocks: Optional[list[BnCfgBlock]] = None
    edges: Optional[list[BnCfgEdge]] = None
    cur_bb: Optional[str] = None


# ── /api/block-for-pc ────────────────────────────────────────────────────────

class BlockForPcResponse(_Permissive):
    pc: str
    block: Optional[str] = None
    cfg_status: Optional[str] = None


# ── /api/field-at (新增 9.3) ─────────────────────────────────────────────────

class FieldAtResponse(_Permissive):
    """Struct field hint at (pc, reg, offset). Returns null if not found."""
    pc: str
    reg: str
    offset: int
    hit: bool = False
    struct: Optional[str] = None
    field: Optional[str] = None
    type_name: Optional[str] = None


# ── Backwards-compat aliases ────────────────────────────────────────────────
# 老代码 import 这些名字 — 把 ready-only model 指向新的 permissive model

CfgBuildingResponse = CfgResponse
CfgReadyResponse = CfgResponse
