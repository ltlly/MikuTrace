"""Pydantic response models for traceMiku Web API.

These models drive the auto-generated OpenAPI schema at /openapi.json,
making the API self-documenting for LLM consumers and frontend codegen.
"""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel


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
    fn_addr: Optional[str] = None     # hex "0x..." or None
    regs: list[str]


# ── /api/records ─────────────────────────────────────────────────────────────

class RecordRow(BaseModel):
    idx: int
    pc: str           # hex "0x..."
    rel: Optional[str] = None
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
    id: str           # hex
    start: str        # hex
    end: str          # hex
    rel: Optional[str] = None
    func: Optional[str] = None
    insns: int
    executions: int
    label: str

class CfgEdge(BaseModel):
    id: str
    src: str          # hex
    dst: str          # hex
    kind: str
    count: int

class CfgFuncSummary(BaseModel):
    name: str
    blocks: int

class CfgBuildingResponse(BaseModel):
    status: str
    cfg: str
    pc_inst: str
    elapsed: dict[str, float]
    errors: dict[str, Optional[str]]

class CfgReadyResponse(BaseModel):
    status: str
    blocks: list[CfgBlock]
    edges: list[CfgEdge]
    entry: str
    block_count: int
    edge_count: int
    total_block_count: int
    fn: Optional[str] = None
    funcs: list[CfgFuncSummary]


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

class BlockDetail(BaseModel):
    start: str
    end: str
    func: Optional[str] = None
    off: Optional[str] = None
    executions: int
    insns: list[BlockInsn]
    exits: list[BlockExit]


# ── /api/loops ───────────────────────────────────────────────────────────────

class LoopInfo(BaseModel):
    members: list[str]
    size: int

class LoopsResponse(BaseModel):
    status: str
    loops: list[LoopInfo]
    count: int


# ── /api/search ──────────────────────────────────────────────────────────────

class SearchResponse(BaseModel):
    query: str
    matches: list[int]
    count: int


# ── /api/strings ─────────────────────────────────────────────────────────────

class StringEntry(BaseModel):
    addr: str         # hex
    value: str
    length: int

class StringsResponse(BaseModel):
    strings: list[StringEntry]
    count: int


# ── /api/forward-taint, /api/backward-taint ──────────────────────────────────

class TaintStep(BaseModel):
    idx: int
    pc: str
    why: Optional[str] = None

class TaintResponse(BaseModel):
    steps: list[TaintStep]
    count: int


# ── /api/mem-dump ────────────────────────────────────────────────────────────

class MemDumpResponse(BaseModel):
    addr: str
    size: int
    hex: str
    ascii: str


# ── /api/idxs-for-pc, /api/idxs-for-block ────────────────────────────────────

class IdxsResponse(BaseModel):
    idxs: list[int]
    count: int


# ── /api/backtrace ───────────────────────────────────────────────────────────

class BacktraceEntry(BaseModel):
    idx: int
    pc: str
    func: Optional[str] = None

class BacktraceResponse(BaseModel):
    backtrace: list[BacktraceEntry]
    count: int


# ── /api/bg-status ───────────────────────────────────────────────────────────

class BgTaskStatus(BaseModel):
    status: str
    started_at: Optional[float] = None
    elapsed: Optional[float] = None
    err: Optional[str] = None

class BgStatusResponse(BaseModel):
    cfg: BgTaskStatus
    pc_inst: BgTaskStatus
    pc_to_block: BgTaskStatus
    block_idxs: BgTaskStatus
    mem: BgTaskStatus


# ── /api/last-write-of-reg ───────────────────────────────────────────────────

class LastWriteResponse(BaseModel):
    idx: int
    pc: str
    func: Optional[str] = None


# ── /api/reg-value-at ────────────────────────────────────────────────────────

class RegValueResponse(BaseModel):
    idx: int
    value: str        # hex


# ── /api/idxs-touching-range, /api/idxs-touching-addr ────────────────────────

class TouchingIdx(BaseModel):
    idx: int
    pc: str
    addr: str
    kind: str         # "r" or "w"

class TouchingResponse(BaseModel):
    idxs: list[TouchingIdx]
    count: int


# ── /api/string-provenance ───────────────────────────────────────────────────

class StringProvEntry(BaseModel):
    idx: int
    pc: str
    func: Optional[str] = None

class StringProvenanceResponse(BaseModel):
    addr: str
    entries: list[StringProvEntry]
    count: int


# ── /api/decomp-status ───────────────────────────────────────────────────────

class DecompStatusResponse(BaseModel):
    backend: Optional[str] = None
    available: bool
    error: Optional[str] = None


# ── /api/asm-tokens-for-pcs ──────────────────────────────────────────────────

class AsmToken(BaseModel):
    cls: str
    text: str

class AsmTokensForPc(BaseModel):
    pc: str
    tokens: list[AsmToken]

class AsmTokensResponse(BaseModel):
    results: list[AsmTokensForPc]


# ── /api/hlil-for-pc ─────────────────────────────────────────────────────────

class HlilLine(BaseModel):
    pc_lo: str
    pc_hi: str
    text: str
    tokens: list[AsmToken] = []

class HlilResponse(BaseModel):
    pc: str
    lines: list[HlilLine]


# ── /api/bn-cfg-svg-for-pc ──────────────────────────────────────────────────

class BnCfgSvgResponse(BaseModel):
    svg: Optional[str] = None
    error: Optional[str] = None


# ── /api/bn-cfg-for-pc ──────────────────────────────────────────────────────

class BnCfgBlock(BaseModel):
    start: str
    end: str
    label: str

class BnCfgEdge(BaseModel):
    src: str
    dst: str
    kind: str
    style: Optional[str] = None

class BnCfgForPcResponse(BaseModel):
    blocks: list[BnCfgBlock]
    edges: list[BnCfgEdge]
    cur_bb: Optional[str] = None


# ── /api/block-for-pc ────────────────────────────────────────────────────────

class BlockForPcResponse(BaseModel):
    pc: str
    block: Optional[str] = None
    cfg_status: Optional[str] = None
