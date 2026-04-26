"""Trace loader + indexer for traceMiku binary trace files.

Record format (272 bytes, little-endian):
    0x000  u64  pc
    0x008  u64  x[31]      (x0..x28, fp=x29, lr=x30)
    0x100  u64  sp
    0x108  u32  nzcv       (reserved)
    0x10c  u32  inst       (raw 4-byte ARM64 machine code)
"""
from __future__ import annotations
import struct, json, pathlib, mmap
from dataclasses import dataclass, field
from typing import Optional

REC_SIZE = 272
REG_NAMES = [f"x{i}" for i in range(29)] + ["fp", "lr"]   # 31 entries
ALL_REGS = REG_NAMES + ["sp", "pc"]

# Pre-compiled struct for one record's pc + x[31] + sp + nzcv + inst
# = 1 u64 (pc) + 31 u64 (regs) + 1 u64 (sp) + 1 u32 + 1 u32
_REC_FMT = "<33QII"


@dataclass
class Record:
    idx: int
    pc: int
    regs: tuple   # 31 values: x0..x28, fp, lr
    sp: int
    nzcv: int
    inst: int

    def reg(self, name: str) -> int:
        if name == "pc": return self.pc
        if name == "sp": return self.sp
        if name == "nzcv": return self.nzcv
        i = REG_NAMES.index(name)
        return self.regs[i]


@dataclass
class Module:
    name: str
    base: int
    size: int
    end: int = field(init=False)
    def __post_init__(self): self.end = self.base + self.size


@dataclass
class TraceMeta:
    pid: Optional[int] = None
    method: str = ""
    cmd: Optional[int] = None
    module: Optional[Module] = None
    fn_addr: Optional[int] = None
    trace_begin: dict = field(default_factory=dict)
    trace_end: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


class Trace:
    """Memory-mapped trace with random access + lazy indexing."""

    def __init__(self, bin_path: str | pathlib.Path, meta: TraceMeta):
        self.path = pathlib.Path(bin_path)
        self.meta = meta
        self._fh = open(self.path, "rb")
        self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        self.n = len(self._mm) // REC_SIZE

    def close(self):
        try: self._mm.close()
        except: pass
        try: self._fh.close()
        except: pass

    def __len__(self): return self.n

    def record(self, i: int) -> Record:
        if i < 0 or i >= self.n: raise IndexError(i)
        off = i * REC_SIZE
        unp = struct.unpack_from(_REC_FMT, self._mm, off)
        pc = unp[0]
        regs = unp[1:32]      # 31 values
        sp = unp[32]
        nzcv, inst = unp[33], unp[34]
        return Record(i, pc, regs, sp, nzcv, inst)

    def pc(self, i: int) -> int:
        return struct.unpack_from("<Q", self._mm, i * REC_SIZE)[0]

    def inst(self, i: int) -> int:
        return struct.unpack_from("<I", self._mm, i * REC_SIZE + 268)[0]


def load(trace_dir_or_file: str | pathlib.Path) -> Trace:
    """Load a trace from either a per-PID bin file or a session directory."""
    p = pathlib.Path(trace_dir_or_file)
    meta = TraceMeta()
    if p.is_file():
        bin_path = p
        # 兼容 meta_{pid}.json 和 meta_{pid}_{tid}.json 两种命名
        stem_parts = p.stem.split("_")[1:]   # 去掉 'trace' 前缀
        if stem_parts:
            for variant in ("_".join(stem_parts), stem_parts[0]):
                mp = p.parent / f"meta_{variant}.json"
                if mp.exists():
                    _populate_meta(meta, json.load(open(mp)))
                    try: meta.pid = int(stem_parts[0])
                    except: pass
                    break
    else:
        # directory — pick the largest trace_<pid>.bin or fallback trace.bin
        candidates = sorted(p.glob("trace_*.bin"),
                            key=lambda x: x.stat().st_size, reverse=True)
        if (p / "trace.bin").exists() and not candidates:
            bin_path = p / "trace.bin"
        else:
            if not candidates:
                raise FileNotFoundError(f"no trace.bin in {p}")
            bin_path = candidates[0]
            stem_parts = bin_path.stem.split("_")[1:]
            try: meta.pid = int(stem_parts[0])
            except: pass
            for variant in ("_".join(stem_parts), stem_parts[0] if stem_parts else ""):
                mp = p / f"meta_{variant}.json"
                if mp.exists():
                    _populate_meta(meta, json.load(open(mp))); break
        # also merge top-level meta.json
        tm = p / "meta.json"
        if tm.exists():
            top = json.load(open(tm))
            if "method" in top: meta.method = top["method"]
            if "cmd" in top: meta.cmd = top["cmd"]
    return Trace(bin_path, meta)


def _populate_meta(meta: TraceMeta, raw: dict):
    meta.raw = raw
    if "module" in raw:
        m = raw["module"]
        meta.module = Module(m["name"], int(m["base"], 16) if isinstance(m["base"], str) else m["base"], m["size"])
    if "fn_addr" in raw:
        meta.fn_addr = int(raw["fn_addr"], 16) if isinstance(raw["fn_addr"], str) else raw["fn_addr"]
    if "trace_begin" in raw: meta.trace_begin = raw["trace_begin"]
    if "trace_end" in raw: meta.trace_end = raw["trace_end"]
    if "hello" in raw and isinstance(raw["hello"], dict):
        if not meta.method:
            meta.method = raw["hello"].get("method", "")
        if meta.cmd is None:
            meta.cmd = raw["hello"].get("cmdValue")
