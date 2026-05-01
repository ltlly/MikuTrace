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
_REG_INDEX = {name: i for i, name in enumerate(REG_NAMES)}

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
        return self.regs[_REG_INDEX[name]]


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
    modules: list[Module] = field(default_factory=list)
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
        # 0 长度 trace: mmap 拒绝, 用 b'' 兜底, n=0. 测试 / 极端边界用.
        sz = self.path.stat().st_size
        if sz == 0:
            self._mm = b""
        else:
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
        self.n = len(self._mm) // REC_SIZE

    def close(self):
        try: self._mm.close()
        except Exception: pass
        try: self._fh.close()
        except Exception: pass

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

    def pc_array(self):
        """numpy uint64 view of all PCs (zero-copy stride view of mmap).
        用于 vectorized 扫描 — np.nonzero(pc_array() == target) 比 Python
        loop 快 60x+ (300ms → 5ms on 2.5M trace)."""
        if not hasattr(self, "_pc_arr"):
            import numpy as np
            # record 272 bytes = 34 u64. PC 在 [0]. Stride view 直接拿 PC 列.
            full = np.frombuffer(self._mm, dtype=np.uint64,
                                 count=self.n * (REC_SIZE // 8))
            self._pc_arr = full[::REC_SIZE // 8]   # 视图, 无拷贝
        return self._pc_arr


def addr_of(rec: Record, mem_op_tuple) -> int:
    """Compute effective address for a memory operand from a record.

    mem_op_tuple = (base, idx_reg, disp, sz, is_w, src_reg).
    """
    base, idx_reg, disp, _sz, _is_w, _src = mem_op_tuple
    bv = rec.reg(base) if base in ALL_REGS else 0
    iv = rec.reg(idx_reg) if (idx_reg and idx_reg in ALL_REGS) else 0
    return (bv + iv + disp) & 0xffffffffffffffff


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
                    _populate_meta(meta, json.loads(mp.read_text()))
                    try: meta.pid = int(stem_parts[0])
                    except Exception: pass
                    break
    else:
        # per-call directory: trace.bin + meta.json (call-level), parent meta.json (run-level)
        if (p / "trace.bin").exists():
            bin_path = p / "trace.bin"
            cm = p / "meta.json"
            if cm.exists():
                _populate_meta(meta, json.loads(cm.read_text()))
            # merge run-level meta from parent of parent (run/calls/<call>/ → run/)
            run_dir = p.parent.parent if p.parent.name == "calls" else p.parent
            tm = run_dir / "meta.json"
            if tm.exists():
                top = json.loads(tm.read_text())
                if "method" in top: meta.method = top["method"] or meta.method
                if "cmd" in top: meta.cmd = top["cmd"] if meta.cmd is None else meta.cmd
                if "module" in top and not meta.module:
                    m = top["module"]
                    meta.module = Module(m["name"],
                                         int(m["base"], 16) if isinstance(m["base"], str) else m["base"],
                                         m["size"])
                if "modules" in top and not meta.modules:
                    for m in top["modules"]:
                        base = int(m["base"], 16) if isinstance(m["base"], str) else m["base"]
                        meta.modules.append(Module(m["name"], base, m["size"]))
                if "fn_addr" in top and not meta.fn_addr:
                    meta.fn_addr = int(top["fn_addr"], 16) if isinstance(top["fn_addr"], str) else top["fn_addr"]
            # 兜底: 若仅 meta.module (legacy) 而未填 modules, 把单数加进列表
            if meta.module and not meta.modules:
                meta.modules.append(meta.module)
            return Trace(bin_path, meta)

        # legacy: trace_<pid>_<tid>.bin layout
        candidates = sorted(p.glob("trace_*.bin"),
                            key=lambda x: x.stat().st_size, reverse=True)
        if not candidates:
            raise FileNotFoundError(f"no trace.bin in {p}")
        bin_path = candidates[0]
        stem_parts = bin_path.stem.split("_")[1:]
        try: meta.pid = int(stem_parts[0])
        except Exception: pass
        for variant in ("_".join(stem_parts), stem_parts[0] if stem_parts else ""):
            mp = p / f"meta_{variant}.json"
            if mp.exists():
                _populate_meta(meta, json.loads(mp.read_text())); break
        tm = p / "meta.json"
        if tm.exists():
            top = json.loads(tm.read_text())
            if "method" in top: meta.method = top["method"]
            if "cmd" in top: meta.cmd = top["cmd"]
            if "module" in top and not meta.module:
                m = top["module"]
                meta.module = Module(m["name"],
                                     int(m["base"], 16) if isinstance(m["base"], str) else m["base"],
                                     m["size"])
            if "modules" in top and not meta.modules:
                for m in top["modules"]:
                    base = int(m["base"], 16) if isinstance(m["base"], str) else m["base"]
                    meta.modules.append(Module(m["name"], base, m["size"]))
            if "fn_addr" in top and not meta.fn_addr:
                meta.fn_addr = int(top["fn_addr"], 16) if isinstance(top["fn_addr"], str) else top["fn_addr"]
        # 兜底: legacy trace 仅 meta.module 时, 同步进 modules 列表
        if meta.module and not meta.modules:
            meta.modules.append(meta.module)
    return Trace(bin_path, meta)


def _populate_meta(meta: TraceMeta, raw: dict):
    meta.raw = raw
    if "module" in raw:
        m = raw["module"]
        meta.module = Module(m["name"], int(m["base"], 16) if isinstance(m["base"], str) else m["base"], m["size"])
    if "modules" in raw:
        for m in raw["modules"]:
            base = int(m["base"], 16) if isinstance(m["base"], str) else m["base"]
            meta.modules.append(Module(m["name"], base, m["size"]))
    # Backward compat: if only "module" (singular) exists, add it to modules list
    if meta.module and not meta.modules:
        meta.modules.append(meta.module)
    if "fn_addr" in raw:
        meta.fn_addr = int(raw["fn_addr"], 16) if isinstance(raw["fn_addr"], str) else raw["fn_addr"]
    if "trace_begin" in raw: meta.trace_begin = raw["trace_begin"]
    if "trace_end" in raw: meta.trace_end = raw["trace_end"]
    if "hello" in raw and isinstance(raw["hello"], dict):
        if not meta.method:
            meta.method = raw["hello"].get("method", "")
        if meta.cmd is None:
            meta.cmd = raw["hello"].get("cmdValue")
