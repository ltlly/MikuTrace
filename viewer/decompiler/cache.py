"""SQLite-backed decompiler result cache.

Two layers:
  - in-memory dict (per-process, function-level)
  - sqlite (persistent across runs, indexed by (so_sha16, fn_off, backend))

Why SHA-of-SO instead of so_path: 同一个 SO 在 vendor/ 和 example/ 都有副本,
hash 相同避免重复缓存; 升级 SO 自动失效.

Cache value 是 JSON-serialized list/dict, 不放 raw 反编译器对象 (跨进程没用).

Two API tiers:
  - 低层 get/put: 任意 JSON-serializable value, 自由 key
  - 高层 typed wrapper (get_hlil/put_hlil/get_vars/...): dataclass↔dict 自动转,
    省掉 caller 自己 asdict 然后 reconstruct 的样板代码
"""
from __future__ import annotations
import sqlite3, hashlib, json, pathlib, time
from dataclasses import asdict
from typing import Any, Optional

from .backend import HlilLine, Token, VarType


_DEFAULT_DIR = pathlib.Path.home() / ".cache" / "tracemiku" / "decomp"


def _sha16(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


class DecompCache:
    def __init__(self, cache_dir: pathlib.Path | None = None):
        self.dir = cache_dir or _DEFAULT_DIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.dir / "cache.db", check_same_thread=False)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS hlil (
                so_sha     TEXT NOT NULL,
                fn_off     INTEGER NOT NULL,
                backend    TEXT NOT NULL,
                key        TEXT NOT NULL,         -- 'hlil' | 'vars' | 'xrefs'
                payload    BLOB NOT NULL,
                ts         REAL NOT NULL,
                PRIMARY KEY (so_sha, fn_off, backend, key)
            )
        """)
        self.db.commit()
        self._mem: dict[tuple, Any] = {}

    @staticmethod
    def hash_so(so_path: str) -> str:
        return _sha16(so_path)

    # ---- low-level: 任意 JSON 值 ----
    def get(self, so_sha: str, fn_off: int, backend: str, key: str) -> Optional[Any]:
        mk = (so_sha, fn_off, backend, key)
        if mk in self._mem:
            return self._mem[mk]
        row = self.db.execute(
            "SELECT payload FROM hlil WHERE so_sha=? AND fn_off=? AND backend=? AND key=?",
            mk).fetchone()
        if not row: return None
        v = json.loads(row[0])
        self._mem[mk] = v
        return v

    def put(self, so_sha: str, fn_off: int, backend: str, key: str, value: Any) -> None:
        mk = (so_sha, fn_off, backend, key)
        self._mem[mk] = value
        self.db.execute(
            "INSERT OR REPLACE INTO hlil (so_sha, fn_off, backend, key, payload, ts) VALUES (?,?,?,?,?,?)",
            (so_sha, fn_off, backend, key, json.dumps(value, default=_default), time.time()))
        self.db.commit()

    def invalidate_backend(self, backend: str) -> int:
        """Drop all entries for one backend (for testing / version bumps)."""
        c = self.db.execute("DELETE FROM hlil WHERE backend=?", (backend,))
        self.db.commit()
        self._mem = {k: v for k, v in self._mem.items() if k[2] != backend}
        return c.rowcount

    def stats(self) -> dict:
        rows = self.db.execute(
            "SELECT backend, key, COUNT(*) FROM hlil GROUP BY backend, key").fetchall()
        return {f"{b}.{k}": n for b, k, n in rows}

    # ---- typed: dataclass round-trip ----
    def get_hlil(self, so_sha: str, fn_off: int, backend: str) -> Optional[list[HlilLine]]:
        raw = self.get(so_sha, fn_off, backend, "hlil")
        return _decode_hlil(raw) if raw is not None else None

    def put_hlil(self, so_sha: str, fn_off: int, backend: str,
                 lines: list[HlilLine]) -> None:
        self.put(so_sha, fn_off, backend, "hlil",
                 [_encode_hlil(l) for l in lines])

    def get_vars(self, so_sha: str, fn_off: int, backend: str) -> Optional[list[VarType]]:
        raw = self.get(so_sha, fn_off, backend, "vars")
        return [VarType(**d) for d in raw] if raw is not None else None

    def put_vars(self, so_sha: str, fn_off: int, backend: str,
                 vars_: list[VarType]) -> None:
        self.put(so_sha, fn_off, backend, "vars", [asdict(v) for v in vars_])

    def get_xrefs(self, so_sha: str, fn_off: int, backend: str) -> Optional[list[int]]:
        return self.get(so_sha, fn_off, backend, "xrefs")

    def put_xrefs(self, so_sha: str, fn_off: int, backend: str, addrs: list[int]) -> None:
        self.put(so_sha, fn_off, backend, "xrefs", addrs)


# ---- (de)serialize helpers — keep next to DecompCache so contract stays in one file ----

def _encode_hlil(line: HlilLine) -> dict:
    return {
        "text":   line.text,
        "pc_lo":  line.pc_lo,
        "pc_hi":  line.pc_hi,
        "indent": line.indent,
        "tokens": [asdict(tk) for tk in line.tokens] if line.tokens else [],
    }


def _decode_hlil(raw: list[dict]) -> list[HlilLine]:
    out = []
    for d in raw:
        toks = [Token(**td) for td in (d.get("tokens") or [])]
        out.append(HlilLine(
            text=d["text"], pc_lo=d["pc_lo"], pc_hi=d["pc_hi"],
            indent=d.get("indent", 0), tokens=toks,
        ))
    return out


def _default(o):
    """JSON encoder for our dataclasses (used by low-level put())."""
    try:
        return asdict(o)
    except TypeError:
        return repr(o)
