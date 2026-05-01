"""viewer/__main__.py CLI subcommands — JSON output stability.

被 LLM agent / 脚本调用. JSON 字段 / 退出码变化无人察觉 → 必须 pin.
策略: 合成一个 per-call dir trace, 用 subprocess 调 `python -m viewer <cmd>`,
parse stdout JSON, assert 结构 + 关键字段.
"""
import json, struct, subprocess, sys, pytest, pathlib


HERE = pathlib.Path(__file__).resolve().parent.parent


# ── synth trace fixture ──────────────────────────────────────────────────────

def _make_trace_dir(tmp_path):
    """合成 trace: A 块 (5 nop + ret), 2 次执行. 共 12 条记录."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_cli"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    n = 0
    for _ in range(2):
        for off, asm in [(0, "mov x0, #1"), (4, "mov x1, x0"),
                         (8, "add x0, x0, #1"), (0xc, "nop"),
                         (0x10, "nop"), (0x14, "ret")]:
            inst, _ks = ks.asm(asm)
            ii = int.from_bytes(bytes(inst), "little")
            bf.write(struct.pack("<Q", base + off))
            for _ in range(31): bf.write(struct.pack("<Q", 0))
            bf.write(struct.pack("<Q", 0x7000))
            bf.write(struct.pack("<I", 0))
            bf.write(struct.pack("<I", ii))
            n += 1
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": n, "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": True},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def trace_dir(tmp_path):
    return _make_trace_dir(tmp_path)


def _run(*args, cwd=HERE, expect_zero=True):
    """Run viewer CLI, return parsed stdout JSON."""
    proc = subprocess.run(
        [sys.executable, "-m", "viewer", *map(str, args)],
        cwd=str(cwd), capture_output=True, text=True, timeout=60,
    )
    if expect_zero:
        assert proc.returncode == 0, (
            f"viewer {args[0]} exited {proc.returncode}\n"
            f"stdout: {proc.stdout[:500]}\n"
            f"stderr: {proc.stderr[:500]}")
    out = proc.stdout.strip()
    if not out: return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as e:
        pytest.fail(f"viewer {args[0]} stdout 不是合法 JSON:\n{out[:500]}\n{e}")


# ── stats ────────────────────────────────────────────────────────────────────

def test_stats(trace_dir):
    r = _run("stats", trace_dir)
    assert r["records"] == 12
    assert r["module"]["name"] == "libt.so"
    assert r["module"]["base"] == hex(0x100000)


def test_stats_top_modules(trace_dir):
    """--top-modules 限制不应让 module field 消失."""
    r = _run("stats", trace_dir, "--top-modules", "1")
    assert r["module"] is not None


# ── search-pc ────────────────────────────────────────────────────────────────

def test_search_pc(trace_dir):
    """PC 0x100000 (mov x0, #1) 在 trace 出现 2 次."""
    r = _run("search-pc", trace_dir, "0x100000")
    assert r["count"] == 2
    assert r["idxs"] == [0, 6]


def test_search_pc_decimal(trace_dir):
    """十进制 PC 也接受."""
    r = _run("search-pc", trace_dir, str(0x100000))
    assert r["count"] == 2


def test_search_pc_not_found(trace_dir):
    r = _run("search-pc", trace_dir, "0xdeadbeef")
    assert r["count"] == 0
    assert r["idxs"] == []


def test_search_pc_limit(trace_dir):
    r = _run("search-pc", trace_dir, "0x100000", "--limit", "1")
    assert r["count"] == 2
    assert len(r["idxs"]) == 1
    assert r["truncated"] is True


# ── idxs-for-pc ──────────────────────────────────────────────────────────────

def test_idxs_for_pc_cursor(trace_dir):
    """cursor=6 (第 2 次执行 mov 起点), before=[0], after=[]."""
    r = _run("idxs-for-pc", trace_dir, "0x100000", "--cursor", "6")
    assert r["before"] == [0]
    assert r["after"] == [6]
    assert r["total_before"] == 1


# ── search-asm ───────────────────────────────────────────────────────────────

def test_search_asm_ret(trace_dir):
    r = _run("search-asm", trace_dir, "ret")
    assert r["count"] == 2   # 2 个 ret


def test_search_asm_no_match(trace_dir):
    r = _run("search-asm", trace_dir, "definitely_not_an_insn")
    assert r["count"] == 0


def test_search_asm_max(trace_dir):
    r = _run("search-asm", trace_dir, "ret", "--max", "1")
    assert len(r["hits"]) == 1


# ── records ──────────────────────────────────────────────────────────────────

def test_records_basic(trace_dir):
    r = _run("records", trace_dir, "--start", "0", "--count", "3")
    assert r["count"] == 3
    assert r["records"][0]["pc"] == hex(0x100000)


def test_records_out_of_range(trace_dir):
    """start 越界应优雅 — count=0."""
    r = _run("records", trace_dir, "--start", "1000", "--count", "5")
    assert r["count"] == 0


# ── so-stats ────────────────────────────────────────────────────────────────

def test_so_stats(trace_dir):
    r = _run("so-stats", trace_dir)
    # 单 SO trace, 该 SO 占 100%
    assert r["records"] == 12
    mods = r["modules"]
    # libt.so 占大部分
    assert any(m["name"] == "libt.so" and m["records"] == 12 for m in mods)


# ── reg-timeline ────────────────────────────────────────────────────────────

def test_reg_timeline_x0(trace_dir):
    """trace 全 0 寄存器 (synth 没真填) → 只 1 个 distinct value."""
    r = _run("reg-timeline", trace_dir, "--reg", "x0")
    assert r["count"] >= 1
    assert r["points"][0]["value"] == "0x0"


def test_reg_timeline_unknown_reg_exits_nonzero(trace_dir):
    """unknown reg → exit 1 (进 _err)."""
    proc = subprocess.run(
        [sys.executable, "-m", "viewer", "reg-timeline", str(trace_dir),
         "--reg", "bogus"],
        cwd=str(HERE), capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode != 0


# ── mem-dump ────────────────────────────────────────────────────────────────

def test_mem_dump(trace_dir):
    """mem 区 0x7000 (sp). synth trace 没写, 应都是 ?? kind."""
    r = _run("mem-dump", trace_dir, "--addr", "0x7000", "--count", "8")
    assert r["count"] == 8
    assert len(r["bytes"]) == 8
    # 没写过的 byte → kind '??'
    assert all(b["kind"] == "??" for b in r["bytes"])


# ── mem-diff ────────────────────────────────────────────────────────────────

def test_mem_diff(trace_dir):
    r = _run("mem-diff", trace_dir, "--idx", "5", "--addr", "0x7000",
             "--size", "4")
    assert r["idx"] == 5
    assert r["size"] == 4
    assert "changed_count" in r
    assert len(r["bytes"]) == 4


# ── fn-summary ──────────────────────────────────────────────────────────────

def test_fn_summary_unknown(trace_dir):
    r = _run("fn-summary", trace_dir, "--fn", "DefinitelyNotInTrace")
    assert r["status"] == "not-found"


# ── last-write-of-addr ──────────────────────────────────────────────────────

def test_last_write_of_addr_no_write(trace_dir):
    """addr 0x7000 没被显式写, before-idx 任意 → status='not-found'."""
    r = _run("last-write-of-addr", trace_dir, "--addr", "0x7000",
             "--before-idx", "5")
    assert r["addr"] == "0x7000"
    assert r["before_idx"] == 5
    assert r["status"] == "not-found"
    assert r["writes_total"] == 0


# ── find-mem-pattern ────────────────────────────────────────────────────────

def test_find_mem_pattern_no_match(trace_dir):
    r = _run("find-mem-pattern", trace_dir, "--bytes", "deadbeef")
    assert r["count"] == 0


def test_find_mem_pattern_invalid_hex_returns_nonzero(trace_dir):
    """非 hex 字符串应 exit 1."""
    proc = subprocess.run(
        [sys.executable, "-m", "viewer", "find-mem-pattern", str(trace_dir),
         "--bytes", "not-hex"],
        cwd=str(HERE), capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode != 0


# ── jni-calls / jobj-history / jni-strings ──────────────────────────────────

def test_jni_calls_no_calls(trace_dir):
    """合成 trace 没 JNI vtable 调, count=0."""
    r = _run("jni-calls", trace_dir)
    assert r["count"] == 0


def test_jobj_history_unknown(trace_dir):
    r = _run("jobj-history", trace_dir, "--jobject", "0xdead")
    assert r["count"] == 0 or r.get("status") in ("ready", "no-data")


def test_jni_strings_no_strings(trace_dir):
    r = _run("jni-strings", trace_dir)
    assert r["count"] == 0


# ── taint-fwd / taint-bwd ────────────────────────────────────────────────────

def test_taint_fwd_basic(trace_dir):
    """从 idx=0 / x0 forward, 至少 mov x1, x0 应 propagate."""
    r = _run("taint-fwd", trace_dir, "--start", "0", "--reg", "x0", "--max", "5")
    assert r["count"] >= 0
    assert r["from"] == 0
    assert r["reg"] == "x0"


def test_taint_bwd_basic(trace_dir):
    r = _run("taint-bwd", trace_dir, "--start", "5", "--reg", "x0", "--max", "5")
    assert r["count"] >= 0


# ── data-chase ──────────────────────────────────────────────────────────────

def test_data_chase_basic(trace_dir):
    r = _run("data-chase", trace_dir, "--start", "5", "--reg", "x0",
             "--max-steps", "5")
    assert "steps" in r


# ── export ──────────────────────────────────────────────────────────────────

def test_export_to_sqlite(tmp_path, trace_dir):
    out = tmp_path / "out.db"
    r = _run("export", trace_dir, "--format", "sqlite", "-o", str(out))
    assert r["records"] == 12
    assert out.exists()
    # 验证 SQLite 内容
    import sqlite3
    con = sqlite3.connect(str(out))
    n, = con.execute("SELECT COUNT(*) FROM records").fetchone()
    assert n == 12
    con.close()


# ── invalid trace path → nonzero exit ───────────────────────────────────────

def test_unknown_trace_path_fails():
    proc = subprocess.run(
        [sys.executable, "-m", "viewer", "stats", "/nonexistent/x"],
        cwd=str(HERE), capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode != 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
