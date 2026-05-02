"""P0-5 CLI: taint-fwd/taint-bwd default --max=5000, stopped_at_max field,
--summary-by-fn aggregation."""
import json, struct, subprocess, sys, pytest, pathlib

HERE = pathlib.Path(__file__).resolve().parent.parent


def _make_long_chain_trace_dir(tmp_path, n_records=20):
    """Build trace dir with a long propagation chain x0↔x1."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_cli"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    seq = ["mov x0, #1"]
    for i in range(1, n_records):
        seq.append("mov x1, x0" if i % 2 == 1 else "mov x0, x1")
    for i, asm in enumerate(seq):
        inst, _ = ks.asm(asm)
        ii = int.from_bytes(bytes(inst), "little")
        bf.write(struct.pack("<Q", base + i * 4))
        for _ in range(31): bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", ii))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": n_records, "ms": 1,
               "retval": "0x0", "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def long_trace(tmp_path):
    return _make_long_chain_trace_dir(tmp_path, n_records=20)


def _run(*args, expect_zero=True):
    proc = subprocess.run(
        [sys.executable, "-m", "viewer", *map(str, args)],
        cwd=str(HERE), capture_output=True, text=True, timeout=60,
    )
    if expect_zero:
        assert proc.returncode == 0, f"stderr: {proc.stderr[:500]}"
    out = proc.stdout.strip()
    return json.loads(out) if out else None


def test_taint_bwd_emits_stopped_at_max_when_capped(long_trace):
    """20-step chain, --max 3 → stopped_at_max=True."""
    r = _run("taint-bwd", long_trace, "--start", "19", "--reg", "x0", "--max", "3")
    assert "stopped_at_max" in r, f"output missing stopped_at_max field: {r}"
    assert r["stopped_at_max"] is True


def test_taint_bwd_emits_stopped_at_max_false_when_natural(long_trace):
    """20-step chain, --max 5000 → stopped_at_max=False (chain ends naturally)."""
    r = _run("taint-bwd", long_trace, "--start", "19", "--reg", "x0", "--max", "5000")
    assert r["stopped_at_max"] is False


def test_taint_fwd_emits_stopped_at_max_when_capped(long_trace):
    r = _run("taint-fwd", long_trace, "--start", "0", "--reg", "x0", "--max", "3")
    assert r["stopped_at_max"] is True


def test_taint_bwd_default_max_is_5000(long_trace):
    """When --max not passed, default should be 5000 (was 500)."""
    proc = subprocess.run(
        [sys.executable, "-m", "viewer", "taint-bwd", "--help"],
        cwd=str(HERE), capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0
    assert "5000" in proc.stdout, f"--help should show default 5000: {proc.stdout}"


def test_taint_fwd_default_max_is_5000(long_trace):
    proc = subprocess.run(
        [sys.executable, "-m", "viewer", "taint-fwd", "--help"],
        cwd=str(HERE), capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0
    assert "5000" in proc.stdout


def test_taint_bwd_summary_by_fn(long_trace):
    """--summary-by-fn aggregates rows by function name."""
    r = _run("taint-bwd", long_trace, "--start", "19", "--reg", "x0",
             "--max", "100", "--summary-by-fn")
    assert "summary_by_fn" in r, f"missing summary_by_fn: {r}"
    # summary_by_fn is a list of {func, count, first_idx, last_idx}
    sf = r["summary_by_fn"]
    assert isinstance(sf, list)
    if sf:
        entry = sf[0]
        assert "count" in entry
        assert "func" in entry
        assert "first_idx" in entry
        assert "last_idx" in entry


def test_taint_fwd_summary_by_fn(long_trace):
    r = _run("taint-fwd", long_trace, "--start", "0", "--reg", "x0",
             "--max", "100", "--summary-by-fn")
    assert "summary_by_fn" in r


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
