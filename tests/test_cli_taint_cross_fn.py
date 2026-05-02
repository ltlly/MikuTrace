"""P1-A CLI: --cross-fn-call adds frame_depth to each row."""
import json, struct, subprocess, sys, pytest, pathlib

HERE = pathlib.Path(__file__).resolve().parent.parent


def _make_trace_dir(tmp_path):
    """6-record trace with bl/ret pair."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_xfn"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    rows = [
        ("mov x0, #1",  {"x0": 1}),
        ("bl #+8",      {"x0": 1, "lr": 0x100008}),
        ("mov x1, x0",  {"x0": 1, "x1": 1}),
        ("ret",         {"x0": 1, "x1": 1}),
        ("mov x2, x0",  {"x0": 1, "x1": 1, "x2": 1}),
    ]
    for i, (asm, regs) in enumerate(rows):
        inst, _ = ks.asm(asm)
        ii = int.from_bytes(bytes(inst), "little")
        bf.write(struct.pack("<Q", base + i * 4))
        for r_idx in range(31):
            name = f"x{r_idx}" if r_idx < 29 else ("fp" if r_idx == 29 else "lr")
            bf.write(struct.pack("<Q", regs.get(name, 0)))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", ii))
    bf.close()
    json.dump({"callIdx": 1, "tid": 100, "records": len(rows), "ms": 1, "retval": "0x0",
               "truncated": False, "last_insn_is_ret": False},
              open(cd / "meta.json", "w"))
    json.dump({"module": {"name": "libt.so", "base": hex(base), "size": 0x10000}},
              open(run / "meta.json", "w"))
    return cd


@pytest.fixture
def trace_dir(tmp_path):
    return _make_trace_dir(tmp_path)


def _run(*args):
    proc = subprocess.run(
        [sys.executable, "-m", "viewer", *map(str, args)],
        cwd=str(HERE), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, f"stderr: {proc.stderr[:500]}"
    return json.loads(proc.stdout.strip())


def test_taint_fwd_cross_fn_call_adds_frame_depth(trace_dir):
    r = _run("taint-fwd", trace_dir, "--start", "0", "--reg", "x0",
             "--max", "20", "--cross-fn-call")
    assert "hits" in r
    for h in r["hits"]:
        assert "frame_depth" in h, f"row missing frame_depth: {h}"
        assert isinstance(h["frame_depth"], int)


def test_taint_bwd_cross_fn_call_adds_frame_depth(trace_dir):
    r = _run("taint-bwd", trace_dir, "--start", "4", "--reg", "x0",
             "--max", "20", "--cross-fn-call")
    assert "chain" in r
    for h in r["chain"]:
        assert "frame_depth" in h


def test_taint_fwd_default_no_frame_depth(trace_dir):
    """Without --cross-fn-call, frame_depth must NOT be in output."""
    r = _run("taint-fwd", trace_dir, "--start", "0", "--reg", "x0", "--max", "20")
    for h in r["hits"]:
        assert "frame_depth" not in h


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
