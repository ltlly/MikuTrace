"""Per-call trace 目录布局 + cmd_info / cmd_list 输出契约."""
import json, struct, subprocess, tempfile, os, pathlib, shutil
import pytest

HERE = pathlib.Path(__file__).resolve().parent.parent
TRACEMIKU = HERE / "tracemiku"


def _write_record(buf, pc, inst, regs=None):
    regs = regs or [0]*31
    buf.write(struct.pack("<Q", pc))
    for v in regs: buf.write(struct.pack("<Q", v))
    buf.write(struct.pack("<Q", 0))   # sp
    buf.write(struct.pack("<I", 0))   # nzcv
    buf.write(struct.pack("<I", inst))


def _make_run(tmp, calls):
    """calls: list of dict(callIdx, tid, records, ms, retval, truncated, last_inst).
    last_inst defaults to 'ret' (0xd65f03c0). PCs are dummy 0x40000+i*4."""
    run = pathlib.Path(tmp)/"run1"
    run.mkdir()
    (run/"calls").mkdir()
    for c in calls:
        n = c["records"]
        last_inst = c.get("last_inst", 0xd65f03c0)   # ret
        d = run/"calls"/f"call_{c['callIdx']:03d}_tid{c['tid']}_{n}r_{c['ms']}ms"
        d.mkdir()
        with open(d/"trace.bin","wb") as bf:
            for i in range(n-1):
                _write_record(bf, 0x40000 + i*4, 0xd503201f)  # nop
            if n > 0:
                _write_record(bf, 0x40000 + (n-1)*4, last_inst)
        meta = {
            "callIdx": c["callIdx"], "tid": c["tid"],
            "records": n, "ms": c["ms"], "retval": c.get("retval","0x0"),
            "truncated": c.get("truncated", False),
            "last_insn_is_ret": (last_inst == 0xd65f03c0),
        }
        json.dump(meta, open(d/"meta.json","w"))
    json.dump({"pkg":"tst","so":"libt","method":"f","cmd":1,
              "calls":[]}, open(run/"meta.json","w"))
    return run


@pytest.fixture
def synth_run(tmp_path):
    return _make_run(tmp_path, [
        {"callIdx": 1, "tid": 100, "records": 4675,    "ms": 98},
        {"callIdx": 2, "tid": 100, "records": 2066291, "ms": 50342},
        {"callIdx": 3, "tid": 100, "records": 4675,    "ms": 100},
    ])


def test_list_run_shows_calls_desc(synth_run):
    r = subprocess.run([str(TRACEMIKU), "list", str(synth_run), "--json"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    rows = json.loads(r.stdout)
    assert len(rows) == 3
    # 降序: 最长的 cold-path call 在最前
    assert rows[0]["records"] == 2066291
    assert rows[0]["callIdx"] == 2


def test_info_call_dir_complete(synth_run):
    longest = sorted(synth_run.glob("calls/call_*"),
                     key=lambda p: -int(p.name.split("_")[3].rstrip("r")))[0]
    r = subprocess.run([str(TRACEMIKU), "info", str(longest), "--json"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["records"] == 2066291
    assert out["truncated"] is False
    assert out["last_insn_is_ret"] is True
    assert out["is_complete"] is True


def test_info_call_dir_truncated(tmp_path):
    """构造一个 truncated call (最后一条不是 ret)"""
    r = _make_run(tmp_path, [
        {"callIdx": 1, "tid": 100, "records": 1000, "ms": 50,
         "truncated": True, "last_inst": 0xd503201f},  # nop
    ])
    cd = next(r.glob("calls/call_*"))
    proc = subprocess.run([str(TRACEMIKU), "info", str(cd), "--json"],
                          capture_output=True, text=True)
    out = json.loads(proc.stdout)
    assert out["truncated"] is True
    assert out["last_insn_is_ret"] is False
    assert out["is_complete"] is False


def test_info_run_aggregates(synth_run):
    r = subprocess.run([str(TRACEMIKU), "info", str(synth_run), "--json"],
                       capture_output=True, text=True)
    out = json.loads(r.stdout)
    assert out["calls_count"] == 3
    assert out["max_records"] == 2066291
    assert out["total_records"] == 4675 + 2066291 + 4675
