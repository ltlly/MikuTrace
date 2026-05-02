"""P0-1: /api/call-tree exposes nested call tree from bl/ret pairs."""
import json, struct, pytest
from fastapi.testclient import TestClient


def _make_trace_with_call(tmp_path):
    """6-record trace: insn, bl, insn, ret, insn (one nested call)."""
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    run = tmp_path / "run1"; run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_tree"; cd.mkdir()
    bf = open(cd / "trace.bin", "wb")
    rows = [
        ("nop",     {}),
        ("bl #+8",  {"lr": 0x100008}),
        ("nop",     {}),
        ("ret",     {}),
        ("nop",     {}),
    ]
    for i, (asm, regs) in enumerate(rows):
        inst, _ = ks.asm(asm)
        ii = int.from_bytes(bytes(inst), "little")
        bf.write(struct.pack("<Q", base + i * 4))
        for r_idx in range(31):
            name = f"x{r_idx}" if r_idx < 29 else ("fp" if r_idx == 29 else "lr")
            v = regs.get(name, 0)
            bf.write(struct.pack("<Q", v))
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
def client(tmp_path):
    cd = _make_trace_with_call(tmp_path)
    from webui.server import make_app
    return TestClient(make_app(cd))


def test_call_tree_endpoint_returns_root(client):
    r = client.get("/api/call-tree").json()
    assert "tree" in r
    assert "enter_idx" in r["tree"]
    assert "exit_idx" in r["tree"]
    assert "children" in r["tree"]


def test_call_tree_finds_nested_call(client):
    """bl at idx 1, ret at idx 3 → tree.children has 1 frame [1, 3]."""
    r = client.get("/api/call-tree").json()
    children = r["tree"]["children"]
    assert len(children) == 1
    assert children[0]["enter_idx"] == 1
    assert children[0]["exit_idx"] == 3


def test_call_tree_max_depth_param(client):
    """?max_depth=1 should cap nesting."""
    r = client.get("/api/call-tree?max_depth=1").json()
    # Root + 1 level under = 1 edge
    def edges(n):
        if not n["children"]: return 0
        return 1 + max(edges(c) for c in n["children"])
    assert edges(r["tree"]) <= 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
