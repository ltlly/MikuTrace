"""Shared pytest fixtures for traceMiku tests."""
import json
import struct
from pathlib import Path

import pytest


@pytest.fixture
def trace_root_two_callees(tmp_path):
    """Synthetic ARM64 trace: f_root calls f_alpha then f_beta.

    9 records covering all 3 fns. Reused across FunctionIndex / dec / LLIL
    equivalence tests. SymbolMap is auto-built from the per-call meta.json's
    known_offsets table (see viewer.symbols.auto_known_offsets / build_from_trace).
    """
    from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    base = 0x100000
    rec_pcs = [base + 0x000, base + 0x004,
               base + 0x100, base + 0x104,
               base + 0x008,
               base + 0x200, base + 0x204, base + 0x208,
               base + 0x00c]
    rec_asm = ["nop", f"bl 0x{base + 0x100:x}",
               "nop", "ret",
               f"bl 0x{base + 0x200:x}",
               "nop", "nop", "ret",
               "ret"]
    run = tmp_path / "run_two_callees"
    run.mkdir()
    (run / "calls").mkdir()
    cd = run / "calls" / "call_001_tid100_9r_2ms"
    cd.mkdir()
    with open(cd / "trace.bin", "wb") as bf:
        for pc, asm in zip(rec_pcs, rec_asm):
            inst, _ = ks.asm(asm, addr=pc)
            bf.write(struct.pack("<Q", pc))
            for r_idx in range(31):
                bf.write(struct.pack("<Q", 0))
            bf.write(struct.pack("<Q", 0x7000))
            bf.write(struct.pack("<I", 0))
            bf.write(struct.pack("<I", int.from_bytes(bytes(inst), "little")))
    # known_offsets must be in per-call meta.json so auto_known_offsets picks it
    # up from trace.meta.raw (the run-level meta.json is merged but not stored
    # in meta.raw).  Keys are relative offsets from module base (not absolute).
    json.dump({"callIdx": 1, "tid": 100, "records": 9, "ms": 2,
               "retval": "0x0", "truncated": False,
               "last_insn_is_ret": True,
               "known_offsets": {"0x0": "f_root",
                                 "0x100": "f_alpha",
                                 "0x200": "f_beta"}},
              open(cd / "meta.json", "w"))
    json.dump({"pkg": "tst", "so": "libt", "method": "f_root", "cmd": 1,
               "module": {"name": "libt.so", "base": hex(base),
                          "size": 0x10000},
               "fn_addr": hex(base)},
              open(run / "meta.json", "w"))
    return cd
