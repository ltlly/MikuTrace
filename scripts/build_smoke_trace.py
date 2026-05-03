"""Build a persistent synth trace for browser smoke test.

Creates /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms/ with the
trace_root_two_callees fixture shape: f_root calls f_alpha then f_beta.
"""
import json
import shutil
import struct
from pathlib import Path

from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

ROOT = Path("/tmp/tracemiku_smoke")
if ROOT.exists():
    shutil.rmtree(ROOT)
ROOT.mkdir()

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

run = ROOT / "run"
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

json.dump({"callIdx": 1, "tid": 100, "records": 9, "ms": 2,
           "retval": "0x0", "truncated": False,
           "last_insn_is_ret": True,
           "known_offsets": {"0x0": "f_root",
                             "0x100": "f_alpha",
                             "0x200": "f_beta"}},
          open(cd / "meta.json", "w"))
json.dump({"pkg": "tst", "so": "libt", "method": "f", "cmd": 1,
           "module": {"name": "libt.so", "base": hex(base),
                      "size": 0x10000},
           "fn_addr": hex(base)},
          open(run / "meta.json", "w"))

print("smoke trace at:", cd)
