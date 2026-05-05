"""Build a persistent synth trace for browser smoke test.

Creates /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms/ with the
trace_root_two_callees fixture shape: f_root calls f_alpha then f_beta.
"""
import json
import shutil
import struct
from pathlib import Path

ROOT = Path("/tmp/tracemiku_smoke")
if ROOT.exists():
    shutil.rmtree(ROOT)
ROOT.mkdir()

base = 0x100000
rec_pcs = [base + 0x000, base + 0x004,
           base + 0x100, base + 0x104,
           base + 0x008,
           base + 0x200, base + 0x204, base + 0x208,
           base + 0x00c]


def encode_bl(pc: int, target: int) -> int:
    delta = target - pc
    if delta % 4:
        raise ValueError(f"unaligned BL target: pc=0x{pc:x} target=0x{target:x}")
    imm26 = delta // 4
    if not -(1 << 25) <= imm26 < (1 << 25):
        raise ValueError(f"BL target out of range: pc=0x{pc:x} target=0x{target:x}")
    return 0x94000000 | (imm26 & 0x03ff_ffff)


rec_inst = [
    0xd503201f,                         # nop
    encode_bl(base + 0x004, base + 0x100),
    0xd503201f,                         # nop
    0xd65f03c0,                         # ret
    encode_bl(base + 0x008, base + 0x200),
    0xd503201f,                         # nop
    0xd503201f,                         # nop
    0xd65f03c0,                         # ret
    0xd65f03c0,                         # ret
]

run = ROOT / "run"
run.mkdir()
(run / "calls").mkdir()
cd = run / "calls" / "call_001_tid100_9r_2ms"
cd.mkdir()

with open(cd / "trace.bin", "wb") as bf:
    for pc, inst in zip(rec_pcs, rec_inst):
        bf.write(struct.pack("<Q", pc))
        for r_idx in range(31):
            bf.write(struct.pack("<Q", 0))
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", inst))

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
