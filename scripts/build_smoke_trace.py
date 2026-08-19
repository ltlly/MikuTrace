"""Build a persistent synth trace for browser smoke test and contract tests.

Creates /tmp/tracemiku_smoke/run/calls/call_001_tid100_9r_2ms/ with the
trace_root_two_callees fixture shape: f_root calls f_alpha then f_beta.

Optional --extended adds a second call dir with records shaped for deep
analysis commands (output-backtrace / vm-* / backward-taint): real store
instructions, non-zero registers, JNI NewStringUTF events, and external
writes.
"""

import argparse
import json
import shutil
import struct
from pathlib import Path

ROOT = Path("/tmp/tracemiku_smoke")
if ROOT.exists():
    shutil.rmtree(ROOT)
ROOT.mkdir()

base = 0x100000
rec_pcs = [
    base + 0x000,
    base + 0x004,
    base + 0x100,
    base + 0x104,
    base + 0x008,
    base + 0x200,
    base + 0x204,
    base + 0x208,
    base + 0x00C,
]


def encode_bl(pc: int, target: int) -> int:
    delta = target - pc
    if delta % 4:
        raise ValueError(f"unaligned BL target: pc=0x{pc:x} target=0x{target:x}")
    imm26 = delta // 4
    if not -(1 << 25) <= imm26 < (1 << 25):
        raise ValueError(f"BL target out of range: pc=0x{pc:x} target=0x{target:x}")
    return 0x94000000 | (imm26 & 0x03FF_FFFF)


rec_inst = [
    0xD503201F,  # nop
    encode_bl(base + 0x004, base + 0x100),
    0xD503201F,  # nop
    0xD65F03C0,  # ret
    encode_bl(base + 0x008, base + 0x200),
    0xD503201F,  # nop
    0xD503201F,  # nop
    0xD65F03C0,  # ret
    0xD65F03C0,  # ret
]

run = ROOT / "run"
run.mkdir()
(run / "calls").mkdir()
cd = run / "calls" / "call_001_tid100_9r_2ms"
cd.mkdir()

with open(cd / "trace.bin", "wb") as bf:
    for pc, inst in zip(rec_pcs, rec_inst):
        bf.write(struct.pack("<Q", pc))
        bf.write(struct.pack("<Q", 0) * 31)
        bf.write(struct.pack("<Q", 0x7000))
        bf.write(struct.pack("<I", 0))
        bf.write(struct.pack("<I", inst))

with open(cd / "meta.json", "w") as mf:
    json.dump(
        {
            "callIdx": 1,
            "tid": 100,
            "records": 9,
            "ms": 2,
            "retval": "0x0",
            "truncated": False,
            "last_insn_is_ret": True,
            "known_offsets": {"0x0": "f_root", "0x100": "f_alpha", "0x200": "f_beta"},
        },
        mf,
    )
with open(run / "meta.json", "w") as mf:
    json.dump(
        {
            "pkg": "tst",
            "so": "libt",
            "method": "f",
            "cmd": 1,
            "module": {"name": "libt.so", "base": hex(base), "size": 0x10000},
            "fn_addr": hex(base),
        },
        mf,
    )

print("smoke trace at:", cd)


def build_extended(run_dir: Path, base_addr: int) -> Path:
    """Build a deep-analysis call dir: stores, JNI output, external writes.

    Layout: 12 records, f_root stores an 8-byte value at [x1] then calls
    f_builder which stores per-byte chunks of an output string, and a
    NewStringUTF JNI hook reports the final output bytes.
    """
    ed = run_dir / "calls" / "call_002_tid200_12r_4ms"
    ed.mkdir()
    out_addr = 0x2000

    # nop, str x0,[x1] (write 8B), bl f_builder, nop,
    # str w0,[x1,#8] (write 4B), bl f_builder2, nop,
    # strb w0,[x1,#12], nop, ret, nop, ret
    insts = [
        0xD503201F,  # 0: nop
        0xF9000020,  # 1: str x0, [x1]
        encode_bl(base_addr + 0x008, base_addr + 0x020),
        0xD503201F,  # 3: nop
        0xB9000820,  # 4: str w0, [x1, #8]
        encode_bl(base_addr + 0x010, base_addr + 0x030),
        0xD503201F,  # 6: nop
        0x39000020,  # 7: strb w0, [x1]
        0xD503201F,  # 8: nop
        0xD65F03C0,  # 9: ret
        0xD503201F,  # 10: nop
        0xD65F03C0,  # 11: ret
    ]
    pcs = [
        base_addr + off
        for off in (0x0, 0x4, 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x28, 0x2C)
    ]
    with open(ed / "trace.bin", "wb") as bf:
        for idx, (pc, inst) in enumerate(zip(pcs, insts)):
            regs = [0] * 31
            if idx == 1:  # str x0,[x1]: value in x0, base in x1
                regs[0] = 0x68676F2E6F727061  # "apro.ogh" 8 bytes LE
                regs[1] = out_addr
            elif idx == 4:  # str w0,[x1,#8]
                regs[0] = 0x65756C6176  # "value" 4B
                regs[1] = out_addr
            elif idx == 7:  # strb w0,[x1]
                regs[0] = 0x21  # '!'
                regs[1] = out_addr
            bf.write(struct.pack("<Q", pc))
            bf.write(b"".join(struct.pack("<Q", r) for r in regs))
            bf.write(struct.pack("<Q", 0x8000))
            bf.write(struct.pack("<I", 0))
            bf.write(struct.pack("<I", inst))

    # JNI NewStringUTF pairs: f_builder produced key/value strings.
    # jni_output_string_pairs_on matches pairs of NewStringUTF events:
    # pair[0] is the key, pair[1] is the value.
    jni = [
        {"trace_idx": 3, "id": "GetStringUTFChars", "ret": "apro.oghvalue!"},
        {"trace_idx": 6, "id": "NewStringUTF", "args": {"bytes": "apro.oghvalue!"}},
        {"trace_idx": 10, "id": "NewStringUTF", "args": {"bytes": "apro.oghvalue!"}},
    ]
    with open(ed / "jni_hooks.jsonl", "w") as jf:
        jf.write("".join(json.dumps(ev) + "\n" for ev in jni))

    # external writes: byte-level x-layer writes at idx 5 and 8.
    ext = []
    for i, b in enumerate(b"apro.oghvalue!"):
        ext.append(struct.pack("<QQB", 5 + (i % 3), out_addr + i, b))
    with open(ed / "external_writes.bin", "wb") as xf:
        xf.write(b"".join(ext))

    with open(ed / "meta.json", "w") as mf:
        json.dump(
            {
                "callIdx": 2,
                "tid": 200,
                "records": 12,
                "ms": 4,
                "retval": "0x0",
                "truncated": False,
                "last_insn_is_ret": True,
                "known_offsets": {
                    "0x0": "f_root",
                    "0x20": "f_builder",
                    "0x30": "f_builder2",
                },
            },
            mf,
        )
    return ed


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--extended", action="store_true", help="also build the deep-analysis call dir"
    )
    args = ap.parse_args()
    if args.extended:
        ext = build_extended(run, base)
        print("extended deep trace at:", ext)


if __name__ == "__main__":
    main()
