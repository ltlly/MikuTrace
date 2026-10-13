#!/usr/bin/env python3
"""在 QEMU + GumJS 中执行生产 agent，校验真实 ARM64 指令、寄存器和 CLI 结果。"""

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(args, *, cwd=ROOT, timeout=60):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"命令失败 ({result.returncode}): {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def elf_instruction(image, address):
    """用 ELF PT_LOAD 定位原始 opcode，不能拿已被 hook 的内存作比较基准。"""
    assert image[:6] == b"\x7fELF\x02\x01", "需要 ELF64 little endian"
    phoff = struct.unpack_from("<Q", image, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", image, 54)
    for index in range(phnum):
        kind, _, offset, virtual, _, size, _, _ = struct.unpack_from("<IIQQQQQQ", image, phoff + index * phsize)
        if kind == 1 and virtual <= address and address + 4 <= virtual + size:
            return struct.unpack_from("<I", image, offset + address - virtual)[0]
    raise AssertionError(f"记录地址不在源 ELF 内: {address:#x}")


def recursive_path(depth):
    if depth == 0:
        return [(offset, 0) for offset in [0, 4, 8, 24, 28]]
    return ([(offset, depth) for offset in [0, 4, 8, 12]] + [(16, depth - 1)]
            + recursive_path(depth - 1) + [(20, depth - 1), (24, depth), (28, depth)])


CASES = [
    # 名称、输入、返回值、调用次数、按执行顺序的 (函数内偏移, x0)、预期拒绝原因。
    ("entry", 42, "49", 3, list(zip(range(0, 28, 4), [42, 42, 42, 43, 45, 49, 49])), None),
    ("short", 42, "43", 1, [(0, 42), (4, 43)], None),
    ("adr", 42, "55", 1, [(0, 42), (4, 42), (8, 42), (12, 55)], None),
    ("literal", 42, "55", 1, [(0, 42), (4, 42), (8, 55)], None),
    ("branch", 42, "43", 1, [(0, 42), (8, 42), (12, 43)], None),
    ("conditional", 0, "0", 1, [(0, 0), (8, 0)], None),
    ("conditional", 42, "43", 1, [(0, 42), (4, 42), (8, 43)], None),
    ("recursive", 4, "4", 1, recursive_path(4), None),
    ("ip_first", 42, "5654", 1, [(0, 42), (4, 0x1616)], None),
    ("ip_late", 42, "5654", 1, [(i, 42) for i in range(0, 20, 4)] + [(20, 0x1616)], None),
    ("unsafe_ips", 42, "43", 1, [(0, 42), (4, 42), (8, 42), (12, 43)], None),
    ("tail", 42, "42", 1, None, None),
    ("atomic", 42, "1", 1, None, None),
    ("atomic_entry", 42, "42", 1, None, "exclusive instruction"),
    ("lr_sensitive", 42, "nonzero", 1, None, "caller-address-sensitive"),
]


def verify_call(spool, manifest_path, image, expected, incomplete):
    manifest = json.loads(manifest_path.read_text())
    assert manifest["state"] == "SEALED"
    meta = manifest["meta"]
    files = {item["name"]: item for item in manifest["files"]}
    trace = Path(files["trace.bin"]["device_path"]).read_bytes()
    simd = Path(files["simd_trace.bin"]["device_path"]).read_bytes()
    records = list(struct.iter_unpack("<33QII", trace))
    assert records and len(records) == meta["records"] == meta["device_records"]
    assert len(simd) == len(records) * 520
    base, entry = int(meta["module"]["base"], 16), int(meta["fn_addr"], 16)
    for index, record in enumerate(records):
        assert record[34] == elf_instruction(image, record[0] - base), (index, record)
        assert struct.unpack_from("<Q", simd, index * 520)[0] == index
        assert simd[index * 520 + 8:index * 520 + 24] == b"\x5a" * 16, ("v0", index)
    assert records[0][0] == entry
    assert records[0][17:19] == (0x1616, 0x1717), "入口不能污染 x16/x17"
    if expected is not None:
        assert [(rec[0] - entry, rec[1]) for rec in records] == expected
    scope = meta["capture_scope"]
    assert scope["entry_complete"] and scope["return_observed"]
    assert scope["first_pc"] == scope["expected_entry_pc"] == meta["fn_addr"]
    assert bool(scope["coverage_gaps"]) == incomplete
    assert meta["truncated"] == incomplete and meta["dropped"] == 0

    # 按 manifest 原样形成调用目录；core 从真实文件独立计算完整性。
    call = spool / "calls" / f"call_{meta['callIdx']:03d}_tid{meta['tid']}_{len(records)}r_{meta['ms']}ms"
    call.mkdir(parents=True)
    receipts = []
    for name, artifact in files.items():
        source = Path(artifact["device_path"])
        assert source.stat().st_size == artifact["bytes"]
        shutil.copyfile(source, call / name)
        receipts.append({"name": name, "bytes": artifact["bytes"],
                         "sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
    meta.update(transfer_state="VERIFIED", required_artifacts=list(files), artifact_checksums=receipts)
    (call / "meta.json").write_text(json.dumps(meta))
    info = json.loads(run([str(ROOT / "tracemiku"), "info", str(call)]))
    assert info["records"] == len(records) and info["is_complete"] == (not incomplete)
    assert info["metadata"]["capture_scope"] == scope
    query = json.loads(run([str(ROOT / "tracemiku"), "records", str(call), "--start", "0", "--count", "1",
                           "--regs", "x0,x16,x17"]))
    assert query["records"][0]["idx"] == 0
    return len(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--devkit", type=Path, required=True, help="同版 ARM64 musl GumJS devkit 目录")
    parser.add_argument("--toolchain", type=Path, required=True,
                        help="JSON：cc、fixture_cflags、fixture_ldflags、library_flags、qemu 都是 argv 数组")
    parser.add_argument("--out", type=Path, help="新建的结果目录；默认创建 /tmp/tracemiku-arm64-* 并保留证据")
    options = parser.parse_args()
    cfg = json.loads(options.toolchain.read_text())
    for key in ["cc", "fixture_cflags", "fixture_ldflags", "library_flags", "qemu"]:
        assert isinstance(cfg[key], list) and all(isinstance(arg, str) for arg in cfg[key]), key
    output = options.out.resolve() if options.out else Path(tempfile.mkdtemp(prefix="tracemiku-arm64-"))
    if options.out:
        output.mkdir(parents=True)
    devkit = options.devkit.resolve()
    fixture, library, script = output / "fixture", output / "libtracemiku_offline.so", output / "agent.js"
    run(cfg["cc"] + cfg["fixture_cflags"] + ["-I", str(devkit), str(ROOT / "tracer/tests/arm64_fixture.c"),
        "-o", str(fixture), "-L", str(devkit), "-lfrida-gumjs"] + cfg["fixture_ldflags"])
    run(cfg["cc"] + cfg["library_flags"] + ["-shared", "-nostdlib", "-fPIC", "-Wl,-Bsymbolic",
        str(ROOT / "tracer/tests/arm64_target.c"), "-o", str(library)])
    run(["node", "node_modules/frida-compile/dist/cli.js", "tests/offline_agent.ts", "-o", str(script), "-c"],
        cwd=ROOT / "tracer")
    image = library.read_bytes()
    summary = []
    for name, value, result, count, expected, rejected in CASES:
        spool = output / f"{name}_{value}"
        spool.mkdir()
        args = cfg["qemu"] + ["-E", f"TRACEMIKU_LIBRARY={library}", "-E", f"TRACEMIKU_CALLS={count}",
            str(fixture), str(script), "trace_" + name, str(spool), str(value), result]
        process = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
        log = process.stdout + process.stderr
        (spool / "console.log").write_text(log)
        assert process.returncode == (2 if rejected else 0), (name, log)
        assert "FIXTURE_RESTORED=1" in log
        if rejected:
            assert rejected in log and not list(spool.glob("trace_call*.bin")), (name, log)
            session = json.loads((spool / "session.json").read_text())
            assert session["state"] == "FAILED" and rejected in session["error"]
            summary.append({"case": name, "rejected": rejected})
        else:
            session = json.loads((spool / "session.json").read_text())
            assert session["state"] == "SEALED" and len(session["calls"]) == count
            totals = [verify_call(spool, Path(path), image, expected, name == "atomic")
                      for path in session["calls"]]
            summary.append({"case": name, "input": value, "records": totals, "complete": name != "atomic"})
        print(json.dumps(summary[-1], ensure_ascii=False), flush=True)
    (output / "result.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"status": "ok", "cases": len(summary), "output": str(output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
