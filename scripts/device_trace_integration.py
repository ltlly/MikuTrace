#!/usr/bin/env python3
"""Device integration test: cross-compile ARM64 target → push → trace → verify.

Requires:
  - NDK installed (auto-detected or set ANDROID_NDK_HOME)
  - adb device connected with root access
  - frida-server running on device
  - USB connection (default) or --remote

Usage:
  uv run python scripts/device_trace_integration.py [--remote HOST:PORT] [--scenario complete]

Exit 0 on success, 1 on failure.
"""

import argparse
import json
import os
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
REC_SIZE = 272
sys.path.insert(0, str(PROJECT))

from tracemiku_device import adb_command, usable_devices
from tracemiku_spool import AdbSpool, file_hash

# ─────────────────────────── NDK detection ───────────────────────────


def find_ndk_clang() -> str | None:
    """Find aarch64-linux-android<api>-clang in NDK if installed."""
    ndk_home = os.environ.get("ANDROID_NDK_HOME")
    if not ndk_home:
        candidates = [
            Path.home() / "Library/Android/sdk/ndk",
            Path("/opt/android-ndk"),
            Path.home() / "Android/Sdk/ndk",
        ]
        for c in candidates:
            if c.exists():
                ndks = sorted(c.iterdir(), reverse=True)
                if ndks:
                    ndk_home = str(ndks[0])
                    break
    if not ndk_home:
        return None

    prebuilt = Path(ndk_home) / "toolchains/llvm/prebuilt"
    if not prebuilt.exists():
        return None
    hosts = list(prebuilt.iterdir())
    if not hosts:
        return None
    bin_dir = hosts[0] / "bin"
    for api in range(33, 20, -1):
        cc = bin_dir / f"aarch64-linux-android{api}-clang"
        if cc.exists():
            return str(cc)
    return None


def compile_test_binary(tmp: Path, src: Path, binary: Path) -> str:
    """Cross-compile ARM64 test binary with NDK clang or system clang + device libc.so."""
    cc = find_ndk_clang()
    if cc:
        subprocess.run([cc, "-O1", "-fPIE", "-pie", "-o", str(binary), str(src)], check=True, timeout=30)
        return str(Path(cc).parent / "llvm-nm")
    clang = shutil.which("clang")
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    if not clang or not nm:
        raise RuntimeError("Cannot find NDK or system clang/llvm-nm. Set ANDROID_NDK_HOME.")
    device_libc = tmp / "libc.so"
    adb("pull", "/apex/com.android.runtime/lib64/bionic/libc.so", str(device_libc))
    subprocess.run([
        clang, "--target=aarch64-linux-android30", "-fuse-ld=lld",
        "-Wl,--dynamic-linker,/system/bin/linker64,-z,max-page-size=4096", "-nostdlib",
        "-DTRACEMIKU_NOSTDLIB=1", "-O1", "-fPIE", "-pie",
        "-o", str(binary), str(src), str(device_libc),
    ], check=True, timeout=30)
    return nm


# ─────────────────────────── Test target source ───────────────────────────

TEST_C_SOURCE = r"""
#ifdef TRACEMIKU_NOSTDLIB
typedef unsigned long long uint64_t;
#define F_OK 0
extern int access(const char *, int);
extern int usleep(unsigned int);
extern unsigned int sleep(unsigned int);
extern int printf(const char *, ...);
extern int fflush(void *);
extern uint64_t strtoull(const char *, char **, int);
extern int atoi(const char *);
extern void exit(int);
__asm__(
".text\n.global _start\n.type _start,%function\n"
"_start:\n"
"ldr x0,[sp]\nadd x1,sp,#8\nbl main\nbl exit\n"
);
#else
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#endif

extern uint64_t tracemiku_test_entry(uint64_t count, unsigned delay);
// 已知执行次数与逐条 x0 值，验证连续性而非只比较同源计数。
__asm__(
".text\n.global tracemiku_test_entry\n.type tracemiku_test_entry,%function\n"
"tracemiku_test_entry:\n"
"stp x29,x30,[sp,#-32]!\nstp x19,x20,[sp,#16]\nmov x29,sp\nnop\n"
"mov x19,x0\nmov x0,x1\nbl sleep\nmov x0,#0\n"
".global tracemiku_test_marker\ntracemiku_test_marker:\n"
"add x0,x0,#1\nsubs x19,x19,#1\nb.ne tracemiku_test_marker\n"
"ldp x19,x20,[sp,#16]\nldp x29,x30,[sp],#32\nret\n"
".size tracemiku_test_entry,.-tracemiku_test_entry\n");

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    // host 完成 prepare/init 后创建触发文件，消除 attach 的启动竞争。
    while (access(argv[1], F_OK) != 0) usleep(10000);
    uint64_t result = tracemiku_test_entry(strtoull(argv[2], 0, 10), atoi(argv[3]));
    printf("TRACEMIKU_TEST_DONE result=%llu\n", (unsigned long long) result);
    fflush(0);
    sleep(atoi(argv[4]));
    return 0;
}
"""

# ─────────────────────────── Helpers ───────────────────────────


def adb(*cmd, check=True, capture=True):
    """Run adb command."""
    full = adb_command(*cmd)
    # check=False：返回码由下方按 `check` 形参统一判定并带上下文报错。
    r = subprocess.run(
        full, capture_output=capture, text=True, timeout=30, check=False
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"adb failed: {' '.join(full)}\n{r.stderr}")
    return r


def verify_trace(call_dir: Path) -> dict:
    """Verify trace output is valid. Returns stats dict."""
    trace_bin = call_dir / "trace.bin"
    meta_json = call_dir / "meta.json"

    if not trace_bin.exists():
        raise AssertionError(f"trace.bin not found: {trace_bin}")
    if not meta_json.exists():
        raise AssertionError(f"meta.json not found: {meta_json}")

    size = trace_bin.stat().st_size
    if size == 0:
        raise AssertionError("trace.bin is empty")
    if size % REC_SIZE != 0:
        raise AssertionError(f"trace.bin size {size} not aligned to {REC_SIZE}")

    num_records = size // REC_SIZE
    if num_records < 10:
        raise AssertionError(f"too few trace records: {num_records}")
    meta = json.loads(meta_json.read_text())

    # meta must declare records count
    if "records" not in meta:
        raise AssertionError("meta.json missing 'records' field")
    declared = meta["records"]
    if declared != num_records:
        raise AssertionError(
            f"meta declares {declared} records but trace.bin has {num_records}"
        )

    # Check first few records have valid PCs (non-zero, reasonable ARM64 range)
    with open(trace_bin, "rb") as f:
        for i in range(min(5, num_records)):
            rec = f.read(REC_SIZE)
            pc = struct.unpack_from("<Q", rec, 0)[0]
            if pc == 0:
                raise AssertionError(f"record {i} has pc=0")
            inst = struct.unpack_from("<I", rec, 268)[0]
            if inst == 0:
                raise AssertionError(
                    f"record {i} has inst=0 (unlikely for valid ARM64)"
                )

    # 统一入口必须能消费真机产物，不能只检查文件长度。
    def cli(*args):
        result = subprocess.run(
            [sys.executable, str(PROJECT / "tracemiku"), *args],
            capture_output=True, text=True, timeout=60, check=True,
        )
        return json.loads(result.stdout)

    info = cli("info", str(call_dir))
    assert info["records"] == num_records
    assert info["record_size"] == REC_SIZE
    assert info["is_complete"] is True
    assert meta["truncated"] is False and meta["dropped"] == 0
    assert meta["transfer_state"] == "VERIFIED"
    for artifact in meta["artifact_checksums"]:
        assert file_hash(call_dir / artifact["name"]) == artifact["sha256"]
    rows = cli("records", str(call_dir), "--indices", f"0,{num_records - 1}",
               "--regs", "x0,sp")["records"]
    assert len(rows) == 2
    with trace_bin.open("rb") as f:
        for row, idx in zip(rows, (0, num_records - 1)):
            f.seek(idx * REC_SIZE)
            raw = f.read(REC_SIZE)
            assert row["idx"] == idx
            assert int(row["pc"], 16) == struct.unpack_from("<Q", raw, 0)[0]
            assert int(row["regs"]["x0"], 16) == struct.unpack_from("<Q", raw, 8)[0]
            assert int(row["regs"]["sp"], 16) == struct.unpack_from("<Q", raw, 256)[0]

    return {
        "records": num_records,
        "size_mb": size / (1024 * 1024),
        "meta": meta,
    }


# ─────────────────────────── Main ───────────────────────────


def wait_until(predicate, timeout, label):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError(f"test watchdog expired: {label}")


def check_continuity(call, marker_offset, iterations):
    meta = json.loads((call / "meta.json").read_text())
    marker = int(meta["module"]["base"], 16) + marker_offset
    loop_records = 0
    with (call / "trace.bin").open("rb") as source:
        while batch := source.read(REC_SIZE * 65536):
            for offset in range(0, len(batch), REC_SIZE):
                pc, x0 = struct.unpack_from("<QQ", batch, offset)
                if marker <= pc <= marker + 8:
                    iteration, phase = divmod(loop_records, 3)
                    assert pc == marker + phase * 4, "loop instruction gap, duplicate or reorder"
                    expected = iteration + int(phase != 0)
                    assert x0 == expected, f"record gap/reorder: expected x0={expected}, got {x0}"
                    loop_records += 1
    assert loop_records == iterations * 3, f"missing loop instructions: {loop_records}/{iterations * 3}"
    if meta.get("simd_sidecar"):
        count = 0
        with (call / "simd_trace.bin").open("rb") as source:
            while batch := source.read(520 * 65536):
                for offset in range(0, len(batch), 520):
                    assert struct.unpack_from("<Q", batch, offset)[0] == count, "SIMD gap or reorder"
                    count += 1
        assert count == meta["records"]


def main():
    ap = argparse.ArgumentParser(description="真机完整采集、压缩回传与断线恢复验证")
    ap.add_argument("--remote", help="frida-server address")
    ap.add_argument("--scenario", choices=("complete", "disconnect", "transfer", "long"), default="complete")
    ap.add_argument("--simd-sidecar", action="store_true")
    ap.add_argument("--snapshot-mem", action="store_true")
    ap.add_argument("--semantic-events", action="store_true")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    devices = usable_devices(adb("devices").stdout, os.environ.get("ANDROID_SERIAL"))
    if len(devices) != 1:
        raise RuntimeError("需要唯一 ADB 真机；使用 ANDROID_SERIAL 选择")
    os.environ["ANDROID_SERIAL"] = devices[0]
    tmp = Path(tempfile.mkdtemp(prefix="tracemiku_devtest_"))
    src, binary = tmp / "target.c", tmp / "tracemiku_devtest"
    src.write_text(TEST_C_SOURCE)
    nm_bin = compile_test_binary(tmp, src, binary)
    symbols = subprocess.check_output([nm_bin, str(binary)], text=True)
    marker = next(int(line.split()[0], 16) for line in symbols.splitlines()
                  if line.endswith(" tracemiku_test_marker"))
    remote = f"/data/local/tmp/{tmp.name}"
    trigger = remote + ".go"
    adb("push", str(binary), remote)
    adb("shell", f"chmod 755 {remote}")
    iterations = 2_000_000 if args.scenario == "long" else 200_000
    delay = 125 if args.scenario == "long" else 6 if args.scenario == "disconnect" else 0
    pid = int(adb("shell", f"nohup {remote} {trigger} {iterations} {delay} 1 >{remote}.log 2>&1 </dev/null & echo $!").stdout.strip())
    out = tmp / "trace_out"
    cmd = [sys.executable, str(PROJECT / "tracemiku"), "trace", "--attach-pid", str(pid),
           "--so", tmp.name, "--export", "tracemiku_test_entry", "--jni-hooks", "none",
           "--ring-recs", "1024", "--out", str(out)]
    if args.remote:
        cmd += ["--remote", args.remote]
    for name in ("simd_sidecar", "snapshot_mem", "semantic_events"):
        if getattr(args, name):
            cmd += ["--" + name.replace("_", "-")]
    print(f"scenario={args.scenario} device={devices[0]} pid={pid} output={tmp}", flush=True)
    process = None
    try:
        with (tmp / "trace.stdout").open("w") as stdout, (tmp / "trace.stderr").open("w") as stderr:
            process = subprocess.Popen(cmd, stdout=stdout, stderr=stderr)
            def ready():
                if process.poll() is not None:
                    raise AssertionError((tmp / "trace.stderr").read_text())
                return "采集器已就绪" in (tmp / "trace.stderr").read_text()
            wait_until(ready, 30, "collector ready")
            adb("shell", f"touch {trigger}")
            descriptor = json.loads((out / "recovery.json").read_text())["sessions"][0]
            spool = AdbSpool()
            if args.scenario == "disconnect":
                wait_until(lambda: spool.read_json(descriptor["manifestPath"])["state"] == "CAPTURING",
                           15, "capture start")
                process.send_signal(signal.SIGKILL)
                process.wait(timeout=10)
                print("host connection killed during capture", flush=True)
                wait_until(lambda: spool.read_json(descriptor["manifestPath"])["state"] == "SEALED",
                           60, "autonomous device seal")
                time.sleep(2)  # fixture 自行退出；回传不得依赖其存活
            elif args.scenario == "transfer":
                wait_until(lambda: len(list((out / ".transfer").rglob("*.json"))) >= 2,
                           90, "two verified transfer chunks")
                process.send_signal(signal.SIGKILL)
                process.wait(timeout=10)
                print("host killed during compressed transfer", flush=True)
            else:
                code = process.wait(timeout=360)
                assert code == 0, (tmp / "trace.stdout").read_text() + (tmp / "trace.stderr").read_text()
            # 所有场景都运行恢复；完成场景验证幂等，断线场景验证复用原件。
            recovery = subprocess.run([sys.executable, str(PROJECT / "tracemiku"), "recover", str(out)],
                                      capture_output=True, text=True, timeout=240, check=False)
            (tmp / "recover.stdout").write_text(recovery.stdout)
            (tmp / "recover.stderr").write_text(recovery.stderr)
            assert recovery.returncode == 0, recovery.stdout + recovery.stderr
            result = json.loads(recovery.stdout)
            assert result["status"] == "ok" and len(result["calls"]) == 1
            call = Path(result["calls"][0]["path"])
            stats = verify_trace(call)
            check_continuity(call, marker, iterations)
            if args.scenario == "long":
                assert stats["records"] > 5_000_000 and stats["meta"]["ms"] > 120_000
            receipts = result["calls"][0]["artifacts"]
            assert sum(item["gzip_bytes"] for item in receipts) > 0
            if args.scenario == "transfer":
                assert sum(item["reused_chunks"] for item in receipts) >= 2
            if args.simd_sidecar:
                simd = stats["meta"]["simd_sidecar"]
                assert simd["records"] == stats["records"] and simd["dropped"] == 0
                assert (call / simd["file"]).stat().st_size == simd["records"] * 520
            print(f"PASS: {stats['records']:,} records; {iterations:,} consecutive marker values; "
                  f"raw={stats['records'] * REC_SIZE:,}; gzip={sum(a['gzip_bytes'] for a in receipts):,}", flush=True)
    except Exception:
        print(f"FAIL: 保留现场 {tmp}", file=sys.stderr)
        raise
    else:
        if not args.keep:
            shutil.rmtree(tmp)
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        # fixture PID 可能已退出；先核对 cmdline，避免 PID 复用杀错进程。
        adb("shell", f"test \"$(tr '\\0' ' ' </proc/{pid}/cmdline 2>/dev/null | cut -d ' ' -f 1)\" != {shlex.quote(remote)} || kill {pid}", check=False)
        adb("shell", f"rm -f {remote} {remote}.go {remote}.log", check=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
