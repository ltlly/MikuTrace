#!/usr/bin/env python3
"""Device integration test: cross-compile ARM64 target → push → trace → verify.

Requires:
  - NDK installed (auto-detected or set ANDROID_NDK_HOME)
  - adb device connected with root access
  - frida-server running on device
  - USB connection (default) or --remote

Usage:
  uv run python scripts/device_trace_integration.py [--remote HOST:PORT] [--duration 15]

Exit 0 on success, 1 on failure.
"""

import argparse
import json
import os
import shutil
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

# ─────────────────────────── NDK detection ───────────────────────────


def find_ndk_clang() -> str:
    """Find aarch64-linux-android<api>-clang in NDK."""
    ndk_home = os.environ.get("ANDROID_NDK_HOME")
    if not ndk_home:
        # Try common locations
        candidates = [
            Path.home() / "Library/Android/sdk/ndk",
            Path("/opt/android-ndk"),
            Path.home() / "Android/Sdk/ndk",
        ]
        for c in candidates:
            if c.exists():
                # Pick newest NDK
                ndks = sorted(c.iterdir(), reverse=True)
                if ndks:
                    ndk_home = str(ndks[0])
                    break
    if not ndk_home:
        raise RuntimeError("Cannot find NDK. Set ANDROID_NDK_HOME.")

    # Find clang binary
    prebuilt = Path(ndk_home) / "toolchains/llvm/prebuilt"
    if not prebuilt.exists():
        raise RuntimeError(f"NDK prebuilt dir not found: {prebuilt}")
    hosts = list(prebuilt.iterdir())
    if not hosts:
        raise RuntimeError(f"No host toolchain in {prebuilt}")
    bin_dir = hosts[0] / "bin"
    # Prefer API 28+
    for api in range(33, 20, -1):
        cc = bin_dir / f"aarch64-linux-android{api}-clang"
        if cc.exists():
            return str(cc)
    raise RuntimeError(f"No aarch64-linux-android*-clang found in {bin_dir}")


# ─────────────────────────── Test target source ───────────────────────────

TEST_C_SOURCE = r"""
// Minimal ARM64 test target for traceMiku device integration.
// Does enough work (insertion sort 500 elements) to produce a meaningful trace.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline))
void insertion_sort(int *arr, int n) {
    for (int i = 1; i < n; i++) {
        int key = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

__attribute__((noinline))
int sum_array(int *arr, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += arr[i];
    return s;
}

// Exported entry — tracemiku will hook this
// noinline 必须保留: -O1 下单一调用点会被内联进 main, .symtab 里的
// outline 副本将无人执行, --export hook 会静默落空.
__attribute__((noinline, visibility("default")))
int tracemiku_test_entry(void) {
    const int N = 500;
    int arr[500];
    srand(42);
    for (int i = 0; i < N; i++) arr[i] = rand() % 10000;
    insertion_sort(arr, N);
    int result = sum_array(arr, N);
    printf("sorted sum = %d\n", result);
    return result;
}

int main(int argc, char **argv) {
    // Signal readiness, then call entry, then sleep to allow trace collection
    printf("TRACEMIKU_TEST_READY pid=%d\n", getpid());
    fflush(stdout);
    // Sleep briefly to give the tracer time to attach
    sleep(3);
    int calls = argc > 1 ? atoi(argv[1]) : 1;
    for (int i = 0; i < calls; i++) tracemiku_test_entry();
    // Frida 回传需要目标存活；由 host 在验证完成后终止测试进程。
    sleep(argc > 2 ? atoi(argv[2]) : 300);
    printf("TRACEMIKU_TEST_DONE\n");
    fflush(stdout);
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


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--remote", default=None, help="frida-server address")
    ap.add_argument("--duration", type=int, default=12, help="trace duration seconds")
    ap.add_argument("--max-records", type=int, default=500000, help="max trace records")
    ap.add_argument("--transport", choices=("frida", "adb"), default="frida")
    ap.add_argument("--max-calls", type=int, default=1, help="capture call limit")
    ap.add_argument("--target-calls", type=int, default=1, help="calls made by the test target")
    ap.add_argument("--target-linger", type=int, default=300,
                    help="seconds the target stays alive for file transfer")
    ap.add_argument("--simd-sidecar", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep output trace dir")
    args = ap.parse_args()
    if (not 1 <= args.target_calls <= 8 or not 1 <= args.max_calls <= 8 or
            not 10 <= args.max_records <= 500000 or not 4 <= args.duration <= 60 or
            not 0 <= args.target_linger <= 300):
        ap.error("calls must be 1..8, records 10..500000, duration 4..60, linger 0..300")

    print("=" * 60)
    print("traceMiku Device Integration Test")
    print("=" * 60)

    # 1. Find NDK clang
    print("\n[1/6] Finding NDK cross-compiler...")
    try:
        cc = find_ndk_clang()
    except RuntimeError as e:
        print(f"  FAIL: {e}", file=sys.stderr)
        return 1
    print(f"  CC = {cc}")

    # 2. Check device connectivity
    print("\n[2/6] Checking adb device...")
    try:
        r = adb("devices")
        devices = usable_devices(r.stdout, os.environ.get("ANDROID_SERIAL"))
        if not devices:
            print("  FAIL: no selected adb device connected")
            return 1
        if len(devices) != 1:
            print("  FAIL: set ANDROID_SERIAL to select one device", file=sys.stderr)
            return 1
        os.environ["ANDROID_SERIAL"] = devices[0]
        print(f"  Device: {devices[0]}")
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"  FAIL: adb not available ({e})")
        return 1

    # 3. Cross-compile
    print("\n[3/6] Cross-compiling ARM64 test binary...")
    tmp = Path(tempfile.mkdtemp(prefix="tracemiku_devtest_"))
    src_file = tmp / "test_target.c"
    bin_file = tmp / "tracemiku_devtest"
    src_file.write_text(TEST_C_SOURCE)

    # check=False：编译失败时下方带 stderr 上下文报告并清理临时目录。
    r = subprocess.run(
        [
            cc,
            "-O1",
            "-fPIE",
            "-pie",
            "-o",
            str(bin_file),
            str(src_file),
            "-static-libstdc++",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if r.returncode != 0:
        print(f"  FAIL: compilation failed:\n{r.stderr}", file=sys.stderr)
        shutil.rmtree(tmp)
        return 1
    print(f"  Built: {bin_file} ({bin_file.stat().st_size} bytes)")

    # 4. Push to device and run
    print("\n[4/6] Pushing to device and launching...")
    device_path = f"/data/local/tmp/{tmp.name}"
    adb("push", str(bin_file), device_path)
    adb("shell", f"chmod 755 {device_path}")

    # Launch in background, capture pid
    # Use shell nohup to keep it alive
    proc = subprocess.Popen(
        adb_command("shell", device_path, str(args.target_calls), str(args.target_linger)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Wait for READY signal
    pid = None
    t0 = time.time()
    while time.time() - t0 < 10:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        line = line.strip()
        if "TRACEMIKU_TEST_READY" in line:
            # Extract pid from "TRACEMIKU_TEST_READY pid=NNN"
            for part in line.split():
                if part.startswith("pid="):
                    pid = int(part.split("=")[1])
            break
    if pid is None:
        print("  FAIL: test binary did not print READY signal", file=sys.stderr)
        proc.kill()
        shutil.rmtree(tmp)
        return 1
    print(f"  Running on device, pid={pid}")

    # 5. Run tracemiku trace
    print("\n[5/6] Running tracemiku trace...")
    out_dir = tmp / "trace_out"
    trace_cmd = [
        sys.executable,
        str(PROJECT / "tracemiku"),
        "trace",
        "--attach-pid",
        str(pid),
        "--so",
        "tracemiku_devtest",
        "--export",
        "tracemiku_test_entry",
        "--max-records",
        str(args.max_records),
        "--max-calls",
        str(args.max_calls),
        "--transport",
        args.transport,
        "--jni-hooks",
        "none",
        "--duration",
        str(args.duration),
        "--out",
        str(out_dir),
    ]
    if args.remote:
        trace_cmd += ["--remote", args.remote]
    if args.simd_sidecar:
        trace_cmd += ["--simd-sidecar"]
    print(f"  cmd: {' '.join(trace_cmd[-8:])}")

    # check=False：trace 子进程的返回码在等待目标进程结束后由下方统一判定。
    try:
        tr = subprocess.run(
            trace_cmd, capture_output=True, text=True,
            timeout=args.duration + 210, check=False,
        )
        (tmp / "trace.stdout").write_text(tr.stdout)
        (tmp / "trace.stderr").write_text(tr.stderr)
    finally:
        # 只终止本次启动的测试 PID；不遗留 adb 子进程或设备目标。
        adb("shell", "kill", str(pid), check=False)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
        adb("shell", "rm", "-f", device_path, check=False)

    if tr.returncode != 0:
        print(f"  FAIL: trace exited {tr.returncode}")
        print(f"  trace stdout: {tr.stdout[-2000:]}")
        if tr.stderr:
            print(f"  stderr: {tr.stderr[:500]}")
        return 1

    # 6. Verify output
    print("\n[6/6] Verifying trace output...")
    # Find call directory
    calls_dir = out_dir / "calls"
    if not calls_dir.exists():
        # Maybe direct output
        calls_dir = out_dir
    call_dirs = sorted(calls_dir.glob("call_*"))
    if len(call_dirs) != min(args.max_calls, args.target_calls):
        print(f"  FAIL: expected {min(args.max_calls, args.target_calls)} calls, got {len(call_dirs)}")
        print(f"  trace stdout: {tr.stdout[-2000:]}")
        return 1
    for cd in call_dirs:
        try:
            stats = verify_trace(cd)
            assert stats["records"] <= args.max_records, "record limit exceeded"
            if stats["records"] == args.max_records:
                assert stats["meta"]["truncated"] is True, "record cap reached without truncated=true"
            if args.simd_sidecar:
                simd = stats["meta"]["simd_sidecar"]
                assert simd["records"] > 0
                assert (cd / simd["file"]).stat().st_size == simd["records"] * simd["record_size"]
            print(
                f"  ✓ {cd.name}: {stats['records']} records, {stats['size_mb']:.2f} MB"
            )
        except AssertionError as e:
            print(f"  ✗ {cd.name}: {e}", file=sys.stderr)
            if not args.keep:
                shutil.rmtree(tmp)
            return 1

    total_recs = sum(
        json.loads((cd / "meta.json").read_text()).get("records", 0) for cd in call_dirs
    )
    print(f"\n{'=' * 60}")
    print(f"PASS — {len(call_dirs)} call(s), {total_recs} total records")
    print(f"{'=' * 60}")

    if not args.keep:
        shutil.rmtree(tmp)
    else:
        print(f"  (kept output at {tmp})")

    return 0


if __name__ == "__main__":
    sys.exit(main())
