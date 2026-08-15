"""Device launch primitives for the traceMiku host CLI.

Extracted from `tracemiku` (which exceeded the 1500-line AGENTS.md red line)
so the adb/UI launch logic is a separate, importable module. Pure subprocess
+ time — no cross-module state.
"""

import subprocess
import time


def launch_start(pkg, max_pid_wait=15):
    """force-stop + monkey 拉起, 不清应用数据, 等 pid 出现就返回.
    用于需要尽早 attach 但不能 `pm clear` 破坏登录/本地状态的场景.
    """
    print(f"[launch] force-stop {pkg} (no pm clear)", flush=True)
    subprocess.run(["adb", "shell", "am", "force-stop", pkg], capture_output=True)
    time.sleep(0.5)
    print("[launch] monkey 拉起", flush=True)
    subprocess.run(
        [
            "adb",
            "shell",
            "monkey",
            "-p",
            pkg,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ],
        capture_output=True,
    )
    t0 = time.time()
    while time.time() - t0 < max_pid_wait:
        r = subprocess.run(
            ["adb", "shell", "pidof", pkg], capture_output=True, text=True
        )
        s = r.stdout.strip()
        if s:
            pid = int(s.split()[0])
            print(f"[launch] pid={pid} ({int(time.time() - t0)}s)", flush=True)
            return pid
        time.sleep(0.25)
    raise RuntimeError(f"launch {pkg} 拿不到 pid 超时 {max_pid_wait}s")


def _check_device(pkg=None, out_dir=None, verbose=True):
    """Shared device pre-flight checks. Returns (ok_count, fail_count, results_list).
    Each result is (check_name, passed: bool, detail: str)."""
    results = []

    def _run(label, cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return r.returncode, r.stdout.strip(), r.stderr.strip()
        except FileNotFoundError:
            return -1, "", f"{cmd[0]} not found"
        except subprocess.TimeoutExpired:
            return -2, "", "timeout"

    # 1. ADB connectivity
    rc, out, err = _run("adb", ["adb", "devices"])
    devices = [
        line for line in out.splitlines()[1:] if line.strip() and "device" in line
    ]
    if rc == 0 and devices:
        results.append(
            ("adb connectivity", True, f"{len(devices)} device(s) connected")
        )
    else:
        results.append(
            ("adb connectivity", False, "no device found — check USB/WiFi connection")
        )

    # 2. Root / su access
    rc, out, _ = _run("root", ["adb", "shell", "id"])
    if "uid=0" in out:
        results.append(("root access", True, "running as root"))
    else:
        rc2, out2, _ = _run("su", ["adb", "shell", "su", "-c", "id"])
        if "uid=0" in out2:
            results.append(("root access", True, "su available"))
        else:
            results.append(
                (
                    "root access",
                    False,
                    "no root — run `adb root` or ensure su binary exists",
                )
            )

    # 3. frida-server running
    rc, out, _ = _run("frida", ["adb", "shell", "ps -A"])
    if "miku" in out.lower() or "frida" in out.lower():
        results.append(("frida-server", True, "process found"))
    else:
        results.append(
            (
                "frida-server",
                False,
                "not running — start with: adb shell /data/local/tmp/.miku-srv &",
            )
        )

    # 4. SELinux state
    rc, out, _ = _run("selinux", ["adb", "shell", "getenforce"])
    if "permissive" in out.lower() or "disabled" in out.lower():
        results.append(("SELinux", True, out))
    else:
        results.append(
            ("SELinux", False, f"state={out} — set permissive: adb shell setenforce 0")
        )

    # 5. Target package exists (optional)
    if pkg:
        rc, out, _ = _run("pkg", ["adb", "shell", "pm", "list", "packages"])
        if f"package:{pkg}" in out:
            results.append(("target package", True, f"{pkg} installed"))
        else:
            # Try partial match
            partial = [line for line in out.splitlines() if pkg.lower() in line.lower()]
            if partial:
                results.append(
                    (
                        "target package",
                        False,
                        f"exact '{pkg}' not found; similar: {partial[0].replace('package:', '')}",
                    )
                )
            else:
                results.append(
                    ("target package", False, f"'{pkg}' not installed on device")
                )

    # 6. Output directory writable (optional)
    if out_dir:
        rc, out, err = _run(
            "write-test",
            ["adb", "shell", f"touch {out_dir}/.miku_test && rm {out_dir}/.miku_test"],
        )
        if rc == 0:
            results.append(("output dir writable", True, out_dir))
        else:
            results.append(
                (
                    "output dir writable",
                    False,
                    f"{out_dir} not writable — check SELinux context or use /data/local/tmp",
                )
            )

    if verbose:
        for name, passed, detail in results:
            mark = "\033[32m✓\033[0m" if passed else "\033[31m✗\033[0m"
            print(f"  {mark} {name}: {detail}")

    ok = sum(1 for _, p, _ in results if p)
    fail = sum(1 for _, p, _ in results if not p)
    return ok, fail, results
