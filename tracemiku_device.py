"""Device launch primitives for the traceMiku host CLI.

Extracted from `tracemiku` (which exceeded the 1500-line AGENTS.md red line)
so the adb/UI launch logic is a separate, importable module. Pure subprocess
+ time — no cross-module state.
"""

import subprocess
import time


def cold_launch_start(pkg, max_pid_wait=15):
    """force-stop + pm clear + monkey 拉起, 等 pid 出现就返回. 不点同意.
    用于 anti-debug 强的 app: attach 必须在隐私弹窗前完成, 否则 Frida 被卡死.
    """
    print(f"[cold-launch] force-stop + pm clear {pkg}", flush=True)
    subprocess.run(["adb", "shell", "am", "force-stop", pkg], capture_output=True)
    subprocess.run(["adb", "shell", "pm", "clear", pkg], capture_output=True)
    time.sleep(2)
    print("[cold-launch] monkey 拉起", flush=True)
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
            print(f"[cold-launch] pid={pid} ({int(time.time() - t0)}s)", flush=True)
            return pid
        time.sleep(0.5)
    raise RuntimeError(f"cold-launch {pkg} 拿不到 pid 超时 {max_pid_wait}s")


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


CONSENT_BUTTON_PATTERNS = [
    r'text="同意"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
    r'text="允许"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
    r'text="同意并继续"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
    r'text="Agree"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
    r'text="I Agree"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
]


def drive_consent(pkg, max_wait=60, home_markers=None, on_done=None):
    """在已拉起的 app 上自动点'同意' + 等首页. 用于 cold_launch_start 之后."""
    import re

    def adb(*a):
        return subprocess.run(
            ["adb", "shell", *a], capture_output=True, text=True
        ).stdout

    t0 = time.time()
    agreed = False
    settled = 0
    while time.time() - t0 < max_wait:
        elapsed = int(time.time() - t0)
        pid = adb("pidof", pkg).strip()
        if not pid:
            print(f"[cold-launch] {elapsed}s: 进程死, 重拉", flush=True)
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
            time.sleep(3)
            continue
        subprocess.run(
            ["adb", "shell", "uiautomator", "dump", "/sdcard/_tm_ui.xml"],
            capture_output=True,
        )
        xml = adb("cat", "/sdcard/_tm_ui.xml")
        subprocess.run(
            ["adb", "shell", "rm", "-f", "/sdcard/_tm_ui.xml"], capture_output=True
        )
        consent_hit = None
        for pat in CONSENT_BUTTON_PATTERNS:
            m = re.search(pat, xml)
            if m:
                consent_hit = m
                break
        if consent_hit:
            x = (int(consent_hit.group(1)) + int(consent_hit.group(3))) // 2
            y = (int(consent_hit.group(2)) + int(consent_hit.group(4))) // 2
            print(
                f"[cold-launch] {elapsed}s: 找到同意按钮 @ ({x},{y}) 点击", flush=True
            )
            subprocess.run(
                ["adb", "shell", "input", "tap", str(x), str(y)], capture_output=True
            )
            agreed = True
            settled = 0
            time.sleep(4)
            continue
        if home_markers and re.search(home_markers, xml):
            print(
                f"[cold-launch] {elapsed}s: 首页加载完成 (agreed={agreed}, marker hit)",
                flush=True,
            )
            if on_done:
                on_done()
            return int(pid.split()[0])
        if agreed:
            settled += 1
            if settled >= 2:
                print(
                    f"[cold-launch] {elapsed}s: 同意按钮已消失 + UI settle, 视为首页加载完成",
                    flush=True,
                )
                if on_done:
                    on_done()
                return int(pid.split()[0])
        print(
            f"[cold-launch] {elapsed}s: 等待 (agreed={agreed}, settled={settled})",
            flush=True,
        )
        time.sleep(2)
    raise RuntimeError(f"cold-launch {pkg} 超时 {max_wait}s")


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
