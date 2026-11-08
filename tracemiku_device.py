"""Device launch primitives for the traceMiku host CLI.

Extracted from `tracemiku` (which exceeded the 1500-line AGENTS.md red line)
so the adb/UI launch logic is a separate, importable module. Pure subprocess
+ time — no cross-module state.
"""

import os
import shlex
import subprocess
import sys
import time

from tracemiku_common import adb_command, make_su_detector


def resolve_running_pid(pkg, device=None):
    """按应用身份解析唯一主进程；显示名和 :suffix 不作为包名证据。"""
    if not isinstance(pkg, str) or not pkg or "\0" in pkg:
        raise ValueError("invalid package identifier")
    candidates = set()
    if device is not None:
        try:
            processes = device.enumerate_processes(scope="metadata")
        except Exception:
            processes = []
        for process in processes:
            parameters = getattr(process, "parameters", {}) or {}
            identities = parameters.get("applications", [])
            if not isinstance(identities, list):
                identities = [identities]
            identities = [*identities, parameters.get("application"), parameters.get("package")]
            identifiers = {identity.get("identifier") if isinstance(identity, dict) else identity
                           for identity in identities if isinstance(identity, (str, dict))}
            if pkg in identifiers and not process.name.startswith(pkg + ":") and process.pid > 0:
                candidates.add(process.pid)
        try:
            applications = device.enumerate_applications(identifiers=[pkg], scope="minimal")
        except Exception:
            applications = []
        main_pids = {app.pid for app in applications if app.identifier == pkg and app.pid > 0}
        if len(main_pids) == 1:
            return main_pids.pop()
        if len(main_pids) > 1:
            return None
        if len(candidates) == 1:
            return candidates.pop()

    command = f"""for cmdline in /proc/[0-9]*/cmdline; do
    IFS= read -r -d '' argv0 < "$cmdline" 2>/dev/null || continue
    [ "$argv0" = {shlex.quote(pkg)} ] || continue
    process_id="${{cmdline#/proc/}}"
    printf '%s\\n' "${{process_id%/cmdline}}"
done"""
    if make_su_detector()():
        command = "su -c " + shlex.quote(command)
    try:
        result = subprocess.run(adb_command("shell", command), capture_output=True,
                                text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode:
        return None
    pids = {int(value) for value in result.stdout.split() if value.isdecimal() and int(value) > 0}
    return pids.pop() if len(pids) == 1 else None


def usable_devices(devices_output, want_serial):
    """从 `adb devices` 输出里取真正可用的设备序列号。

    第二列必须严格等于 "device": unauthorized / offline / no permissions
    都不是可用设备, 子串匹配会全部误判成已连接。指定 serial 时只认该 serial。
    """
    out = []
    for line in (devices_output or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2 or parts[1] != "device":
            continue
        if want_serial and parts[0] != want_serial:
            continue
        out.append(parts[0])
    return out


def launch_start(pkg, max_pid_wait=15):
    """force-stop + monkey 拉起, 不清应用数据, 等 pid 出现就返回.
    用于需要尽早 attach 但不能 `pm clear` 破坏登录/本地状态的场景.
    所有 adb 调用统一 10s timeout — adb 挂死时快速失败而不是永远阻塞.
    """
    print(f"[launch] force-stop {pkg} (no pm clear)", file=sys.stderr, flush=True)
    subprocess.run(adb_command("shell", "am", "force-stop", pkg),
                   capture_output=True, timeout=10, check=False)
    time.sleep(0.5)
    print("[launch] monkey 拉起", file=sys.stderr, flush=True)
    subprocess.run(
        adb_command(
            "shell",
            "monkey",
            "-p",
            pkg,
            "-c",
            "android.intent.category.LAUNCHER",
            "1",
        ),
        capture_output=True,
        timeout=10,
        check=False,
    )
    t0 = time.time()
    while time.time() - t0 < max_pid_wait:
        r = subprocess.run(
            adb_command("shell", "pidof", pkg), capture_output=True, text=True,
            timeout=10, check=False,
        )
        s = r.stdout.strip()
        if s:
            pid = int(s.split()[0])
            print(f"[launch] pid={pid} ({int(time.time() - t0)}s)", file=sys.stderr, flush=True)
            return pid
        time.sleep(0.25)
    raise RuntimeError(f"launch {pkg} 拿不到 pid 超时 {max_pid_wait}s")


def _check_device(pkg=None, out_dir=None, verbose=True):
    """Shared device pre-flight checks. Returns (ok_count, fail_count, results_list).
    Each result is (check_name, passed: bool, detail: str)."""
    results = []

    def _run(label, cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            return r.returncode, r.stdout.strip(), r.stderr.strip()
        except FileNotFoundError:
            return -1, "", f"{cmd[0]} not found"
        except subprocess.TimeoutExpired:
            return -2, "", "timeout"

    # 1. ADB connectivity
    # 第二列必须严格等于 "device": unauthorized / offline / no permissions 都
    # 不是可用设备, 子串匹配会全部误判成已连接。指定 serial 时只认该 serial。
    rc, out, _err = _run("adb", adb_command("devices"))
    want_serial = os.environ.get("ANDROID_SERIAL")
    devices = usable_devices(out, want_serial)
    endpoint = []
    if os.environ.get("ANDROID_ADB_SERVER_PORT"):
        endpoint.append(f"port={os.environ['ANDROID_ADB_SERVER_PORT']}")
    if want_serial:
        endpoint.append(f"serial={want_serial}")
    ep = (" [" + " ".join(endpoint) + "]") if endpoint else ""
    if rc == 0 and devices:
        results.append(
            ("adb connectivity", True,
             f"{len(devices)} device(s) connected{ep}: {', '.join(devices)}")
        )
    else:
        results.append(
            ("adb connectivity", False,
             f"no usable device{ep} — 检查 USB/WiFi 与 ANDROID_SERIAL/ANDROID_ADB_SERVER_PORT")
        )

    # 2. Root / su access
    rc, out, _ = _run("root", adb_command("shell", "id"))
    if "uid=0" in out:
        results.append(("root access", True, "running as root"))
    else:
        _rc2, out2, _ = _run("su", adb_command("shell", "su", "-c", "id"))
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
    # 精确进程名匹配: ps -A 的 NAME 列是 comm (≤15 字符). 子串匹配会把任意
    # 名字含 "miku"/"frida" 的进程 (如 com.miku.app) 误判为 server 在跑.
    # 实际进程名约定: stealth server = .miku-srv (comm 可能截断为 miku),
    # 官方/patched server = frida-server[-NN] (comm 15 字符截断).
    rc, out, _ = _run("frida", adb_command("shell", "ps -A"))
    server_names = {".miku-srv", "frida-server", "miku"}
    proc_names = [
        ln.split()[-1] for ln in out.splitlines()[1:] if ln.strip()
    ]
    if any(n in server_names or n.startswith("frida-server") for n in proc_names):
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
    rc, out, _ = _run("selinux", adb_command("shell", "getenforce"))
    if "permissive" in out.lower() or "disabled" in out.lower():
        results.append(("SELinux", True, out))
    else:
        results.append(
            ("SELinux", False, f"state={out} — set permissive: adb shell setenforce 0")
        )

    # 5. Target package exists (optional)
    if pkg:
        rc, out, _ = _run("pkg", adb_command("shell", "pm", "list", "packages"))
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
        rc, out, _err = _run(
            "write-test",
            adb_command("shell", f"touch {out_dir}/.miku_test && rm {out_dir}/.miku_test"),
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
