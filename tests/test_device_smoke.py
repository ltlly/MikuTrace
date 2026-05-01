"""真机 smoke tests — 验证 adb / frida 路径完整, agent js 语法干净.

用户连了真机 (33cfd6d3). frida-server 监听 :6699 (adb forward).
本套不真跑 trace (需要点 app), 只验:
  - adb device 在线
  - frida 能连 + 列进程
  - tracer agent js 全部 node syntax check
  - tracemiku list / info 在 traces 目录上工作
  - finalize 对空 pending dir 不崩

跑 -m device 才跑 (CI 没设备).
"""
import json, pathlib, subprocess, sys, pytest, shutil

HERE = pathlib.Path(__file__).resolve().parent.parent
TRACER_JS_DIR = HERE / "tracer"


def _adb_devices_online() -> bool:
    try:
        r = subprocess.run(["adb", "devices"], capture_output=True,
                           text=True, timeout=5)
        return any("\tdevice" in ln for ln in r.stdout.splitlines()[1:])
    except Exception:
        return False


pytestmark = [
    pytest.mark.device,
    pytest.mark.slow,
    pytest.mark.skipif(not shutil.which("adb"), reason="adb 不在 PATH"),
    pytest.mark.skipif(not _adb_devices_online(), reason="无在线 adb 设备"),
]


# ── adb ─────────────────────────────────────────────────────────────────────

def test_adb_device_online():
    r = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
    online = [ln for ln in r.stdout.splitlines() if "\tdevice" in ln]
    assert len(online) >= 1, f"应有 ≥1 在线设备: {r.stdout}"


def test_adb_shell_basic():
    """adb shell 能执行基本命令."""
    r = subprocess.run(["adb", "shell", "echo", "ok"],
                       capture_output=True, text=True, timeout=5)
    assert r.returncode == 0
    assert "ok" in r.stdout


# ── frida ───────────────────────────────────────────────────────────────────

def _frida_remote_dev():
    """Try multiple paths to find frida server."""
    import frida
    # 用户 setup: adb forward tcp:6699 tcp:6699
    try:
        dev = frida.get_device_manager().add_remote_device("localhost:6699")
        dev.enumerate_processes()
        return dev
    except Exception:
        pass
    # fallback: USB
    try:
        return frida.get_usb_device(timeout=2)
    except Exception:
        return None


def test_frida_server_reachable():
    """frida-server 能连 + 进程列表非空."""
    dev = _frida_remote_dev()
    if dev is None:
        pytest.skip("frida-server 不可达 (检查 adb forward / 启动 frida-server)")
    procs = dev.enumerate_processes()
    assert len(procs) > 10, f"frida 应能枚举系统进程 (>10), got {len(procs)}"
    # init/zygote 等系统进程应在
    names = {p.name for p in procs}
    assert "init" in names or "zygote" in names or "system_server" in names


# ── tracer agent js syntax ──────────────────────────────────────────────────

def test_all_tracer_js_node_syntax_clean():
    """tracer/*.js 必须能过 node --check (语法错 → undeployable)."""
    if not shutil.which("node"):
        pytest.skip("node 不在 PATH — agent JS 语法检查需要 node")
    js_files = list(TRACER_JS_DIR.glob("*.js"))
    assert len(js_files) >= 1, f"tracer/ 应有 .js 文件: {TRACER_JS_DIR}"
    errs = []
    for js in js_files:
        r = subprocess.run(["node", "--check", str(js)],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            errs.append(f"{js.name}: {r.stderr[:200]}")
    assert not errs, "agent js 语法错:\n" + "\n".join(errs)


# ── tracemiku list / info smoke ─────────────────────────────────────────────

def test_tracemiku_list_runs_works():
    """tracemiku list (无参) 列出 runs, 不崩."""
    traces_dir = HERE / "traces"
    if not traces_dir.exists():
        pytest.skip(f"无 {traces_dir} 目录")
    r = subprocess.run([sys.executable, str(HERE / "tracemiku"), "list"],
                       capture_output=True, text=True, timeout=10,
                       cwd=str(HERE))
    # list 命令未必有 stdout (空目录), 但不应非 0 退出
    assert r.returncode == 0, f"tracemiku list 退出 {r.returncode}\nstderr: {r.stderr[:300]}"


def test_tracemiku_info_on_existing_call():
    """如果 traces/multiso_v2/calls 下有 call dir, 跑 info 应出 JSON."""
    calls_dir = HERE / "traces" / "multiso_v2" / "calls"
    if not calls_dir.exists():
        pytest.skip(f"无 {calls_dir}")
    call_dirs = [d for d in calls_dir.iterdir()
                 if d.is_dir() and d.name.startswith("call_")]
    if not call_dirs:
        pytest.skip("无 call_* dir")
    cd = call_dirs[0]
    r = subprocess.run([sys.executable, str(HERE / "tracemiku"), "info", str(cd)],
                       capture_output=True, text=True, timeout=10,
                       cwd=str(HERE))
    assert r.returncode == 0, f"info exit {r.returncode}: {r.stderr[:200]}"
    # info 输出应含 trace 元信息 — 中文/英文混排都接受
    assert any(k in r.stdout for k in ("路径", "记录", "tid=", "first_pc", "records")), (
        f"info 输出不像正常 trace info: {r.stdout[:300]}")


def test_tracemiku_finalize_safe_on_no_pending(tmp_path):
    """finalize 对没有 _pending_call_* 的 run dir 应静默 noop."""
    run = tmp_path / "run1"
    run.mkdir()
    (run / "calls").mkdir()
    json.dump({"pkg": "x"}, open(run / "meta.json", "w"))
    r = subprocess.run([sys.executable, str(HERE / "tracemiku"), "finalize", str(run)],
                       capture_output=True, text=True, timeout=10,
                       cwd=str(HERE))
    assert r.returncode == 0, f"finalize 空 run 应 noop, got rc={r.returncode}: {r.stderr[:200]}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "device"])
