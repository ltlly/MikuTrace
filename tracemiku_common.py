"""采集与恢复共用的设备定位、原子文件写入；不包含分析语义。"""
import json
import os
import subprocess

ADB_PROBE_TIMEOUT = 30

def adb_command(*args):
    """构造 adb argv: 尊重 ANDROID_ADB_SERVER_PORT / ANDROID_SERIAL。"""
    cmd = ["adb"]
    port = os.environ.get("ANDROID_ADB_SERVER_PORT")
    if port:          # 空串视为未设置
        try:
            port_num = int(port)
        except ValueError:
            raise ValueError(
                f"ANDROID_ADB_SERVER_PORT 必须是整数, 得到 {port!r}") from None
        if not 1 <= port_num <= 65535:
            raise ValueError(
                f"ANDROID_ADB_SERVER_PORT 必须在 1..65535, 得到 {port_num}")
        cmd += ["-P", str(port_num)]
    serial = os.environ.get("ANDROID_SERIAL")
    if serial:
        cmd += ["-s", serial]
    return [*cmd, *args]


def make_su_detector(wlog=None):
    """每次采集创建一个 su 探测器: 结论只探测一次, 失败按「需要 su」降级。"""
    state = {"use_su": None}

    def detect():
        if state["use_su"] is not None:
            return state["use_su"]
        use_su = True
        try:
            r = subprocess.run(adb_command("shell", "id"),
                               capture_output=True, text=True,
                               stdin=subprocess.DEVNULL,
                               timeout=ADB_PROBE_TIMEOUT, check=False)
            use_su = not (r.returncode == 0 and "uid=0" in (r.stdout or ""))
        except (subprocess.TimeoutExpired, OSError) as exc:
            if wlog:
                wlog(f"  adb root 探测失败 ({exc.__class__.__name__}); 缓存 su 降级结论")
        state["use_su"] = use_su
        return use_su

    return detect


def atomic_json(path, obj):
    """原子写 JSON: 先写 .tmp 再 rename, 避免崩溃留下半截 meta。"""
    tmp = str(path) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    sync_directory(os.path.dirname(os.path.abspath(path)))


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
