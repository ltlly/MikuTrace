"""Frida 会话驱动：Python API + 显式注入 frida-java-bridge。

frida-tools CLI 在非 tty 下会立刻退出，spawn 模式在本机 frida-server 上不注入脚本，
所以统一走这个驱动：
  - attach 主进程（多进程 app 取第一个 pid）
  - 前置加载 frida_tools/bridges/java.js
  - 加载探针脚本，收集消息到 JSONL
  - 可选：按计划用 adb input 驱动 UI
用法: python3 fr_session.py <script.js> <out.jsonl> [action.json]
action.json: [{"at": 20, "do": "tap", "x": 300, "y": 955}, ...]
"""
import json
import os
import subprocess
import sys
import threading
import time

import frida

PORT = int(os.environ.get("FRIDA_PORT", "27099"))
PKG = os.environ.get("TARGET_PKG", "com.aliyun.tongyi")
ADB_ENV = dict(os.environ, ANDROID_ADB_SERVER_PORT="5038")
BRIDGE = os.path.expanduser(
    "~/.local/share/uv/tools/frida-tools/lib/python3.14/site-packages/frida_tools/bridges/java.js"
)


def adb(*args, timeout=60):
    return subprocess.run(["adb", *args], capture_output=True, text=True, env=ADB_ENV, timeout=timeout)


def main():
    script_path, out_path = sys.argv[1], sys.argv[2]
    actions = json.load(open(sys.argv[3])) if len(sys.argv) > 3 else []
    launch = os.environ.get("LAUNCH") == "1"

    if launch:
        adb("shell", "am", "force-stop", PKG)
        time.sleep(2)
        adb("shell", "monkey", "-p", PKG, "-c", "android.intent.category.LAUNCHER", "1")
        time.sleep(int(os.environ.get("LAUNCH_WAIT", "10")))

    r = adb("shell", "pidof", PKG)
    if r.returncode != 0 or not r.stdout.strip():
        raise SystemExit("target not running: %r" % r.stdout)
    pid = int(r.stdout.strip().split()[0])

    dev = frida.get_device_manager().add_remote_device("127.0.0.1:%d" % PORT)
    session = dev.attach(pid)
    lock = threading.Lock()

    def sink(message, data):
        if message["type"] == "send":
            text = str(message["payload"])
        elif message["type"] == "error":
            text = "[error] " + (message.get("description") or "") + " " + (message.get("stack") or "")
        else:
            text = "[%s] %s" % (message["type"], message.get("description") or "")
        print("[msg] " + text[:300], flush=True)
        with lock:
            with open(out_path, "a") as f:
                f.write(text + "\n")

    # bridge 与探针必须在同一个 JS runtime 里，否则探针看不到 Java 全局
    # java.js 只定义 `var bridge = ...`，需要自己挂到全局 Java 上
    combined = (open(BRIDGE).read()
                + "\nvar Java = bridge;\n"
                + open(script_path).read())
    probe = session.create_script(combined, name="probe")
    probe.on("message", sink)
    probe.load()
    print("[driver] probe loaded", flush=True)

    start = time.time()
    for act in sorted(actions, key=lambda a: a["at"]):
        wait = act["at"] - (time.time() - start)
        if wait > 0:
            time.sleep(wait)
        kind = act.get("do")
        if kind == "tap":
            adb("shell", "input", "tap", str(act["x"]), str(act["y"]))
        elif kind == "key":
            adb("shell", "input", "keyevent", act["key"])
        elif kind == "text":
            adb("shell", "input", "text", act["text"])
        elif kind == "launch":
            adb("shell", "monkey", "-p", act.get("pkg", PKG), "-c", "android.intent.category.LAUNCHER", "1")
        print("[driver] action %s at %.1fs" % (kind, time.time() - start), flush=True)

    total = int(os.environ.get("TOTAL_SECONDS", "90"))
    while time.time() - start < total:
        time.sleep(2)
    print("[driver] done", flush=True)
    session.detach()


if __name__ == "__main__":
    main()
