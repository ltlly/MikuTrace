#!/usr/bin/env python3
"""spawn_hook.py — Spawn Android app with Frida hook injection.

用法:
    uv run python tools/spawn_hook.py <package> <hook_script.js> [--timeout 60] [--output /tmp/hook_results.txt]

示例:
    uv run python tools/spawn_hook.py com.ss.android.ugc.aweme tools/native_sign_hooks_v4.js --timeout 120

hook 脚本使用 send() 发送消息，结果写入 --output 文件。
"""

import frida
import sys
import time
import os
import argparse


def main():
    parser = argparse.ArgumentParser(description="Spawn Android app with Frida hooks")
    parser.add_argument("package", help="Android package name")
    parser.add_argument("script", help="Path to Frida hook script (.js)")
    parser.add_argument("--timeout", type=int, default=60, help="Seconds to wait (default: 60)")
    parser.add_argument("--output", default="/tmp/spawn_hook_results.txt", help="Output file path")
    args = parser.parse_args()

    if not os.path.exists(args.script):
        print(f"ERROR: script not found: {args.script}")
        sys.exit(1)

    out_path = os.path.abspath(args.output)
    open(out_path, 'w').close()

    def log(msg: str):
        with open(out_path, 'a') as f:
            f.write(msg + '\n')

    device = frida.get_usb_device()
    pid = device.spawn([args.package])
    log(f"SPAWNED {pid}")
    session = device.attach(pid)

    code = open(args.script).read()

    def on_msg(msg, data):
        if msg['type'] == 'send':
            log(msg['payload'])
        elif msg['type'] == 'error':
            log(f"ERROR: {msg}")

    script = session.create_script(code)
    script.on('message', on_msg)
    script.load()
    log("SCRIPT_LOADED")
    device.resume(pid)
    log(f"RESUMED (waiting {args.timeout}s)")

    for i in range(args.timeout):
        time.sleep(1)

    log("TIMEOUT")
    session.detach()
    log("DETACHED")
    print(f"Done. Results in {out_path}")


if __name__ == "__main__":
    main()
