#!/usr/bin/env bash
# 安装 patched frida-server-17 (含 code slab fallback) 到设备
# 详见 ../../docs/frida-codeslab-patch.md

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/frida-server-17-patched"
PORT="${1:-6699}"

[ -f "$BIN" ] || { echo "[!] $BIN 不存在, 先 build (见 docs/frida-codeslab-patch.md)"; exit 1; }

echo "[*] 推送 $BIN → 设备"
adb push "$BIN" /data/local/tmp/frida-server-17-patched

echo "[*] 设权限"
adb shell 'su -c "chmod 755 /data/local/tmp/frida-server-17-patched"'

echo "[*] 关闭旧 frida-server (任意版本)"
adb shell 'su -c "killall frida-server-17 frida-server-17-patched frida-server-16 frida-server-test frida-server 2>/dev/null"' || true
sleep 1

echo "[*] 启动 patched frida-server"
adb shell 'nohup su -c "/data/local/tmp/frida-server-17-patched" </dev/null >/dev/null 2>&1 &' &
sleep 3

echo "[*] adb forward tcp:$PORT → tcp:27042"
adb forward tcp:$PORT tcp:27042

echo "[*] 验证"
adb shell 'su -c "ps -ef | grep frida-server-17-patched | grep -v grep"'
echo "[*] 测试 frida-ps:"
frida-ps -H 127.0.0.1:$PORT 2>&1 | head -3
