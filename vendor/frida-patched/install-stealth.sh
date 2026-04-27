#!/usr/bin/env bash
# 安装 stealth frida-server (含 codeslab fallback + anti-detect 重命名) 到设备
# 与 install.sh (基础 patched 版) 区别:
#   - 推到 /data/local/tmp/.miku-srv (隐藏文件, 文件名无 "frida")
#   - process cmdline = ".miku-srv", thread comm 全是 miku-* (server prgname 已改)
#   - target 进程内 frida-agent.so 注入后, gum-js-loop → miku-js-loop
#
# 用法:
#   ./install-stealth.sh         默认 forward 6699
#   ./install-stealth.sh 6688    自定义本地端口

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/frida-server-17-stealth"
PORT="${1:-6699}"
DEVICE_PATH="/data/local/tmp/.miku-srv"

[ -f "$BIN" ] || { echo "[!] $BIN 不存在; 先 ./build-from-source.sh"; exit 1; }

echo "[*] 校验"
if command -v sha256sum >/dev/null && [ -f "$HERE/SHA256SUMS" ]; then
  ( cd "$HERE" && sha256sum -c --quiet --ignore-missing SHA256SUMS ) \
    || { echo "[!] SHA256 mismatch — binary 可能损坏或被篡改"; exit 1; }
fi

echo "[*] 检查 adb root"
if ! adb shell 'id' | grep -q 'uid=0'; then
  echo "[!] adb 不是 root. 试 'adb root' 或确认设备已 root."
  exit 1
fi

echo "[*] killall 旧 frida/miku server"
adb shell 'killall frida-server frida-server-17 frida-server-17-patched frida-server-17-stealth .miku-srv miku 2>/dev/null' || true
sleep 1

echo "[*] 推送 $BIN → 设备 $DEVICE_PATH"
adb push "$BIN" "$DEVICE_PATH"
adb shell "chmod 755 $DEVICE_PATH"

echo "[*] 启动 stealth server"
adb shell "nohup $DEVICE_PATH </dev/null >/dev/null 2>&1 &" >/dev/null
sleep 3

echo "[*] adb forward tcp:$PORT → tcp:27042"
adb forward tcp:$PORT tcp:27042

echo "[*] 验证: 进程"
adb shell "pgrep -af '$DEVICE_PATH' | head -3"

echo "[*] 验证: cmdline (应仅含 .miku-srv, 无 frida)"
PID=$(adb shell "pgrep -f '$DEVICE_PATH' | head -1" | tr -d '\r')
if [ -n "$PID" ]; then
  adb shell "echo -n 'cmdline: '; tr '\0' ' ' < /proc/$PID/cmdline; echo; echo -n 'comm: '; cat /proc/$PID/comm"
else
  echo "[!] 找不到 server 进程 — 启动失败?"
  exit 2
fi

echo "[*] 验证: host frida-ps -H 127.0.0.1:$PORT"
if command -v frida-ps >/dev/null; then
  frida-ps -H "127.0.0.1:$PORT" 2>&1 | head -5
else
  echo "  (host 缺 frida-ps; pip install frida-tools)"
fi

echo
echo "[+] 完成. 用法:"
echo "    frida-ps -H 127.0.0.1:$PORT"
echo "    frida -H 127.0.0.1:$PORT -p <pid> -l script.js"
echo "    ./tracemiku trace --remote 127.0.0.1:$PORT --pkg ... --so ... --fn-offset ..."
