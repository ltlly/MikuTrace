#!/usr/bin/env bash
# tb_launcher.sh — 启动 com.taobao.taobao 并自动处理隐私协议 "同意" 弹窗.
# 用法: ./tracer/tb_launcher.sh [pkg]
#   默认 pkg=com.taobao.taobao
#
# 行为:
#   1. monkey 启动 app
#   2. 轮询 uiautomator dump 找到 "同意" 按钮就 tap
#   3. 等到主界面真正出现 (首页 navigation tab 出现) 才返回
#   4. 返回 0 = 成功, 非 0 = 超时

set -u
PKG="${1:-com.taobao.taobao}"
MAX_WAIT=60        # 总超时秒数
POLL_INTERVAL=2

log() { echo "[tb_launcher] $*" >&2; }

# 1. 启动 app
log "monkey 启动 $PKG"
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1

# 2. 轮询同意按钮
START=$(date +%s)
AGREED=0
HOMED=0
while :; do
  ELAPSED=$(($(date +%s) - START))
  [ "$ELAPSED" -gt "$MAX_WAIT" ] && { log "超时 ${MAX_WAIT}s"; exit 1; }

  PID=$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r')
  if [ -z "$PID" ]; then
    log "进程死了, 重新拉起"
    adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
    sleep 3
    continue
  fi

  # dump UI
  adb shell uiautomator dump /sdcard/_tb_ui.xml >/dev/null 2>&1
  XML=$(adb shell cat /sdcard/_tb_ui.xml 2>/dev/null)

  if [ "$AGREED" = 0 ]; then
    # 找 text="同意" 按钮 bounds
    COORD=$(echo "$XML" | python3 -c '
import sys, re
xml = sys.stdin.read()
# 优先精确匹配 "同意" (不含 "不同意")
for m in re.finditer(r"text=\"同意\"[^>]*?bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"", xml):
    x1,y1,x2,y2 = map(int, m.groups())
    print((x1+x2)//2, (y1+y2)//2); break
' 2>/dev/null)
    if [ -n "$COORD" ]; then
      log "找到同意按钮 @ $COORD, 点击"
      adb shell input tap $COORD
      AGREED=1
      sleep 4
      continue
    fi
  fi

  # 检测主界面: 找 "推荐"/"首页" tab 等首页标志
  if echo "$XML" | grep -qE '(推荐|首页|淘宝直播|消息.*购物车|推荐.*闪购)'; then
    log "首页加载完成 (耗时 ${ELAPSED}s, agreed=$AGREED)"
    HOMED=1
    break
  fi

  log "等待中 ${ELAPSED}s/${MAX_WAIT}s  agreed=$AGREED"
  sleep "$POLL_INTERVAL"
done

[ "$HOMED" = 1 ] || { log "未到首页"; exit 2; }
exit 0
