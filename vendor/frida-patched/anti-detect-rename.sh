#!/usr/bin/env bash
# 重命名 frida 在 target 进程内可见的字符串/线程名/路径 → "miku" 主题。
#
# 用法:
#   ./anti-detect-rename.sh <frida-source-dir>
# 默认 frida 源码目录: ../../build/frida-build/frida (build-from-source.sh 工作区)
#
# 不动:
#   - re.frida.*  D-Bus interface 名 (wire protocol, host 端 stock frida 依赖)
#   - "frida:rpc"                    (wire protocol)
#   - frida_agent_main 符号           (.symbols/.version/.def 多文件改, 留 v2)
#   - frida-agent-{arch}.so 文件名    (meson 输出, 留 v2)
#
# 动:
#   1. g_set_prgname("frida")          → ("miku")
#   2. "frida-main-loop" 线程名         → "miku-main-loop"   (15 chars OK)
#   3. "frida-agent-container"          → "miku-agent-cont"  (≤15 chars 等长)
#   4. "gum-js-loop"                    → "miku-js-loop"
#   5. "frida-gadget" 线程名 (gadget)   → "miku-gadget"
#   6. "frida-helper-main-loop" Darwin  → "miku-helper-main"
#   7. "re.frida.server" 默认 unix dir  → "re.miku.server"
#   8. droidy "frida:" socket prefix    → "miku:"
#   9. /data/local/tmp/frida-helper-    → /data/local/tmp/miku-helper-
#  10. /data/local/tmp/frida-gadget-    → /data/local/tmp/miku-gadget-
#  11. android-helper LocalSocket "/frida-helper-" → "/miku-helper-"
#  12. nice-name "re.frida.helper"     → "re.miku.helper"
#
# Idempotent: 重复跑也不会爆。
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
FRIDA_SRC="${1:-$HERE/../../build/frida-build/frida}"
[ -d "$FRIDA_SRC" ] || { echo "[!] frida 源码目录 $FRIDA_SRC 不存在 — 给参数 1 或先跑 build-from-source.sh"; exit 1; }
cd "$FRIDA_SRC"
[ -d subprojects/frida-gum ] || { echo "[!] $FRIDA_SRC/subprojects/frida-gum 不存在 — 先 git submodule update --init --recursive subprojects/frida-gum subprojects/frida-core"; exit 1; }
[ -d subprojects/frida-core ] || { echo "[!] $FRIDA_SRC/subprojects/frida-core 不存在"; exit 1; }

GUM=subprojects/frida-gum
CORE=subprojects/frida-core

apply_sed () {
  local desc="$1" file="$2" pat="$3"
  if [ ! -f "$file" ]; then
    echo "  [!] 跳过 $file (不存在)"
    return
  fi
  local before
  before=$(grep -c "$(echo "$pat" | sed 's|s/||; s|/g$||; s|/[^/]*$||')" "$file" 2>/dev/null || echo 0)
  sed -i "$pat" "$file"
  echo "  [✓] $desc — $file (matches before: $before)"
}

echo "[*] 1. g_set_prgname → miku"
apply_sed 'prgname'         "$GUM/gum/gum.c"                                     's|g_set_prgname ("frida")|g_set_prgname ("miku")|'

echo "[*] 2. frida-main-loop 线程名"
apply_sed 'main-loop thread' "$CORE/src/frida-glue.c"                            's|"frida-main-loop"|"miku-main-loop"|'

echo "[*] 3. frida-agent-container 线程名"
apply_sed 'agent-container'  "$CORE/src/agent-container.vala"                    's|"frida-agent-container"|"miku-agent-cont"|'

echo "[*] 4. gum-js-loop 线程名"
apply_sed 'gum-js-loop'      "$GUM/bindings/gumjs/gumscriptscheduler.c"          's|"gum-js-loop"|"miku-js-loop"|'

echo "[*] 5. frida-gadget 线程名"
apply_sed 'gadget thread'    "$CORE/lib/gadget/gadget-glue.c"                    's|"frida-gadget"|"miku-gadget"|'

echo "[*] 6. frida-helper-main-loop (Darwin)"
apply_sed 'helper main'      "$CORE/src/darwin/frida-helper-service.vala"        's|"frida-helper-main-loop"|"miku-helper-main"|'

echo "[*] 7. re.frida.server 默认 unix dir"
apply_sed 're.frida.server'  "$CORE/server/server.vala"                          's|"re\.frida\.server"|"re.miku.server"|'

echo "[*] 8. droidy injector frida: prefix"
apply_sed 'frida: socket'    "$CORE/src/droidy/injector.vala"                    's|"frida:" + package|"miku:" + package|'

echo "[*] 9-10. /data/local/tmp paths"
for f in "$CORE/src/droidy/droidy-host-session.vala" "$CORE/src/droidy/injector.vala" \
         "$CORE/src/linux/linux-host-session.vala"; do
  apply_sed '/data/local/tmp/frida-helper-' "$f" 's|/data/local/tmp/frida-helper-|/data/local/tmp/miku-helper-|g'
  apply_sed '/data/local/tmp/frida-gadget-' "$f" 's|/data/local/tmp/frida-gadget-|/data/local/tmp/miku-gadget-|g'
done

echo "[*] 11. android-helper Helper.java LocalSocket / dex path"
apply_sed 'Helper.java dex'    "$CORE/src/android-helper/re/frida/Helper.java"   's|/data/local/tmp/frida-helper-|/data/local/tmp/miku-helper-|g'
apply_sed 'Helper.java socket' "$CORE/src/android-helper/re/frida/Helper.java"   's|"/frida-helper-|"/miku-helper-|g'

echo "[*] 12. nice-name re.frida.helper"
apply_sed 'nice-name'        "$CORE/src/droidy/droidy-host-session.vala"         's|--nice-name=re\.frida\.helper|--nice-name=re.miku.helper|'

echo
echo "[+] 验证 (target-side 应只剩 wire-protocol 必需的 frida 字面量):"
echo
echo "[*] gum-js-loop?"
grep -n 'gum-js-loop' "$GUM/bindings/gumjs/gumscriptscheduler.c" || echo "  (清理干净)"
echo "[*] g_set_prgname?"
grep -n 'g_set_prgname' "$GUM/gum/gum.c"
echo "[*] re.frida.server in server.vala?"
grep -n 're\.frida\|re\.miku' "$CORE/server/server.vala"
echo
echo "[+] 完成. 这些 D-Bus 名仍是 frida (wire protocol, 不动): re.frida.HostSession17 等"
