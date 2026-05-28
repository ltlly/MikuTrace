#!/usr/bin/env bash
# 从源码构建 frida-server-android-arm64 (macOS host, cross-compile)
#
# 集成 patches:
#   1. codeslab fallback (gummemory-posix.c) — 解决高位 ASLR 下 code slab 分配失败
#   2. literal pool overflow fix (gumstalker-arm64.c, gumstalker-arm.c) — PR#1113
#   3. anti-detect rename (frida→miku) — 字符串/线程名/路径重命名
#   4. strongR/Florida anti-detection patches (frida-core) — 协议/符号/maps 反检测
#
# 用法:
#   ./build-from-source-mac.sh            完整流程: clone + NDK + patch + build
#   ./build-from-source-mac.sh patch      只 patch
#   ./build-from-source-mac.sh make       只 (重新)编译
#   ./build-from-source-mac.sh clean      删 build artifact, 保留源码 + NDK
#   ./build-from-source-mac.sh distclean  删一切
#
# 工作目录: 仓库根/build/frida-build/  (gitignored)
# 输出: vendor/frida-patched/miku-trace-server-<version>
#
# 前置条件: meson, ninja, go ≥ 1.24, node, npm, git, patch
# 代理: export https_proxy=http://127.0.0.1:7897 等

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$REPO/build/frida-build"
FRIDA_DIR="$WORK/frida"
FRIDA_VERSION="17.9.11"

# NDK — macOS ARM64
NDK_VER="r27c"
NDK_URL="https://dl.google.com/android/repository/android-ndk-${NDK_VER}-darwin.dmg"
NDK_DIR="$WORK/ndk/android-ndk-${NDK_VER}"

# 你的 frida-gum fork (含 PR#1113 fix)
GUM_FORK_REPO="https://github.com/ltlly/frida-gum.git"
GUM_FORK_BRANCH="fix/stalker-arm64-literal-pool-overflow"

# Florida patches repo
FLORIDA_REPO="https://github.com/Ylarod/Florida.git"

OUTPUT_NAME="miku-trace-server-${FRIDA_VERSION}"
OUTPUT="$HERE/$OUTPUT_NAME"

CMD="${1:-all}"

# ─── 代理设置 ───
setup_proxy () {
  if [ -n "$https_proxy" ] || [ -n "$HTTP_PROXY" ]; then
    echo "[+] 代理已设置: ${https_proxy:-$HTTP_PROXY}"
  else
    # 尝试默认代理
    if curl -s --connect-timeout 2 -x http://127.0.0.1:7897 https://github.com > /dev/null 2>&1; then
      export https_proxy=http://127.0.0.1:7897
      export http_proxy=http://127.0.0.1:7897
      export all_proxy=socks5://127.0.0.1:7897
      echo "[+] 自动检测到代理 127.0.0.1:7897"
    fi
  fi
}

ensure_tools () {
  local missing=()
  for t in git patch meson ninja go node npm; do
    command -v "$t" >/dev/null || missing+=("$t")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "[!] 缺少工具: ${missing[*]}"
    echo "    brew install ${missing[*]}"
    exit 1
  fi
  echo "[+] 工具链 OK: meson $(meson --version), ninja $(ninja --version), $(go version | cut -d' ' -f3)"
}

ensure_workdir () {
  mkdir -p "$WORK"
}

ensure_ndk () {
  if [ -f "$NDK_DIR/source.properties" ]; then
    echo "[+] NDK $(grep 'Pkg.Revision' "$NDK_DIR/source.properties" | sed 's/.*= *//') ✓"
    return
  fi

  # 尝试 homebrew NDK
  local brew_ndk="/opt/homebrew/share/android-ndk"
  if [ -d "$brew_ndk" ] && [ -f "$brew_ndk/source.properties" ]; then
    echo "[+] 使用 Homebrew NDK: $brew_ndk"
    mkdir -p "$WORK/ndk"
    ln -sf "$brew_ndk" "$NDK_DIR"
    return
  fi

  # 检查系统 NDK
  if [ -n "$ANDROID_NDK_ROOT" ] && [ -d "$ANDROID_NDK_ROOT" ]; then
    echo "[+] 使用环境变量 NDK: $ANDROID_NDK_ROOT"
    mkdir -p "$WORK/ndk"
    ln -sf "$ANDROID_NDK_ROOT" "$NDK_DIR"
    return
  fi

  echo "[*] 下载 NDK $NDK_VER (~1.5GB DMG)"
  mkdir -p "$WORK/ndk"
  local dmg="$WORK/ndk/ndk.dmg"
  if [ ! -f "$dmg" ]; then
    curl -fL --progress-bar -o "$dmg" "$NDK_URL"
  fi
  echo "[*] 挂载 DMG 并提取 NDK"
  local mount_point="/tmp/ndk-mount-$$"
  mkdir -p "$mount_point"
  hdiutil attach "$dmg" -mountpoint "$mount_point" -nobrowse -quiet
  cp -R "$mount_point/AndroidNDK"*".app/Contents/NDK" "$NDK_DIR" 2>/dev/null || \
    cp -R "$mount_point/android-ndk-"* "$NDK_DIR" 2>/dev/null || \
    { echo "[!] DMG 结构不符预期"; hdiutil detach "$mount_point" -quiet; exit 1; }
  hdiutil detach "$mount_point" -quiet
  rm -rf "$mount_point"
  echo "[+] NDK 提取完成: $NDK_DIR"
}

ensure_source () {
  if [ ! -d "$FRIDA_DIR" ]; then
    echo "[*] Clone frida (tag $FRIDA_VERSION, --depth 1)"
    git clone --depth 1 --branch "$FRIDA_VERSION" \
      https://github.com/frida/frida.git "$FRIDA_DIR"
  fi

  echo "[*] 初始化 submodules (frida-gum + frida-core)"
  cd "$FRIDA_DIR"
  git submodule update --init --recursive --depth 1 subprojects/frida-gum 2>/dev/null || true
  git submodule update --init --recursive --depth 1 subprojects/frida-core 2>/dev/null || true

  # 确保 submodule 存在
  [ -d "$FRIDA_DIR/subprojects/frida-gum/gum" ] || {
    echo "[!] frida-gum submodule 初始化失败"
    exit 1
  }
  [ -d "$FRIDA_DIR/subprojects/frida-core/src" ] || {
    echo "[!] frida-core submodule 初始化失败"
    exit 1
  }
}

# ─── 替换 frida-gum 为我们的 fork (含 PR#1113 fix) ───
apply_gum_fork () {
  local gum_dir="$FRIDA_DIR/subprojects/frida-gum"
  echo "[*] 替换 frida-gum 为 fork (含 literal pool overflow fix)"

  cd "$gum_dir"
  # 检查是否已经应用
  if git log --oneline -1 | grep -q "literal pool"; then
    echo "  [✓] frida-gum fork 已应用"
    return
  fi

  # 添加 fork remote 并 fetch
  git remote get-url fork >/dev/null 2>&1 || \
    git remote add fork "$GUM_FORK_REPO"
  git fetch fork "$GUM_FORK_BRANCH" --depth 5
  git checkout "fork/$GUM_FORK_BRANCH" -- . 2>/dev/null || \
    git reset --hard "fork/$GUM_FORK_BRANCH"
  echo "  [✓] 已切换到 fork/$GUM_FORK_BRANCH"
}

# ─── 应用 codeslab fallback patch ───
apply_codeslab_patch () {
  local gum_dir="$FRIDA_DIR/subprojects/frida-gum"
  echo "[*] 应用 codeslab fallback patch"

  if grep -q 'MikuTrace patch' "$gum_dir/gum/backend-posix/gummemory-posix.c" 2>/dev/null; then
    echo "  [✓] codeslab patch 已应用"
    return
  fi

  patch -p1 -d "$gum_dir" < "$HERE/gummemory-posix.patch"
  echo "  [✓] codeslab fallback patch 应用成功"
}

# ─── 应用 is_out_of_space length>0 修复 ───
apply_length_check_fix () {
  local stalker="$FRIDA_DIR/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c"
  echo "[*] 应用 is_out_of_space literal_refs.length > 0 check"

  if grep -q 'literal_refs.data != NULL && cw->literal_refs.length > 0' "$stalker" 2>/dev/null; then
    echo "  [✓] length check 已应用"
    return
  fi

  # 如果只有 data != NULL 没有 length > 0, 修补
  if grep -q 'literal_refs.data != NULL' "$stalker" 2>/dev/null; then
    sed -i '' 's/if (cw->literal_refs.data != NULL)/if (cw->literal_refs.data != NULL \&\& cw->literal_refs.length > 0)/' "$stalker"
    echo "  [✓] 已添加 length > 0 check"
  else
    echo "  [!] 未找到需要修补的位置 (可能 fork 版本已包含)"
  fi
}

# ─── 应用反检测重命名 (已有脚本) ───
apply_anti_detect_rename () {
  echo "[*] 应用 anti-detect 重命名 (frida→miku)"
  bash "$HERE/anti-detect-rename.sh" "$FRIDA_DIR"
}

# ─── 获取并应用 Florida/strongR patches (frida-core) ───
apply_florida_patches () {
  local patches_dir="$WORK/florida-patches"
  local core_dir="$FRIDA_DIR/subprojects/frida-core"

  echo "[*] 获取 Florida anti-detection patches"

  if [ ! -d "$patches_dir" ]; then
    git clone --depth 1 "$FLORIDA_REPO" "$patches_dir" 2>/dev/null || {
      echo "  [!] 无法 clone Florida repo, 使用已有的 anti-detect-rename.sh 替代"
      return
    }
  fi

  # 应用 frida-core patches (跳过已有的重命名类 patch, 只取增量)
  cd "$core_dir"

  # 0001: frida:rpc 字符串混淆 (Base64 编码)
  local rpc_patch="$patches_dir/patches/frida-core/0001-Florida-string_frida_rpc.patch"
  if [ -f "$rpc_patch" ]; then
    if ! grep -q 'Base64.decode\|decode_hex_xor' "$core_dir/lib/base/rpc.vala" 2>/dev/null && \
       ! grep -q 'Base64.decode\|decode_hex_xor' "$core_dir/lib/interfaces/session.vala" 2>/dev/null; then
      echo "  [*] 应用 0001: frida:rpc 字符串混淆"
      git am "$rpc_patch" 2>/dev/null || git apply "$rpc_patch" 2>/dev/null || {
        echo "  [!] 0001 patch 无法直接应用, 手动处理 frida:rpc 混淆"
        # 手动实现: session.vala 或 rpc.vala 中的 "frida:rpc" → Base64 解码
        for vf in lib/base/rpc.vala lib/interfaces/session.vala; do
          if [ -f "$vf" ] && grep -q '"frida:rpc"' "$vf"; then
            sed -i '' 's/"frida:rpc"/(string) GLib.Base64.decode ("ZnJpZGE6cnBj")/' "$vf"
            echo "    [✓] $vf: frida:rpc → Base64 decode"
          fi
        done
      }
    else
      echo "  [✓] 0001 frida:rpc 混淆已应用"
    fi
  fi

  # 0003: pipe_linjector — linjector FIFO 路径去特征
  local pipe_patch="$patches_dir/patches/frida-core/0003-Florida-pipe_linjector.patch"
  if [ -f "$pipe_patch" ]; then
    echo "  [*] 尝试应用 0003: linjector pipe 路径去特征"
    git apply "$pipe_patch" 2>/dev/null && echo "    [✓] 0003 OK" || echo "    [!] 0003 跳过 (冲突或已包含)"
  fi

  # 0006: protocol_unexpected_command — 协议指纹
  local proto_patch="$patches_dir/patches/frida-core/0006-Florida-protocol_unexpected_command.patch"
  if [ -f "$proto_patch" ]; then
    echo "  [*] 尝试应用 0006: 协议指纹消除"
    git apply "$proto_patch" 2>/dev/null && echo "    [✓] 0006 OK" || echo "    [!] 0006 跳过 (冲突或已包含)"
  fi

  # 0009: memfd 名称
  local memfd_patch="$patches_dir/patches/frida-core/0009-Florida-memfd-name-jit-cache.patch"
  if [ -f "$memfd_patch" ]; then
    echo "  [*] 尝试应用 0009: memfd 名称伪装"
    git apply "$memfd_patch" 2>/dev/null && echo "    [✓] 0009 OK" || echo "    [!] 0009 跳过 (冲突或已包含)"
  fi

  echo "[+] Florida patches 处理完毕"
}

# ─── 手动应用核心反检测 (如 Florida clone 失败时的 fallback) ───
apply_manual_anti_detect () {
  local core_dir="$FRIDA_DIR/subprojects/frida-core"
  echo "[*] 手动应用核心反检测修改 (fallback)"

  # frida:rpc 混淆
  for vf in "$core_dir/lib/base/rpc.vala" "$core_dir/lib/interfaces/session.vala"; do
    if [ -f "$vf" ] && grep -q '"frida:rpc"' "$vf"; then
      sed -i '' 's/"frida:rpc"/(string) GLib.Base64.decode ("ZnJpZGE6cnBj")/' "$vf"
      echo "  [✓] frida:rpc → Base64: $(basename "$vf")"
    fi
  done

  # frida_agent_main → main
  for vf in $(grep -rl 'frida_agent_main' "$core_dir/src/" 2>/dev/null); do
    sed -i '' 's/"frida_agent_main"/"main"/g' "$vf"
    echo "  [✓] frida_agent_main → main: $(basename "$vf")"
  done

  # linjector pipe 路径
  local helper_backend="$core_dir/src/linux/frida-helper-backend.c"
  if [ -f "$helper_backend" ] && grep -q '/linjector' "$helper_backend"; then
    sed -i '' 's|/linjector-%u|/%p%u|g' "$helper_backend"
    echo "  [✓] linjector pipe → 去特征路径"
  fi

  # frida-agent SO 随机名
  local linux_session="$core_dir/src/linux/linux-host-session.vala"
  if [ -f "$linux_session" ] && grep -q 'frida-agent-' "$linux_session"; then
    sed -i '' 's/"frida-agent-" + arch + ".so"/GLib.Uuid.string_random () + ".so"/' "$linux_session" 2>/dev/null || true
    echo "  [✓] frida-agent SO → UUID 随机名"
  fi
}

do_configure () {
  cd "$FRIDA_DIR"
  export ANDROID_NDK_ROOT="$NDK_DIR"
  echo "[*] ./configure --host=android-arm64"
  python3 configure.py --host=android-arm64 \
    --enable-server \
    --disable-gadget \
    --disable-inject \
    --without-prebuilds=sdk:host 2>&1 | tail -5 || \
  ./configure --host=android-arm64 \
    --enable-server \
    --disable-gadget \
    --disable-inject 2>&1 | tail -5
}

do_make () {
  cd "$FRIDA_DIR"
  export ANDROID_NDK_ROOT="$NDK_DIR"
  export GOPROXY="${GOPROXY:-https://goproxy.io,direct}"

  local jobs
  jobs=$(sysctl -n hw.logicalcpu 2>/dev/null || echo 8)
  echo "[*] make -j$jobs (this takes 20-60 min)"
  make -j"$jobs" 2>&1 | tail -20

  local out="$FRIDA_DIR/build/subprojects/frida-core/server/frida-server"
  [ -f "$out" ] || out="$FRIDA_DIR/build/frida-android-arm64/subprojects/frida-core/server/frida-server"
  [ -f "$out" ] || { echo "[!] 找不到编译产物, 列出 build 目录:"; find "$FRIDA_DIR/build" -name "frida-server" 2>/dev/null; exit 1; }

  cp "$out" "$OUTPUT"
  chmod 755 "$OUTPUT"
  echo "[+] 输出: $OUTPUT ($(du -sh "$OUTPUT" | cut -f1))"
  shasum -a 256 "$OUTPUT"
}

apply_all_patches () {
  apply_gum_fork
  apply_codeslab_patch
  apply_length_check_fix
  apply_anti_detect_rename
  apply_florida_patches
  # 如果 Florida clone 失败, fallback 到手动
  if [ ! -d "$WORK/florida-patches" ]; then
    apply_manual_anti_detect
  fi
}

# ─── dispatch ───
setup_proxy

case "$CMD" in
  patch)
    ensure_workdir; ensure_source; apply_all_patches ;;
  configure)
    ensure_tools; ensure_workdir; ensure_source; ensure_ndk; do_configure ;;
  make)
    ensure_tools; ensure_workdir; ensure_ndk; do_make ;;
  clean)
    rm -rf "$FRIDA_DIR/build" ;;
  distclean)
    rm -rf "$WORK" ;;
  all|"")
    ensure_tools
    ensure_workdir
    setup_proxy
    ensure_source
    ensure_ndk
    apply_all_patches
    do_configure
    do_make
    echo
    echo "[+] ========================================"
    echo "[+] 构建完成: $OUTPUT"
    echo "[+] 集成 patches:"
    echo "[+]   1. codeslab fallback (高位 ASLR 修复)"
    echo "[+]   2. literal pool overflow fix (PR#1113)"
    echo "[+]   3. anti-detect rename (frida→miku)"
    echo "[+]   4. Florida/strongR patches (协议/符号/maps)"
    echo "[+] ========================================"
    ;;
  *)
    echo "用法: $0 [patch|configure|make|clean|distclean|all]"
    exit 1
    ;;
esac
echo "[+] 完成: $CMD"
