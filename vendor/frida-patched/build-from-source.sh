#!/usr/bin/env bash
# 从源码构建 frida-server-android-arm64 (codeslab fallback + anti-detect 重命名)
#
# 用法:
#   ./build-from-source.sh            完整流程: clone + NDK + patch + build (~30-60min cold)
#   ./build-from-source.sh patch      只 patch (要求 ./build/frida-build/frida 已存在)
#   ./build-from-source.sh make       只 (重新)编译 (要求已 configure)
#   ./build-from-source.sh clean      删 build artifact, 保留源码 + NDK
#
# 工作目录: 仓库根/build/frida-build/  (gitignored)
#   ├── frida/                    frida 源码 (--depth 1)
#   ├── ndk/android-ndk-r29/      NDK r29.x  (frida 17.9 强制)
#   └── ndk.zip                   下载缓存
#
# 输出: vendor/frida-patched/frida-server-17-stealth
#
# 前置条件:
#   - meson + ninja (脚本会用 pip --user 装)
#   - go (frida-compiler-backend 需要; Ubuntu: apt install golang)
#   - patch, unzip, curl

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$REPO/build/frida-build"
NDK_VER="r29"
NDK_URL="https://dl.google.com/android/repository/android-ndk-${NDK_VER}-linux.zip"
NDK_DIR="$WORK/ndk/android-ndk-${NDK_VER}"
FRIDA_DIR="$WORK/frida"
OUTPUT="$HERE/frida-server-17-stealth"

CMD="${1:-all}"

ensure_tools () {
  for t in patch unzip curl git; do
    command -v "$t" >/dev/null || { echo "[!] 缺 $t (apt install $t)"; exit 1; }
  done
  if ! command -v meson >/dev/null || ! command -v ninja >/dev/null; then
    echo "[*] 装 meson + ninja"
    pip install --user --quiet meson ninja
    export PATH="$HOME/.local/bin:$PATH"
  fi
  command -v go >/dev/null || { echo "[!] 缺 go (frida-compiler-backend 需要; sudo apt install golang)"; exit 1; }
}

ensure_workdir () {
  mkdir -p "$WORK"
}

ensure_ndk () {
  if [ -f "$NDK_DIR/source.properties" ]; then
    local ver
    ver=$(grep -m1 'Pkg.Revision' "$NDK_DIR/source.properties" | sed 's/Pkg.Revision *= *//')
    [ "${ver%%.*}" = "29" ] || { echo "[!] NDK 主版本 ${ver%%.*} != 29 (frida 17.9 强制 r29)"; exit 1; }
    echo "[+] NDK $ver ✓"
    return
  fi
  if [ ! -f "$WORK/ndk.zip" ]; then
    echo "[*] 下载 NDK $NDK_VER (~780MB)"
    curl -fL --progress-bar -o "$WORK/ndk.zip" "$NDK_URL"
  fi
  echo "[*] 解压 NDK"
  mkdir -p "$WORK/ndk"
  ( cd "$WORK/ndk" && unzip -q "$WORK/ndk.zip" )
  [ -d "$NDK_DIR" ] || { echo "[!] 解压后 $NDK_DIR 不存在"; exit 1; }
}

ensure_source () {
  if [ ! -d "$FRIDA_DIR" ]; then
    echo "[*] clone frida (--depth 1, ~2GB)"
    git clone --depth 1 https://github.com/frida/frida.git "$FRIDA_DIR"
  fi
  if [ ! -d "$FRIDA_DIR/subprojects/frida-gum/gum" ] || [ ! -d "$FRIDA_DIR/subprojects/frida-core/src" ]; then
    echo "[*] init submodule frida-gum + frida-core"
    ( cd "$FRIDA_DIR" && git submodule update --init --recursive --depth 1 subprojects/frida-gum subprojects/frida-core )
  fi
}

apply_patches () {
  echo "[*] 1/2: codeslab fallback patch"
  if grep -q 'MikuTrace patch' "$FRIDA_DIR/subprojects/frida-gum/gum/backend-posix/gummemory-posix.c" 2>/dev/null; then
    echo "  [✓] 已应用 (检测到 MikuTrace patch 标记)"
  else
    patch -p1 -d "$FRIDA_DIR/subprojects/frida-gum" < "$HERE/gummemory-posix.patch"
  fi
  echo "[*] 2/2: anti-detect 重命名"
  bash "$HERE/anti-detect-rename.sh" "$FRIDA_DIR"
}

prewarm_go_modules () {
  # frida-compiler-backend 拉 typescript-go + esbuild; proxy.golang.org 国内常 timeout.
  # 用 goproxy.cn 镜像预热 cache, 避免 build-backend.py 用 config.env 屏蔽 GOPROXY 后失败.
  if [ -f "$FRIDA_DIR/subprojects/frida-core/src/compiler/go.mod" ]; then
    if ls ~/go/pkg/mod/cache/download/github.com/frida/typescript-go/@v/v0.*.zip 2>/dev/null | head -1 | grep -q .; then
      echo "[+] Go module cache 已暖 ✓"
    else
      echo "[*] 预热 Go module cache (国内网络 fallback)"
      ( cd "$FRIDA_DIR/subprojects/frida-core/src/compiler" && \
        GOPROXY=https://goproxy.cn,https://goproxy.io,direct GOSUMDB=sum.golang.google.cn go mod download )
    fi
  fi
}

do_configure () {
  cd "$FRIDA_DIR"
  export ANDROID_NDK_ROOT="$NDK_DIR"
  echo "[*] ./configure --host=android-arm64 (server only)"
  ./configure --host=android-arm64 \
              --enable-server \
              --disable-frida-tools \
              --disable-frida-python \
              --disable-gadget \
              --disable-inject \
              --disable-graft-tool
}

do_make () {
  cd "$FRIDA_DIR"
  export ANDROID_NDK_ROOT="$NDK_DIR"
  : "${GOPROXY:=https://goproxy.cn,https://goproxy.io,direct}"
  export GOPROXY
  echo "[*] make -j$(nproc)"
  make -j"$(nproc)"
  local out="$FRIDA_DIR/build/subprojects/frida-core/server/frida-server"
  [ -f "$out" ] || { echo "[!] $out 不存在"; exit 1; }
  cp "$out" "$OUTPUT"
  ( cd "$HERE" && sha256sum "$(basename "$OUTPUT")" > .stealth.sha )
  # 刷新 SHA256SUMS (保留其他条目)
  if [ -f "$HERE/SHA256SUMS" ]; then
    grep -v "$(basename "$OUTPUT")" "$HERE/SHA256SUMS" > "$HERE/.SHA256SUMS.new" || true
    cat "$HERE/.stealth.sha" >> "$HERE/.SHA256SUMS.new"
    mv "$HERE/.SHA256SUMS.new" "$HERE/SHA256SUMS"
    rm -f "$HERE/.stealth.sha"
  fi
  echo "[+] 输出: $OUTPUT"
  ls -la "$OUTPUT"
}

# ─── dispatch ───
case "$CMD" in
  patch)
    ensure_workdir; ensure_source; apply_patches ;;
  configure)
    ensure_tools; ensure_workdir; ensure_source; ensure_ndk; do_configure ;;
  make)
    ensure_tools; ensure_workdir; ensure_ndk; prewarm_go_modules; do_make ;;
  clean)
    rm -rf "$FRIDA_DIR/build" ;;
  distclean)
    rm -rf "$WORK" ;;
  all|"")
    ensure_tools
    ensure_workdir
    ensure_source
    ensure_ndk
    apply_patches
    prewarm_go_modules
    do_configure
    do_make
    ;;
  *)
    echo "未知命令: $CMD"
    echo "用法: $0 [patch|configure|make|clean|distclean|all]"
    exit 1
    ;;
esac
echo "[+] 完成: $CMD"
