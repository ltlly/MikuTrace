# vendor/frida-patched

Patched `frida-server` for Android arm64 — 解决 stock frida 17.x 在 Android 14+
+ ASLR 高位 + OLLVM 大库 trace 时 `Unable to allocate code slab` SIGTRAP 问题.

## 文件

| 文件 | 说明 |
|---|---|
| `frida-server-17-patched` | Android arm64 ELF, 53MB, frida 17.9.x + 本仓 patch |
| `gummemory-posix.patch`   | 单文件 diff, 应用到 frida-gum master |
| `install.sh`              | adb push + 启动 + forward 一键脚本 |
| `SHA256SUMS`              | 完整性校验 |

## 用法

```bash
./install.sh           # 默认 forward 6699
./install.sh 6688      # 自定义端口
```

执行后:
- 推送 `frida-server-17-patched` → `/data/local/tmp/`
- killall 任何老 frida-server
- 启动 patched server (root 后台)
- adb forward tcp:N → tcp:27042
- frida-ps -H 127.0.0.1:N 验证

## 自己重编

详细步骤见 [`../../docs/frida-codeslab-patch.md`](../../docs/frida-codeslab-patch.md).

要点:
1. clone frida (`git submodule update --init --recursive subprojects/frida-gum subprojects/frida-core`)
2. `patch -p1 -d subprojects/frida-gum < gummemory-posix.patch`
3. `export ANDROID_NDK_ROOT=/path/to/ndk-r29 MACOS_CERTID=- IOS_CERTID=-`
4. `./configure --host=android-arm64 --enable-server --disable-frida-tools --disable-frida-python --disable-gadget --disable-inject`
5. `make`
6. 产物: `build/subprojects/frida-core/server/frida-server`

## 兼容性

- 测试设备: Pixel 7 (Tensor G2), Android 16 (CP1A.260305.018, SDK 36)
- frida-gum upstream commit: `7f71906ab428b2198aefc9aa5ae3c153d8d6e56a`
- 应该兼容所有 Android 12+ arm64 设备 (patch 路径在 backend-posix, 不依赖特定内核)
- 不影响 stock frida 行为: fallback 仅在原 near-allocation 彻底失败时启用
