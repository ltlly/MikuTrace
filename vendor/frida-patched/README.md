# 定制 Frida Runtime

本目录包含 Frida 17.9.11 arm64 server、补丁和校验和。补丁涉及 Stalker literal-pool
溢出、Android 14 code slab 分配回退及部分字符串/路径指纹；保留 `frida_agent_main` ABI。

```bash
cd vendor/frida-patched
sha256sum -c SHA256SUMS
./install-stealth.sh
```

安装到 `/data/local/tmp/.miku-srv`；本地默认端口 6699 转发设备 27042，脚本要求 adb shell 已有 root。host 使用官方 Frida Python 包。
Linux 构建用 `build-from-source.sh`，macOS 用 `build-from-source-mac.sh`，依赖对应
版本源码与 Android NDK。更新产物须同步校验和并通过 `make test-device`，覆盖
attach、spawn、短 trace 和收尾。边界见 [采集诊断](../../docs/anti-detection-catalog.md)。
