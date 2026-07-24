# traceMiku 定制 Frida Runtime

本目录保存当前真机采集依赖的 Frida 17.9.11 arm64 runtime、补丁、校验和及构建脚本。
`miku-trace-server-17.9.11` 是当前安装流程的运行资产，不是可随意删除的缓存。

## 补丁范围

- Frida Gum Stalker literal-pool overflow 修复。
- Android 14 code slab 分配失败的回退路径。
- 常见 Frida 字符串、服务名和路径特征调整。
- 保留 `frida_agent_main` ABI 符号，避免 Vala 生成代码和 export file 不一致。

补丁只解决已验证的采集故障，不保证绕过所有检测。完整边界见
`docs/anti-detection-catalog.md`。

## 安装现有产物

```bash
cd vendor/frida-patched
sha256sum -c SHA256SUMS
./install-stealth.sh
```

脚本将 server 推送到设备私有路径并配置非默认端口。主机端 `frida-python` 和
`frida-tools` 使用官方版本，通信协议未修改。

## 从源码构建

Linux 使用 `build-from-source.sh`，macOS 使用 `build-from-source-mac.sh`。构建需要与
17.9.11 对应的 Frida 源码和 Android NDK。生成新二进制后必须：

1. 更新 `SHA256SUMS` 和本文件版本说明。
2. 在普通目标验证 attach、spawn、短 trace 和完整收尾。
3. 运行 `make test-device`。
4. 在已知高强度目标验证 Stalker 和反检测，但不能只用单一目标作为回归标准。

二进制与主机包版本不一致时可能出现协议或能力错误，升级必须作为独立变更处理。
