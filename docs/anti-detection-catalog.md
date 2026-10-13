# 采集诊断与反检测边界

| 实现 | 作用与限制 |
|---|---|
| `tracer/src/anti_detect/hide_rwx_maps.ts` | 过滤 maps 中的 RWX 映射；不覆盖直接 syscall 或其他枚举路径 |
| `tracer/src/anti_detect/block_self_kill.ts` | 拦截自杀信号；内联 SVC 需目标 patch spec |
| spec 驱动 patch | 固定偏移按目标版本配置；只在对应模块条件下使用 |
| [定制 Frida runtime](../vendor/frida-patched/README.md) | Stalker 修复与部分指纹调整 |

插件默认关闭；目标配置位于 `tools/hooks/` 或 `examples/`。使用方法见
[采集命令](FEATURES.md#采集与恢复)。

`doctor` 检查 adb、root、进程和配置，不执行真实注入；检查通过不代表 attach/spawn 成功。
adb 端点使用 `ANDROID_SERIAL` 与 `ANDROID_ADB_SERVER_PORT`（1..65535）。

目标触发的 adb subprocess 失效可使用 Frida 回传；它只改变回传路径，不处理进程自杀、
Frida 断线或内核挂死。已知目标证据见 [libsgmainso](../examples/libsgmainso/README.md)。
