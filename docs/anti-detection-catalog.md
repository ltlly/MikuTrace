# 反调试 / 反 Trace / 反 Frida 手段全目录

> traceMiku 失败案例收集 — 所有已知反检测手段及其对 traceMiku 的影响
> 最后更新: 2026-05-16

## 分类体系

| 层级 | 检测对象 | 手段 | traceMiku 现状 |
|------|---------|------|---------------|
| L1 | ptrace | TracerPid / /proc/self/status | ✅ stealth frida-server 绕过 |
| L2 | 进程内存 | /proc/self/maps rwx 扫描 | ✅ `--hide-rwx-maps` |
| L3 | 进程行为 | fork+ptrace 双进程守护 | ❌ 架构性限制 (需 eBPF) |
| L4 | 代码段 | libart .text CRC / inline hook 检测 | ⚠️ `--trace-deep` 触发 |
| L5 | 符号/库 | frida_agent_main / gadget 扫描 | ❌ 需重 link agent.so |
| L6 | 线程 | gmain / gum-js-loop 线程名 | ⚠️ stealth 已改部分 |
| L7 | 端口/服务 | 27042 端口 / D-Bus name | ✅ 非默认端口 / 无 D-Bus |
| L8 | 时间 | 执行时间异常 (Stalker 减速) | ⚠️ 不可避免, 不影响结果 |
| L9 | 文件 | /data/local/tmp 文件检测 | ✅ 改用 app cache dir |
| L10 | syscall | tgkill/tkill/kill 自杀 | ⚠️ `--patch-suicide` 不完整 |

---

## L1 — ptrace 附着检测

### 手段
```c
// 读取 /proc/self/status 的 TracerPid 字段
FILE *f = fopen("/proc/self/status", "r");
// 若 TracerPid != 0 → 被调试
```

### 变种
- `ptrace(PTRACE_TRACEME, 0, 0, 0)` — 试图自己 ptrace 自己, 失败=已被 trace
- `prctl(PR_SET_DUMPABLE, 0)` — 禁止 ptrace
- `/proc/self/stat` 的 state 字段 (t = tracing stop)

### traceMiku 现状
✅ **已绕过**: stealth frida-server (改过内核特征) + KSU root 免 ptrace 限制

---

## L2 — /proc/self/maps 内存布局检测

### 手段
```c
// 扫描 /proc/self/maps 寻找:
// 1. rwxp 匿名段 → Frida Stalker block cache (8MB)
// 2. frida-agent.so / frida-gadget.so 映射
// 3. 陌生 .so 映射 (对比已知加载列表)
char buf[4096];
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(buf, sizeof(buf), f)) {
    if (strstr(buf, "rwxp") && strstr(buf, "00000000"))
        goto detected;
    if (strstr(buf, "frida"))
        goto detected;
}
```

### traceMiku 现状
✅ `--hide-rwx-maps`: Interceptor hook libc `open/openat/read/pread64`, 过滤 rwxp 行
⚠️ 不覆盖 `readlink` / `fread` / 直接 `readlinkat` 路径 — 高强度反检测可能绕过

---

## L3 — fork 双进程守护 + ptrace

### 手段
```
Parent → fork() → Child
                    ↓
                  ptrace(PTRACE_ATTACH, parent_pid)
                    ↓
                  循环 waitpid 监控 parent
                    ↓
                  若 parent 被其他 ptrace → child 检测到 → kill
```

### traceMiku 现状
❌ **架构性限制**: ptrace-based Frida server 上 attach fork()'d child 全部 `F3 timeout`
   (child 继承 parent 的 ptrace 关系, 无法二次 attach)
🔧 **部分对策**: `--enable-fork-hook` + `--child-trace-mode` (P1-C M1/M2/M3)
   - M1: 抓 fork-event (parent_pc, child_pid)
   - M2: race-attach child (短命 child 50-200ms 抓不到)
   - M3: /proc/<pid>/stat 轮询 child lifecycle
🚀 **根治**: miku-shield (eBPF kernel 层, 无 ptrace 特征)

---

## L4 — 代码段完整性校验 (CRC / inline hook 检测)

### 手段
```
AntiDebugThread (独立线程, 周期 ~1s):
  1. 读取目标 .text 段当前内存字节
  2. 与 /system/lib64/xxx.so 磁盘镜像比对
  3. 或与启动时保存的 CRC/MD5/SHA 比对
  4. 不匹配 → tgkill(main_tid, SIGSEGV)
```

### 触发条件 (traceMiku)
- `--trace-deep` 开启时, Stalker per-symbol exclude libart 在边界放 inline trampoline
- inline trampoline 修改 libart .text → CRC 不匹配 → 自杀

### traceMiku 现状
⚠️ **已知坑** (libsgmainso 6.8.260403): `--trace-deep` → ~60k records → SI_USER
✅ **不用 --trace-deep**: 主流程通跑 (15.4M records)
📄 详细复现: [docs/anti-debug-libart.md](anti-debug-libart.md)
🔧 规划: `--block-self-kill` 拦截 tgkill/tkill/kill/pthread_kill/raise

---

## L5 — 符号 / 库扫描

### 手段
```c
// 1. 扫描 /proc/self/maps 中的 so 列表, 检测陌生库
// 2. dl_iterate_phdr 遍历 linker namespace
// 3. 扫描 libc 函数头是否被 inline hook
// 4. 搜索内存中的 "frida" 字符串
void *handle = dlopen("libc.so", RTLD_NOLOAD);
void *open_ptr = dlsym(handle, "open");
if (*(uint8_t*)open_ptr == 0xFF) // 被 hook
    goto detected;
```

### 关键特征
- `frida_agent_main` symbol (Frida agent entrypoint)
- `frida-gadget.so` / `frida-agent.so` 文件名
- `gum-js-loop` / `gum` 相关字符串
- Frida Interceptor trampoline 特征字节

### traceMiku 现状
⚠️ **部分绕过**: stealth server 改名 `gum-js-loop` → `miku-js-loop`, `pool-frida` → `pool-miku`
❌ **未绕过**: `frida_agent_main` symbol 仍可被扫到 (需重 link agent.so)
❌ **未绕过**: glib 内 `gmain` / `gdbus` 线程名 (glib 内部, 非 frida 特征但可启发式检测)

---

## L6 — 线程名扫描

### 手段
```c
// 读取 /proc/self/task/*/comm 或 /proc/self/task/*/stat
// 检测可疑线程名
DIR *d = opendir("/proc/self/task");
while ((de = readdir(d))) {
    snprintf(path, sizeof(path), "/proc/self/task/%s/comm", de->d_name);
    // 读线程名 → 比对黑名单
}
```

### 检测目标
- `gum-js-loop` → Frida JS 引擎线程
- `gmain` / `gdbus` → GLib 线程 (Frida 内部用 GLib)
- `pool-frida` → Frida 线程池
- `frida-*` 前缀

### traceMiku 现状
⚠️ stealth server 已改 `gum-js-loop` / `pool-frida`
❌ glib `gmain` / `gdbus` 无法改 (非 Frida 代码)

---

## L7 — 端口 / 服务 / IPC 检测

### 手段
```bash
# 1. 扫描本地端口
cat /proc/net/tcp | grep 69B2  # 27042 = 0x69B2

# 2. D-Bus 服务扫描
dbus-send --system --dest=org.freedesktop.DBus \
  --type=method_call /org/freedesktop/DBus \
  org.freedesktop.DBus.ListNames

# 3. netstat / ss
netstat -tlnp | grep frida
```

### traceMiku 现状
✅ USB 连接 (非 TCP) / 非默认端口
✅ 无 D-Bus 暴露

---

## L8 — 时间异常检测

### 手段
```c
// 1. 简单: 比对关键函数执行时间
clock_gettime(CLOCK_MONOTONIC, &start);
critical_function();  // 正常 < 1ms
clock_gettime(CLOCK_MONOTONIC, &end);
if ((end.tv_nsec - start.tv_nsec) > 10000000)  // > 10ms
    goto detected;

// 2. 复杂: 统计模型
// 正常运行 N 次, 记录均值+方差, 后续波动 > 3σ → 检测
```

### 触发原因
- Stalker 每条指令 callout → 代码执行慢 10-100x
- CModule 降低开销, 但仍有 ~50ns/insn 额外延迟

### traceMiku 现状
⚠️ **不可避免**: 只要 trace 就会有时序异常
✅ 实测不影响结果完整性 (trace 能跑到 ret)
⚠️ 时序敏感的反检测 (time-based canary) 可能触发

---

## L9 — 文件系统检测

### 手段
```c
// 1. 检查已知 Frida 路径
access("/data/local/tmp/frida-server", F_OK)
access("/data/local/tmp/re.frida.server", F_OK)
access("/system/lib64/libfrida-gadget.so", F_OK)

// 2. 检查 /proc/self/fd, 找 frida 相关 fd
// 3. 用 inotify 监控 /proc/self/maps 变化
// 4. 扫描所有可写目录下的可疑文件
```

### traceMiku 现状
✅ trace 数据写入 app 私有 cache dir (`/data/data/<pkg>/cache/.miku`)
✅ agent 不在公共目录

---

## L10 — 信号自杀 (tgkill/tkill/kill)

### 手段
```asm
; 检测到 Frida 后:
mov x0, #0          ; tgid=0 (当前进程)
mov x1, main_tid    ; 目标线程
mov x8, #131        ; __NR_tgkill
mov x2, #11         ; SIGSEGV
svc #0
```

### 变种
- `tkill(tid, SIGSEGV)` — 单线程
- `kill(getpid(), SIGKILL)` — 全进程
- `pthread_kill(pthread_self(), SIGSEGV)`
- `raise(SIGABRT)` — 触发 tombstone
- `syscall(__NR_exit_group, 0)` — 静默退出
- 不直接调 syscall, 走 OLLVM 混淆 dispatcher

### traceMiku 现状
⚠️ `--patch-suicide` + `--suicide-patch-spec`: NOP 目标 SO 的内联 svc #0
❌ **不完整**: dispatcher 可能走其他路径 (如 libsgmainso 共 38 个 `movz x?, #131`, 只 patch 6 个)
🔧 规划: `--block-self-kill` (libc 层 hook tgkill → 拦截所有 signal-based 自杀)

---

## 综合反检测能力矩阵

| 检测层级 | 手段 | stealth frida | --hide-rwx-maps | --patch-suicide | --block-self-kill (计划) | miku-shield (计划) |
|---------|------|:---:|:---:|:---:|:---:|:---:|
| L1 ptrace | TracerPid | ✅ | - | - | - | ✅ |
| L2 maps | rwxp 扫描 | - | ✅ | - | - | ✅ |
| L3 fork | 双进程 | - | - | - | - | ✅ |
| L4 CRC | .text 校验 | - | - | - | ✅ | ✅ |
| L5 symbol | 库扫描 | ⚠️ | - | - | - | ✅ |
| L6 thread | 线程名 | ⚠️ | - | - | - | ✅ |
| L7 port | 端口扫描 | ✅ | - | - | - | ✅ |
| L8 timing | 时间异常 | - | - | - | - | - |
| L9 files | 文件检测 | ✅ | - | - | - | ✅ |
| L10 signal | 信号自杀 | - | - | ⚠️ | ✅ | ✅ |

---

## 失败案例记录

### #1 — libsgmainso 6.8.260403 + --trace-deep (2026-05-02)
- **触发**: `--trace-deep` → Stalker inline-hook libart .text
- **表现**: ~60k records → SI_USER + tombstone
- **根因**: anti-debug worker 线程周期 CRC libart .text vs 磁盘镜像
- **文档**: [docs/anti-debug-libart.md](anti-debug-libart.md)
- **GitHub Issue**: [#1](https://github.com/ltlly/MikuTrace/issues/1)

### #2 — liblynxsecurity.so 无 JNI_OnLoad (2026-05-16)
- **触发**: `--export JNI_OnLoad`
- **表现**: `[!!] export "JNI_OnLoad" not found in liblynxsecurity.so`
- **根因**: 安全 SO 使用静态 JNI 命名 (`Java_<pkg>_<cls>_<method>`) 或 RegisterNatives，不导出 JNI_OnLoad
- **类型**: 工具适配问题（非反调试）
- **解决**: 用 `--export <完整符号名>` 替代 `--export JNI_OnLoad`
- **SO**: liblynxsecurity.so (com.ss.android.ugc.aweme)
- **导出函数**: `nativeVerifySignBlock`, `nativeUpdateRsaPublicKeys`

### #3 — 函数 hook 成功但未被调用 (2026-05-16)
- **触发**: `--cold-launch` → hook 成功 → 函数从未执行
- **表现**: `head=0, tail=0, dropped=0, callIdx=0` — 0 records
- **根因**: consent driver 无法通过 app 开屏/splash → 函数从未被触发
- **类型**: 工具自动交互限制（非反调试）
- **解决方向**: 
  - 手动操作设备触发函数后再 trace
  - 使用 `--launch`（不 pm clear）保持登录状态
  - 扩展 consent driver 支持更多 UI 模式


### #3 — SO 在 agent hook 前已完成 JNI_OnLoad (2026-05-16)
- **触发**: `--cold-launch` → dlopen hook 成功 → SO 已加载 → JNI_OnLoad 已执行完毕
- **表现**: `[+] hook xxx!JNI_OnLoad @ 0x...` → `head=0, tail=0` — 函数已 hook 但未进入
- **根因**: dlopen 返回前 linker 已调用 SO 的 init 函数（JNI_OnLoad），agent 的 Interceptor.attach 在 dlopen hook 返回后才执行，已晚于 init 函数执行
- **类型**: 工具时序限制（非反调试）
- **影响 SO**: libkwsgmain.so (com.kuaishou.nebula)、libturing_live.so / libnms.so (com.ss.android.ugc.aweme)
- **解决方向**:
  - 使用 Frida spawn 模式（`frida -f`）在进程启动前注入 agent
  - Hook ELF loader 的 `call_init` 函数，在 init 执行前拦截
  - LD_PRELOAD 方式替代 attach 后 hook
  - 对于不能 trace JNI_OnLoad 的 SO，trace 其他延迟调用的导出函数

### #4 — 函数 hook 成功但未被调用 (2026-05-16)
- **触发**: `--cold-launch` → hook 成功 → 函数从未执行
- **表现**: `head=0, tail=0, dropped=0, callIdx=0` — 0 records
- **根因**: consent driver 无法通过 app 开屏/splash → app 未到达触发函数的交互状态
- **类型**: 工具自动交互限制（非反调试）
- **影响**: 抖音 (com.ss.android.ugc.aweme)、快手 (com.kuaishou.nebula) 的 cold-launch
- **解决方向**:
  - 手动操作设备触发函数后再 trace
  - 使用 `--launch`（不 pm clear）保持登录状态
  - 扩展 consent driver 支持更多 UI 模式
  - 添加自定义 UI 自动化脚本支持

### #6 — Spawn 模式成功 trace JNI_OnLoad (2026-05-16) ✅
- **触发**: Python Frida API spawn → 注入 agent_cmodule_v5.js → device.resume()
- **表现**: 成功 hook libkwsgmain.so JNI_OnLoad @ offset 0x45854
- **结果**: 75,414 records / 92ms / 819,717 rec/s / dropped=0 / ret=0x10004 (JNI_VERSION_1_4)
- **App**: com.kuaishou.nebula (快手)
- **关键**: spawn 模式在进程启动前注入 → init 函数被成功拦截
- **工具**: tools/spawn_trace_jni_onload.py

### #7 — 抖音签名算法 SO 全貌 (2026-05-16)
- **发现**: 抖音不使用 libcms.so/libnms.so，签名完全在 liblynxsecurity.so 中
- **核心函数**: nativeVerifySignBlock (RSA 签名验证), nativeUpdateRsaPublicKeys
- **已成功 trace**: nativeVerifySignBlock → 2,756 records / 149ms / dropped=0
- **网络层**: 多个 BoringSSL 变体 (libssl.so, stable_cronet_libssl.so, libttboringssl.so)
- **工具**: tools/spawn_sign_scan.py

### #5 — SO 懒加载，trace 窗口内未加载 (2026-05-16)
- **触发**: agent attach 后等待 dlopen → SO 在 60s trace 窗口内从未加载
- **表现**: `init -> waiting-dlopen` → trace 结束 → 0 calls
- **根因**: 某些 SO 按需加载（用户触发特定功能时），不在 app 启动时加载
- **影响 SO**: libturing_live.so, libnms.so (com.ss.android.ugc.aweme), libst_mobile.so (com.sina.weibo)
- **类型**: 工具交互限制（非反调试）
- **解决方向**: 延长 duration、手动触发 SO 加载路径后重新 attach

### #2 — fork-based anti-debug (race-attach 架构限制)
- **触发**: fork() 子进程做 ptrace 守护
- **表现**: `--child-trace-mode full` → attach F3 timeout
- **根因**: ptrace-based Frida 无法二次 attach fork 子进程 (继承关系)
- **任务**: P1-C M1/M2/M3 (部分缓解)
- **根治**: miku-shield eBPF

---

## 参考

- [Frida 反检测概要 (内部)](https://github.com/ltlly/miku-shield)
- [Android Anti-Debugging Techniques (Pangu Team)](https://github.com/panguteam/android_anti_debug)
- [Stalker 行为 & 反检测影响](https://frida.re/docs/stalker/)
