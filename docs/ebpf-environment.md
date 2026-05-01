# eBPF 环境 + miku-shield 项目说明

设备已刷一个改造过的 4.19-cip kernel（项目位置：`/home/ltlly/Code/kernel_research`），
提供完整的 upstream-grade eBPF 能力。本文档给做 **miku-shield**（基于 eBPF 的反 Frida-detection 工具）
的 AI 看，覆盖：(1) kernel 提供了什么；(2) 工具策略：fork stackplz；(3) 测试目标。

---

## 1. 工具策略 — fork stackplz 作为代码基线

**不要从零写 BPF**。我们直接复制 [stackplz](https://github.com/SeeFlowerX/stackplz) 的源码当
项目基线，在它之上加 anti-frida fingerprint 层 + LSM-based mitigation。

### 为什么 fork 而不是当外部依赖

- stackplz 已经实现了 arm64 Android 上 syscall trace + uprobe trace + struct 解析 + 调用栈 +
  寄存器 dump，覆盖反检测识别（Phase 1）需要的全部底层 eBPF 能力
- stackplz 是 Apache 2.0（兼容我们项目）+ Go/C 双语（控制面 Go，BPF 程序 C）
- 我们要加的 mitigation（LSM hooks、fmod_ret 改返回值）需要直接改 stackplz 的 BPF 程序结构，
  当外部依赖反而难做
- 单 binary 部署比 「stackplz binary + 我们的 wrapper」 部署简单
- 用户后续维护单一代码库

### 项目结构（建议）

```
tools/miku-shield/
├── README.md                       # 必须注明 fork 自 SeeFlowerX/stackplz Apache-2.0
├── LICENSE                         # 保留 stackplz 的 Apache-2.0 + 我们的修改头
├── NOTICE                          # 上游 attribution
├── go.mod                          # 改 module 名（github.com/<user>/miku-shield 或类似）
├── Makefile / build.sh             # 沿用 stackplz 的（可能要小改 module path）
├── cli/                            # stackplz 原有 — Go cli 入口
├── user/                           # stackplz 原有 — Go 控制面
├── src/                            # stackplz 原有 — BPF C 源码
│   ├── (existing stackplz BPF progs)
│   └── shield/                     # 新加 — 我们的 mitigation BPF 程序
│       ├── lsm_block.bpf.c            # LSM file_open / socket_connect deny
│       └── proc_filter.bpf.c          # fmod_ret on vfs_read for /proc filtering (Phase 3)
├── shield/                         # 新加 — 反检测专用控制面 (Go)
│   ├── patterns.go                    # anti-frida 模式库（路径正则、端口、proc 文件名）
│   ├── fingerprint.go                 # 已知 anti-frida 库 / 检测套件识别
│   ├── timeline.go                    # 输出格式化
│   └── mitigate.go                    # 加载 mitigation BPF 程序
└── data/
    └── known_detectors.yaml        # 检测器知识库（StealthKit、FAB 等）
```

### Fork 实施步骤

```bash
cd /home/ltlly/Code/traceMiku
mkdir -p tools && cd tools
git clone https://github.com/SeeFlowerX/stackplz.git miku-shield
cd miku-shield
# 改 module path 让我们的代码能和 stackplz 的代码互引用
sed -i 's|module github.com/SeeFlowerX/stackplz|module github.com/<user>/miku-shield|' go.mod
grep -rl 'github.com/SeeFlowerX/stackplz' --include='*.go' | xargs sed -i 's|github.com/SeeFlowerX/stackplz|github.com/<user>/miku-shield|g'
# 保留 LICENSE / NOTICE 原样
# 写 README 说明 fork 关系
```

### README 必须包含

```markdown
## 致谢 / Credits

miku-shield 基于 [SeeFlowerX/stackplz](https://github.com/SeeFlowerX/stackplz)
fork (Apache-2.0)，复用其 arm64 Android eBPF 框架（syscall trace + uprobe + 参数解析）。

我们在其上添加：
- anti-frida 检测点的模式识别层
- LSM-based mitigation（拒绝 frida-server 文件访问、屏蔽 frida 端口）
- fmod_ret-based /proc 内容改写（Phase 3）

stackplz 原作者：SeeFlowerX
原项目 license：Apache-2.0（保留在 LICENSE 文件）
```

---

## 2. Kernel 提供的 eBPF 能力（已验证）

设备：Xiaomi alioth (Redmi K40 / POCO F3 / Mi 11X) on LineageOS 23.2
Kernel：Linux 4.19.325-cip128（含 mainline 5.5/5.18/6.0 BPF trampoline 移植）
KernelSU v3.2.4 已就位（`adb root` 可用），SELinux Permissive
BTF：`/mnt/vendor/persist/vmlinux.btf` + `/sys/kernel/btf/vmlinux` 暴露给 libbpf

### 可用的 BPF prog types

29/32 prog types `available`。对反检测工具有用的：

| 类别 | 状态 | 反检测里的用处 |
|---|---|---|
| `tracepoint:syscalls:sys_enter_*` / `sys_exit_*` | ✓ | 抓 openat、connect、read 等系统调用，按 uid/pid 过滤 |
| `kprobe` / `kretprobe` | ✓ | 入口/出口 hook 任意 kernel function |
| `fentry` / `fexit` | ✓（**标准 upstream 行为**） | `ctx[0..N]` 真实参数，fexit 在 ret 后触发，能读 return value |
| `fmod_ret` | ✓ | 改 syscall 返回值 — mitigation 关键 |
| `BPF_PROG_TYPE_LSM` | ✓ | `file_open` / `socket_connect` 拦截 |
| `uprobe` / `uretprobe` | ✓ | hook target app 的 native lib 函数（stackplz 已用） |
| `perf_event` (sampling) | ✓ | 采样 profiler |

不可用：`syscall` (5.14+)、`netfilter` (6.x)、`lirc_mode2`（无 IR 硬件）。

### fentry/fexit/fmod_ret 工作原理（标准 upstream）

```c
SEC("fexit/do_sys_open")
int BPF_PROG(after_open, int dfd, const char *filename, int flags, int mode, long ret)
{
    /* ret 是真实返回值（fd 编号或 -错误码） */
    return 0;
}

SEC("fmod_ret/do_sys_open")
int BPF_PROG(modify_open, int dfd, const char *filename, int flags, int mode, long ret)
{
    /* 返 -ENOENT 让 caller 觉得文件不存在 */
    return -ENOENT;
}
```

实测验证（cold reboot）：
```
$ ls / && echo z > /data/local/tmp/test
sh ENTRY  dfd=ffffffffffffff9c flags=20241        # AT_FDCWD = -100
sh EXIT   dfd=ffffffffffffff9c flags=20241 ret=3  # 真实 fd
```

详细：`/home/ltlly/Code/kernel_research/docs/runbook/2026-04-29-mainline-direct-multi-port.md`

### LSM hooks 列表（4.19 上已确认可用的）

```bash
adb shell bpftool feature probe full | grep "lsm/"
```

最关键的 mitigation hooks：
- `lsm/file_open` — 文件打开拦截
- `lsm/socket_connect` — 网络连接拦截
- `lsm/inode_permission` — 文件权限检查
- `lsm/bprm_check_security` — exec 监控

LSM hook 在 4.19 上比 5.7+ 略简（部分新 hook 可能不存在），先 `bpftool feature probe full` 验证。

### 工具发开链

宿主机：
```bash
sudo apt install -y clang llvm libbpf-dev linux-tools-common bpftrace
# Go 工具链（stackplz 需要）
# 推荐 Go 1.21+，android-ndk 用于 cross compile

# vmlinux.h 生成（CO-RE 兼容）
adb pull /sys/kernel/btf/vmlinux /tmp/vmlinux
bpftool btf dump file /tmp/vmlinux format c > vmlinux.h
```

设备：
```bash
adb root
adb shell bpftool feature probe                # 完整能力清单
adb shell bpftool prog list                    # 已加载的 BPF 程序
adb shell cat /sys/kernel/tracing/trace_pipe   # bpf_printk 输出
```

### 包名 → uid → BPF 过滤

```bash
adb shell pm list packages -U com.taobao.taobao
# package:com.taobao.taobao  uid:10169
```

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xffffffff;
    if (uid != TARGET_UID) return 0;
    /* ... */
}
```

stackplz 已经实现 uid filter（`-n com.taobao.taobao`），fork 后直接复用。

---

## 3. 测试目标

两个 app，都是已知有 anti-frida + 反爬 + 自建沙箱的代表：

| App | 包名 | 目标 lib（之前 traceMiku 用过） | 反检测特性 |
|---|---|---|---|
| 淘宝 | `com.taobao.taobao` | libsgmainso（白盒 sign 计算） | 强：scan 自身进程内存、检测 frida 字串、检测 27042 端口、检测 maps 中模块名 |
| 去哪儿 | `com.Qunar`（注意大写 Q）| libgoblin（之前 uprobe 验证过 Ena1907_req） | 强：类似上面 + 自建 sandbox，多线程检测 |

如果包名不确定，先 `adb shell pm list packages | grep -i qunar` 确认实际包名。

### 测试场景设计

每个 target 都做这三组测试：

**场景 A — 纯识别（Phase 1）**
- target 启动，miku-shield 在旁边运行 syscall trace，跟踪 60s
- 输出 timeline：每个 anti-frida 检测尝试 → 时间戳 + 检测类型 + 检测路径/端口
- 期望：抓出 ≥10 个明确的 anti-frida 检测点

**场景 B — Mitigation 启用（Phase 2）**
- 同时启用 LSM block：拒绝 frida-server 文件访问 + 屏蔽 27042 端口
- target 此时 frida-server 在跑（traceMiku 的 stealth 版）
- 期望：target 检测到 frida 的概率显著下降，业务功能正常

**场景 C — 配合 traceMiku（Phase 3）**
- miku-shield 跑 mitigation
- 同时 traceMiku 跑 cmodule v5 trace 抓 libsgmainso doCommandNative
- 期望：trace 完整完成（dropped=0），无 anti-frida tombstone

### 检测点知识库（已知，初版）

下面这些已知 anti-frida 检测，用作 fingerprint 库的种子：

```yaml
# data/known_detectors.yaml
filesystem:
  - /data/local/tmp/frida-server
  - /data/local/tmp/re.frida.server
  - /data/local/tmp/frida-cli
  - /data/local/tmp/.miku-srv             # traceMiku stealth 版用的
  - /data/local/tmp/.miku-cli
  - /data/data/re.frida.server
  - /system/bin/frida-server

network:
  - port: 27042                            # frida default
  - port: 27043                            # frida secondary
  - port: 6699                             # traceMiku stealth 版

proc_inspection:
  paths:
    - /proc/self/maps                      # 扫 frida/gum 模块
    - /proc/self/task/*/comm               # 扫 gum-js-loop / gmain / gdbus 线程
    - /proc/self/status                    # TracerPid 检测
    - /proc/self/cmdline                   # 父进程检测
    - /proc/self/syscall                   # syscall 指纹
    - /proc/net/tcp                        # 端口枚举
  string_patterns:
    - "frida"
    - "gum-js-loop"
    - "gmain"
    - "gdbus"
    - "linjector"
    - "re.frida.server"

memory_patterns:                           # eBPF 看不到，仅作参考
  - "gum_memory_allocate_near"
  - "frida_agent_main"
```

---

## 4. 边界 + 不要踩的坑

1. **`bpf_probe_write_user`** 是 unsafe，需要 page faulted-in，对 user buffer 写有 race 风险。
   `/proc/self/maps` rewrite 这种 Phase 3 工作要小心 paginated read 边界
2. **fmod_ret** 改返回值后，必须保证签名匹配（fexit 改 ret 不影响后续调用，fmod_ret 改 ret 在 trampoline 处生效）
3. **uprobe 装在 stripped 库** 找符号要靠 BuildID + offset；stackplz 已经有这套机制，复用即可
4. **LSM hook 里不要做长操作**，是同步检查路径，慢了卡用户态
5. **eBPF 程序自己加载/运行** 也会改一些 kernel state（如 ftrace 表），高级 anti-frida 理论上能感知 — 但实测上几乎没有 app 检查这个，远低于检测 ptrace/maps 的 priority

---

## 5. 参考资料链

kernel 项目（基础设施，不要改）：
- 项目根：`/home/ltlly/Code/kernel_research/`
- `STATUS.md` — kernel 当前状态、commit 列表
- `docs/FINAL-ACHIEVEMENTS.md` — 整体成果
- `docs/runbook/2026-04-29-mainline-direct-multi-port.md` — 标准 eBPF 行为如何达到
- `docs/runbook/2026-04-28-btf-firmware-loader.md` — BTF 怎么装载
- `scripts/install-btf-to-persist.sh` — BTF 安装到 /mnt/vendor/persist

stackplz 上游（fork 来源）：
- https://github.com/SeeFlowerX/stackplz （Apache-2.0）

traceMiku 自身（提供 frida stealth + 测试 helper）：
- `BENCHMARKS.md` — frida cmodule v5 性能数据 + cold-launch 触发逻辑
- `docs/frida-codeslab-patch.md` — frida-server stealth patch 怎么做
- `vendor/frida-patched/` — 已打补丁的 frida-server，6699 端口

如果设备表现异常（BTF 不加载、enabled_functions 没有 R/I/D 标志、ctx[0] 不是真实参数），
回看 kernel_research 项目的 runbook 找对应章节。
