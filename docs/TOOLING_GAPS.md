# 设备侧工具改进需求清单

本文件只记录**已确认的设备链路缺陷**与对应改动建议，等待维护者确认后再实现。
不属于 traceMiku 功能路线图；实现后的功能用法以 `docs/FEATURES.md` 为准。

记录环境：一加平板 Pro（OPD2404，Android 16 / SDK 36，arm64-v8a，KernelSU root），
主机 adb 客户端 + frida-tools 17.17.0。

## 1. 设备层不识别非默认 adb server 端口（**已修**）

> **已修（2026-10）**：新增 `adb_command()` 统一注入 `-P $ANDROID_ADB_SERVER_PORT` /
> `-s $ANDROID_SERIAL`（端口校验 1..65535），`tracemiku` 与 `tracemiku_device.py` 全部调用点已迁移，
> doctor 回显实际端点且只认严格等于 `device` 的行。下面保留原始现象记录。

- **现象**：`adb devices` 报 `no permissions`（`/dev/bus/usb/007/036` 为 `root:root 0660`），
  写 `/etc/udev/rules.d/51-android-22d9.rules` 并 `udevadm trigger` 后节点被重建、ACL 被清掉，
  `setfacl` 之后 `udev kill-server && adb start-server` 仍看不到设备。设备实际被一个
  以 root 运行、监听 `tcp:5038` 的 adb server 独占。
- **影响**：`tracemiku_device.py:66/80/101/118/128/151` 与
  `scripts/device_trace_integration.py:134/271` 全部直接 spawn `adb`，默认只连 `5037`，
  在该设备上「设备未就绪」判定为假阴性。
- **建议改动**：设备层统一支持 `ANDROID_SERIAL` / `ANDROID_ADB_SERVER_PORT` 透传
  （读环境变量注入 `adb -s` / `-P`），并在 `doctor` 输出里回显最终生效的 adb 端点。
- **验收**：`tracemiku doctor` 在只暴露 5038 的设备上能报 `root=true`、`frida=true`；
  无端点时给出明确失败原因而不是「未连接」。

## 2. Android 16 上 `adb install` 会挂起等待授权界面

- **现象**：`adb install -r -g <82MB APK>` 挂死且无任何输出，logcat 显示
  `com.android.packageinstaller/…PackageInstallerActivity` 取得焦点；
  `adb shell "pm install …"` 同样无输出返回。
- **影响**：任何需要装包的设备流程都会无限等待，且没有超时与失败语义。
- **建议改动**：设备层加 `install` 能力，默认走 `su -c 'pm install …'`（root 通道已存在），
  并加超时 + 非零退出码透传；root 不可用时明确报「需要 root 安装」而不是静默挂起。
- **验收**：在 Android 16 真机上安装 80MB 级 APK 全程无人工交互，失败时输出可读原因。

## 3. frida 探针无法识别 jailed 的 frida-server

- **现象**：设备上存在一个被 KPatch 隐藏的 frida-server（二进制版本自报 `0.0.0`）。
  `frida-ps -U` 能列出 288 个进程（含系统进程），看起来正常；但
  - `frida -U -p <pid>` → `agent connection closed unexpectedly`
  - `frida -U -f <pkg>` → `need Gadget to attach on jailed Android`
  同一时刻 `frida-server` 启动日志有 `Unable to save SELinux policy to the kernel: Out of memory`。
  `setenforce 0` 后另起 root frida-server 即可正常 attach/spawn。
- **影响**：`tracemiku_device.py:101` 只执行 `frida-ps`，会把这种「能枚举、不能注入」的
  半可用状态判成 frida 可用，后续所有 trace 都在 attach 阶段失败。
- **建议改动**：frida 探针增加真实 attach 探测（对自身子进程或 `adbd` 做一次注入往返），
  区分 `available` / `jailed` / `absent` 三态并给出各自修复提示
  （`jailed` → 提示 `setenforce 0` + 以 root 重启 frida-server）。
- **验收**：`tracemiku doctor` 在 jailed 设备上报 `frida=jailed` 并附修复建议，不报假阳性。

## 4. frida 侧：spawn 模式不注入、CLI 非交互即退出、多进程 pid 解析

- **现象**（同一台设备、同一 frida-server 17.x）：
  - `frida -H 127.0.0.1:PORT -f <pkg> -l <script>`：进程被 spawn 并 resume，
    但脚本顶层与 `Java.perform` 回调**都不执行**，日志只有
    `Spawned ... Resuming main thread!`，且脚本内的 `setTimeout` 轮询也不会跑；
    同一脚本换成 `-p <pid>` attach 则完全正常。
  - `frida ... -l <script> -q`（stdin 非 tty）会**立即退出**并连带结束 session，
    表现为脚本刚加载就没输出；用 `sleep N \| frida ...` 保持 stdin 打开才稳定。
  - `adb shell pidof <pkg>` 在多进程 app 上返回**空格分隔的多个 pid**，
    `frida -p` 无法解析，需要 `cut -d' ' -f1` 或 `awk '{print $1}'`。
- **影响**：任何依赖 spawn 抓冷启动流量的采集脚本都会静默失效（无报错、无 hook），
  极易被误判为「该路径没有流量」。
- **建议改动**：设备层若要提供 trace/hook 能力，必须
  1) 用「轮询 pid → attach」替代 spawn，并显式校验脚本已安装（心跳/ack），
  2) 非交互执行时保持 stdin 打开或改用 frida Python API（注意 Python API 不自动注入
     Java bridge，需显式加载 `frida-java-bridge`），
  3) 对 `pidof` 多 pid 显式取主进程。
- **验收**：设备层冷启动采集必须返回「已注入并确认」的显式状态；脚本未安装时报错而非静默。


## 5. 缺少「解密后 so 内存镜像导出」与「native 方法 hook」两条设备能力

- **现象（本次逆向的真实阻塞点）**：目标 `lib/arm64/libsgmainso-*.so` 磁盘 ELF 头被破坏
  （`readelf`：`no .dynamic section in the dynamic segment`），静态工具无法导入；
  而 SG 插件类不在 APK dex 里，而在同样伪装成 `.so` 的 zip 容器内
  （`libsgmain.so` 实为 zip，内含 `classes.dex`）。这两件事都只能靠运行时取。
  当前只能用一次性 `dd if=/proc/<pid>/mem` 按 maps 分段读、再手工按 file offset 拼装。
- **建议改动**：
  1. `tracemiku dump-mem-lib --pid <pid> --so <name> --out <dir>`：读 `/proc/<pid>/maps`，
     按模块分段 dump，输出 SO 镜像 + `meta.json`（各段 vaddr/offset/flags、缺段说明），
     缺段显式标注为未知，不以零填充冒充真值。
  2. `tracemiku jni-hook`：按 `类名#方法` hook native/静态方法，输出结构化 JSONL
     （调用序、入参类型与值、返回值、所属模块与偏移），供离线重放与差分。
- **约束**：两者都必须遵守现有边界——有界输出、明确失败语义、资源上限、
  语义先落 core 再由 CLI 序列化、目标知识只放 `tools/hooks/` 或 `examples/<target>/`。
- **验收**：对同一 so 连续两次导出结果可复现；`jni-hook` 输出可被 CLI 侧解析并做
  参数/返回值断言测试。

## 6. trace 拉取阶段的 adb 探测超时会让整条分析链不可用（阻塞级，**已修**）

> **已修（2026-10）**：`meta.json` 未知布尔改为三值语义（`tracemiku-core/src/trace/meta.rs`），
> finalize 迁入 core 并按 `trace.bin` 回填（`tracemiku-core/src/trace/finalize.rs`），
> 拉取改为「短命令 cp + `adb pull`」的事务式传输、拉取失败保留 pending 且退出码非零、
> adb 端点统一由 `adb_command()` 注入。下面保留原始现象记录。

- **现象**：在真机上跑 `tracemiku trace --pkg com.aliyun.tongyi --spawn --so libsgmainso
  --method doCommandNative --cmd 70102 --cmd-arg 2 --out traces/sg68_xsign --max-records 8000`，
  设备侧采集完全正常（`RegisterNatives` 命中、4 次调用各 8000 条记录、`dropped=0`），
  但每一条 trace 的拉取都失败：

  ```text
  gzip pull 失败 (Command '['adb', 'shell', 'id']' timed out after 5 seconds); 回退 raw cat
  [!] pull device trace 失败: Command '['adb', 'shell', 'id']' timed out after 5 seconds
  ```

  随后所有基于 AppState 的分析命令全部不可用：

  ```text
  $ ./tracemiku coverage traces/sg68_xsign/calls/call_001_.../
  Error: load AppState
  Caused by: invalid JSON in .../meta.json: invalid type: null, expected a boolean at line 12 column 26
  ```

  `info` 仍可用（它直接读 `trace.bin`），能正确报出 `records=8000 / first_pc / last_pc`。
- **根因**（`tracemiku:238-245`）：

  ```python
  def _detect_su_needed():
      if _adb_pull_use_su[0] is not None: return _adb_pull_use_su[0]
      r = subprocess.run(["adb", "shell", "id"], capture_output=True, text=True, timeout=5)
      is_root_shell = "uid=0" in (r.stdout or "")
      _adb_pull_use_su[0] = not is_root_shell
      return _adb_pull_use_su[0]
  ```

  三个问题叠加：
  1. `timeout=5` 硬编码。**Stalker 正在跑时设备必然过载**（实测 12000~38000 rec/s），
     此时 `adb shell id` 稳定超过 5s——同一时刻手工执行只要 0.077s。也就是"越需要
     trace 的场景越拉不下来"。
  2. `TimeoutExpired` 直接向上抛，**既不重试也不降级到 su 路径**。
  3. 探测结论**不缓存**（超时时不写入 `_adb_pull_use_su`），于是每一次 pull 重新失败。
- **次生问题**：`meta.json` 在拉取失败后被 `finalize` 写成
  `records=0, bytes=0, first_pc=null, last_pc=null, last_insn_is_ret_ret=null`，
  而 `finalize` 只扫 `_pending_call_*` 目录，**不会**为已存在的 call 目录按 `trace.bin`
  重算这些字段。结果是"数据在磁盘上、但元数据不可用"，人工把 `trace.bin` 拉回来也救不回来。
- **建议改动**：
  1. 探测超时上限提到 30s；`TimeoutExpired` 按「非 root shell」处理并走 su 路径，
     成功后写入缓存（含失败结论），保证一次探测只发生一次。
  2. 拉取失败时不要 finalize 成 `records:0` 的 meta，改为保留 `_pending_call_*`
     让 `finalize` 事后修复。
  3. `finalize` 增加修复路径：对已存在 `trace.bin` 但 meta 缺
     `records/bytes/first_pc/last_pc/last_insn_is_ret` 的 call，按 bin 重算并回填。
  4. （可选）`doctor` 增加一次「拉取通路自检」，避免在 trace 结束后才发现拉不下来。
- **验收**：在满载 trace 场景下 4 次调用的 `trace.bin` 全部自动落到
  `calls/call_*/trace.bin`，`meta.json` 字段完整，`coverage` / `call-tree` / `strings`
  可直接运行；人为让首次 `adb shell id` 超时也不影响后续拉取。

## 7. `tracer/_agent.js` 构建依赖缺失，agent 编译不出来（**已修**）

> **已修（2026-10）**：新增 `make agent` 目标（`npm install` + `npm rebuild frida` + `npm run build`
> + 产物非空断言），`tracer/package.json` 的 build/watch/typecheck 显式走本地 `node_modules`，
> agent 缺失时给出「先执行 make agent」而不是 `FileNotFoundError`。

- **现象**：`./tracemiku trace` 直接崩：

  ```text
  FileNotFoundError: .../tracer/_agent.js
  ```

  按 `tracer/package.json` 跑 `npm run build` 又报 10 处类型错误：

  ```text
  src/core/utils.ts:11:26 - error TS-1: Property 'findExportByName' does not exist on type 'typeof Module'.
  src/hooks/jni_vtable.ts:15:27 - error TS-1: ...
  ```

- **根因**：`tracer/node_modules` 不存在，`npm run build` 落到了 PATH 上的全局
  `frida-compile`，而 TypeScript 解析到的是全局较新版本的 `@types/frida-gum`，
  该版本已移除 `Module.findExportByName`（frida 17 改为 `Module.getGlobalExportByName` /
  `Module.findGlobalExportByName`）。项目 `package.json` 实际钉的是
  `@types/frida-gum@^18.7.1`（装到 18.8.2），该版本仍有这个 API。
- **还差一步**：`cd tracer && npm install` 之后仍不能构建——npm 阻止了 `frida` 的
  install script，`frida_binding.node` 缺失，`frida-compile` 以
  `Cannot find module .../frida_binding.node` 崩掉。需要 `npm rebuild frida`
  （或 `npm install-scripts approve frida`）之后 `npm run build` 才成功，产出 50911 字节。
- **建议改动**：
  1. 把 `tracer/_agent.js` 纳入构建前置（`make` 目标或 `doctor` 检查），
     缺文件时给出「先执行 `cd tracer && npm install && npm rebuild frida && npm run build`」
     的明确提示，而不是 `FileNotFoundError`。
  2. 记录 frida npm 包的 install script 需要显式批准，避免升级 npm 后静默失败。
  3. 验收：`make test-fast` 之前 agent 必须存在；`doctor` 在 agent 缺失时明确报错。

## 8. 被 trace 的目标会让 adbd 的 subprocess 路径失效，adb 不可用于回传（**已解决**）

> 本文按「已确认事实 / 已被推翻的推断」分开写。最初两轮的结论都被后续实验推翻，
> 保留在这里是为了避免再被引用。

**已确认（三组对照 + 设备侧自证）**
- 触发条件是 **Stalker 挂到目标进程上**。对照 A：目标 + `--max-records 1`（只追 1 条指令）
  照样复现；对照 C：同一目标只 attach + 装 JNI hook、Stalker 从未启动 → 完全正常。
  attach 本身、追踪强度都不是因素。
- 失效范围只有 adbd 的 subprocess 路径：`adb shell` / `adb logcat` 挂死；
  `adb devices` / `adb get-state` / `adb push` / `adb forward` / frida 通道全部正常。
- `adb shell -n -T 'printf "MARKER
"'` 从不出现 marker —— 命令没执行到输出，
  不是「执行完但协议没收尾」。
- **设备上其它进程的 fork/exec 正常**：复现前启动的设备侧 helper 连续 154 轮
  `date` + `toybox true` 全部成功（25~60ms），而同一时段 `adb shell` 已挂死。
  所以不是全局 fork 阻塞。
- `cat /proc/[0-9]*/stack` 会把 helper 永久卡住（读 `/proc/<pid>/stack` 阻塞通常意味着
  存在内核栈无法展开的任务）。
- 不是 CPU 饱和（~70% idle）、不是内存/IO 压力（PSI 全 0）、不是 pids cgroup 上限
  （内核到上限返回 EAGAIN 而非排队）、不是 zombie/D 状态本身（那是表现不是根因）。
- 同一设备/内核上 traceMiku 本身开发时 Stalker 工作正常 → 目标特有的检测/自修改代码路径
  与 Stalker 交互触发。

**已被推翻的推断（勿再引用）**
- ~~「目标进程活着会拖慢 adb，它死后 adb 立刻恢复」~~：不成立。当时每次观察到 adb 恢复
  都同时重启了 adb server。
- ~~「设备上所有新进程创建会无限阻塞」~~：被 helper 154 轮自测推翻。
- ~~「重启 adb server 必然恢复」~~：只是时间相关；重启会重建连接，恰好撞上 fork 成功的窗口。

**内核/用户态的确切等待点仍未定位**（候选：该目标的自修改代码/AVMP 与 Stalker CModule
交互导致某任务进入不可中断状态，或用户自装的进程隐藏内核模块与之交互后自锁）。
取证脚本见 `tools/collect_subprocess_evidence.sh`（复现前启动、事后 `adb pull`；
每轮独立落盘、不读 `/proc/*/stack`、每轮独立文件）。

**解决方式：不依赖 adb 的回传通道。**`--transport frida`（现为默认）由 host 驱动、
有界窗口、二进制附件分块回传 trace 字节，全程零 fork。真机已验证：4 个 call 各
1,632,000 字节自动落盘、meta 完整、`coverage` / `call-tree` / `strings` 可跑通，
且 trace 结束后 `adb shell` 仍正常。设备 spool 保留为恢复源，不在回传成功后删除。
详见 `docs/FEATURES.md` 与 `./tracemiku capabilities` 的 `capture_extensions`。
