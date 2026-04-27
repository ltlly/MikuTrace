# frida-gum code slab 分配失败 patch

> Pixel 7 / Android 16 上抓 OLLVM 大库 (libsgmainso 等) instruction trace 时,
> frida 17 的 Stalker 在 ~4500 条记录后 SIGTRAP, 整个 target 进程被杀。
> 本 patch 在 `gum/backend-posix/gummemory-posix.c` 的 `gum_memory_allocate_near()`
> 末尾加了一个 fallback, 让 code slab 分配失败时退化为 anywhere mmap, 而不是
> 上层 `g_assert(result != NULL)` 直接 abort 进程。

## 现象

target tombstone:

```
Abort message: 'Unable to allocate code slab near 0x6e8eebf000 with max_distance=2138779647'
signal 5 (SIGTRAP), code -6 (SI_TKILL)
backtrace:
  #00 libc.so syscall+32
  #01 libcrashsdk.so          ← target 自带 crash handler
  #02 libcrashsdk.so
  #03 [anon:thread signal stack]   ← frida-gum 自杀
```

trace meta 表现: 1 个 call, 1805~4544 条 records, `truncated=true`,
`last_insn_is_ret=false`, onLeave 不触发 — 因为 target 已经被 frida 自己 kill。

## 根因

frida-gum 从 v14.2.14 起在 `gum_memory_allocate_near()` 里加了
`gum_address_spec_is_satisfied_by` 检查 — 强制 stalker code/data slab 必须落在
目标 SO 的 ±2GB (max_distance=0x7fffffff) 范围内。意图: ARM64 b/bl 是 ±128MB,
间接跳 (bl 通过 thunk) 也只能 ±2GB, 所以 stalker 重写出来的代码必须靠近原代码。

但实现上, `gum_memory_allocate_near` 走两步:

1. `mmap(suggested_base=spec->near_address, ...)`: 把目标 SO 地址作为 hint
   传给 mmap, 让内核倾向就近分配。如果命中 ±2GB, 直接返回。
2. 否则 `gum_enumerate_free_ranges()` 遍历 `/proc/self/maps` 的空闲洞,
   用 `gum_try_suggest_allocation_base` 找一个落在约束内的洞 mmap。
3. 还找不到 → 返回 NULL → 上层 `g_assert(result != NULL)` SIGTRAP。

**Pixel 7 + Android 16 + OLLVM 大库** 三件套同时满足:

- ASLR 把 libsgmainso 放到高位 `0x6e..0x75`, 周围 ±2GB 已经被 art / system
  libs 切成无数小洞 (见 [issue #793 提交的 maps.txt](https://github.com/frida/frida-gum/files/14944105/maps.txt))
- OLLVM 控制流平坦化让 stalker 每条指令 putCallout 生成一个 JIT thunk,
  4500 条 ≈ 几 MB code slab, 单次 mmap 一个连续 ±2GB-fit 的 chunk 失败概率高
- 第二步 enumerate 遍历到的洞如果 size 不够, 也跳过

→ `result == NULL` → abort。

[issue #707 报告者](https://github.com/frida/frida-gum/issues/707) 实测删除
该 spec 检查后 stalker 仍正常运行, 因为 stalker 内部用 ADRP+BR Xn (`adrp x16, #imm21; br x16`)
做远跳, 已经能跨 2GB 边界, "near" 只是减少 thunk 的 best-effort 优化。

## patch

[`vendor/frida-patched/gummemory-posix.patch`](../vendor/frida-patched/gummemory-posix.patch)
针对 frida-gum master (commit `7f71906ab428b2198aefc9aa5ae3c153d8d6e56a`,
对应 frida 17.9.x):

```c
   gum_enumerate_free_ranges (gum_try_alloc_in_range_if_near_enough, &ctx);

+  /* MikuTrace patch: ±max_distance 内空间耗尽时 fallback 到 anywhere mmap,
+   * 避免上层 g_assert SIGTRAP 整个 target 进程. */
+  if (ctx.result == NULL)
+    ctx.result = gum_memory_allocate (NULL, size, alignment, prot);
+
   return ctx.result;
 }
```

只在原逻辑彻底失败时启用 fallback, 不影响正常 case 的就近分配。

## 编译

macOS host 交叉编 android-arm64:

```bash
git clone https://github.com/frida/frida.git
cd frida
git submodule update --init --recursive subprojects/frida-gum subprojects/frida-core
patch -p1 -d subprojects/frida-gum < /path/to/MikuTrace/vendor/frida-patched/gummemory-posix.patch
export ANDROID_NDK_ROOT=/path/to/android-ndk-r25c
./configure --host=android-arm64 --enable-server --disable-frida-tools \
            --disable-frida-python --disable-gadget --disable-inject
make -j8
# 产物: build/subprojects/frida-core/server/frida-server
```

预编译二进制 (frida 17.9.1 + 本 patch, android-arm64): 见
[`vendor/frida-patched/frida-server-17-patched`](../vendor/frida-patched/).
SHA256 在同目录 `SHA256SUMS`。

## 推送到设备 + 用法

一行: `./vendor/frida-patched/install.sh` (默认 forward 6699), 或手动:

```bash
adb push vendor/frida-patched/frida-server-17-patched /data/local/tmp/
adb shell 'su -c "chmod 755 /data/local/tmp/frida-server-17-patched"'
adb shell 'su -c "killall frida-server-17 frida-server 2>/dev/null"'
adb shell 'nohup su -c "/data/local/tmp/frida-server-17-patched" >/dev/null 2>&1 &'
adb forward tcp:6699 tcp:27042
# 然后正常跑 tracemiku
./tracemiku trace --pkg com.taobao.taobao --so libsgmainso \
  --fn-offset 0x57770 --cmd 70102 --duration 240 --mode js \
  --cold-launch --remote 127.0.0.1:6699 --out traces/run1
```

## 验证: patched 前后对比 (实测数据)

测试目标: TB `com.taobao.taobao` 10.60.10 (libsgmainso-6.8.260403),
`doCommandNative` cmd=70102, duration 240s, Pixel 7 + Android 16 + frida 17.9.1。

| 配置 | calls | records | TB SIGTRAP? | 备注 |
|---|---:|---:|---|---|
| frida 17 stock | 1 | **1,805** | ✅ 9 秒后崩 | tombstone: `Unable to allocate code slab` |
| frida 17 stock + cmodule mode | 1 | **1,805** | ✅ 同上 | mode 无关, 底层 stalker 同样崩 |
| **frida 17 patched** | 1 | **3,858,484** | ❌ 全程稳定 | call#1 流式记录到 teardown, ~16,800 rec/s |

提升: **2000x records, 进程零崩溃**。 PID watchdog 全程未触发, `fnHooked=true`,
record 流连续 (无 stalker drop), `cmdHist` 多种 cmd 同时被 hook 监听。

## 上游

- [frida-gum #707 (2023)](https://github.com/frida/frida-gum/issues/707): 报告者
  实测删除 GumAddressSpec 检查后 stalker 正常 — 提供了本 patch 的实证基础
- [frida-gum #793 (2024)](https://github.com/frida/frida-gum/issues/793): 同样
  错误信息, 大 OLLVM 库 trace 时频繁出现, 至本文档撰写时上游未修
- [frida #2819 (2024)](https://github.com/frida/frida/issues/2819): Android 14
  + S22 + Stalker 多线程时 SIGTRAP, 同根因
