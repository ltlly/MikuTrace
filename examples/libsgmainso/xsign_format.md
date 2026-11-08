# x-sign 载荷结构（实测反推，仅 SG 6.8.260602 / 千问 7.3.6.3039）

证据：`test_vectors.json` 的 135 组向量（`oracle_vectors` 76 + `diff_vectors` 29 + `fixed_vectors` 30，跨 6 个进程样本）与 4 份 trace。

## 1. 编码层与字段布局（135 组向量逐字节验证）

`xsign_codec.py --selftest` 对全部 135 组向量做 `decode -> encode` 往返：

```
向量 135, decode->encode 载荷逐字节还原 135
```

- **外层编码**：标准 Base64 字母表（含 `+` / `/`，**不是** base64url），解码固定 **76 字节**。
- **外层掩码**：2 字节交替，`n[i] = b[i] ^ b[74 + (i & 1)]`，仅对 `i >= 10`；
  掩码字节就是载荷自己的最后两字节。归一化后 `b[74:76] == 0`。
- **字符串层面的唯一差异**：最后一个 base64 字符的低 4 位是编码器未清零的丢弃位，
  **不属于签名内容**（135 组里只有 4 组恰好为 0）。因此一致性判据是载荷 76 字节，
  不是字符串。

### 字段布局

| 区段 | 绝对偏移 | 内容 | 变化来源 |
|---|---|---|---|
| header | 0..7 | `6b364c827d34e710`（8 字节常量） | 仅 `env`（env=2 时前 4 字节与第 6 字节变） |
| pad | 8, 10 | `0x00` | — |
| a | 9 | 1 字节 | 每调用 |
| nonce | 11..21 | 10 字节 + 1 字节计数器 | 每调用（前 10 字节绑定请求内容） |
| len_field | 22..25 | `0x00000183`（387） | 恒定 |
| template | 26..66 | 41 字节常量模板（其中 25 字节随 env） | 仅 `env` |
| tail | 67..69 | 3 字节（`device_blob[41..43]`） | 每进程（`miniWua` 输入影响偏移 67） |
| tail_a | 70..71 | 2 字节 | 每调用 |
| counter | 72..73 | 大端 16 位 | 同 `api` 每次 70102 调用 `+0x10` |
| mask | 74..75 | 掩码自身 | 每调用 |

- **会话与模板区**：6 个独立进程采到 6 个 `device_blob`（偏移 26..69），前 41 字节（26..66）在所有进程、所有 env=0 样本中完全一致，差异仅出现在最后 3 字节（67..69）；6.8 的 blob 内不包含 `x-umt`。
- **计数器**：同进程同 `api` 内严格 `+0x10 / 70102 调用`（76 组连续样本无一例外），初值跨进程不同；换用不同 `api` 时该字段不推进（`api_*` 四组都停在 12304），绑定 `api` 维度。
- **输入依赖与异常边界**：`device_blob` / `counter` / 模板区与请求内容无关；请求内容仅影响 10 字节 `nonce[0..10)`。`signKey` 输入错误或 `appKey` 未注册在 native 侧抛 `SecException`；`useWua=false` 返回 map 无 `wua` 键；`env=1/2` 改变 `x-umt` 及 `x-sign` 头部与 32..56 区域。千问 7.3.6 的 `ISGPluginManager` 为动态代理，需枚举 `DexPathList` 含 `libsgmain.so` 的 classloader 获取 `IRouterComponent`（见 `fr_session.py` + `diff_probe.js`）。

## 2. 请求内容绑定证据

`same00` 与 `api_0..api_3` 满足**同进程（同 device_blob）且同 counter（12304）**，
唯一差异是 INPUT 里的 `api` 字段：

| tag | INPUT 的 api | counter | nonce[0..10) |
|---|---|---|---|
| same00 | `mtop.intf.signedTest` | 12304 | `000b51ac5c06393152f0` |
| api_0 | `mtop.a.b` | 12304 | `03b08a87cb80babe89e4` |
| api_1 | `mtop.taobao.h5.detail` | 12304 | `0665a808d43526cfa944` |
| api_2 | `mtop.taobao.wsearch.h5search` | 12304 | `04bb31059992bd75e634` |
| api_3 | `x` | 12304 | `0d1a8cec7b85cdb5b004` |

→ **请求内容确实进入 x-sign，绑定位置就是那 10 字节。**

## 3. 本示例范围内的未解项

`nonce[0..10)` 的生成算法、进程尾字节 `67..69` 与每调用变化字节 `a` / `tail_a` 的 native 生产者在本黑盒向量集中未闭合；已排除 `nonce` 为通用 LCG（2^32 / 2^64 全窗口）、`lrand48`/`mrand48`（mod 2^48、a=0x5DEECE66D）及单调/等差序列。已定位的 `sub_54b70`（`dst[i] = src2[i] ^ (src1[i] - 0x81)`）仅解码输出键名与 `avg_getSecurityFactors`，载荷生产进入 AVMP VM（见 `static_findings.md` 与 `avmp/README.md`）。
