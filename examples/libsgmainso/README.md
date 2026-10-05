# libsgmainso / x-sign 逆向档案

目标：`com.aliyun.tongyi`（千问）7.3.6.3039 内置 Alibaba SecurityGuard
`6.8.260602` 的 `libsgmainso-6.8.260602.so`，逆向 mtop 请求签名
`x-sign` / `x-mini-wua` / `x-sgext` / `x-umt` / `wua` 的生成逻辑。

## 文件

| 文件 | 内容 |
|---|---|
| `known_offsets.json` | 目标坐标：JNI 入口、70102 语义、12 个入参、canonical INPUT 布局、trace 取证结论（解码器、输出键表） |
| `xsign_format.md` | x-sign 76 字节载荷的字段布局、编码层、输入依赖判定、未知项 |
| `xsign_codec.py` | x-sign 编解码参考实现，`--selftest` 对全部向量做载荷级往返校验 |
| `xparams_format.md` | 五个输出参数（x-sign / x-mini-wua / x-sgext / x-umt / wua）的结构、编码层与「能否离线生成」判定 |
| `xparams_codec.py` | 五个参数统一编解码 + 一致性自检 |
| `test_vectors.json` | 135 组真值向量（`oracle_vectors` 76 / `diff_vectors` 29 / `fixed_vectors` 30），每组带完整 12 个入参 |
| `fr_session.py` | Frida 会话驱动（Python API + 显式注入 java bridge + 可选 adb UI 驱动） |
| `diff_probe.js` | 单字段差分探针（70102 定点调用） |

## 采集到的 so 镜像（不在仓库内）

6.8 的 so 在 APK 里**未加密**（2172 条明文字符串；段表被剥但 program header 与
STRTAB 完好，R+X 段 `file offset 0 == vaddr`，可按 flat base 0 直接反汇编）：

```bash
python3 - <<'PY'
import zipfile
z = zipfile.ZipFile('qwen_703.apk')
open('libsgmainso-6.8.260602.so','wb').write(
    z.read('lib/arm64-v8a/libsgmainso-6.8.260602.so'))
PY
```

`avg_getSecurityFactors` / `x-mini-wua` 等字符串**不在文件里**，因为它们是运行时
解码出来的（见 `known_offsets.json` 的 `trace_findings.decode_loop`）。

## 采集 trace

```bash
./tracemiku trace \
  --pkg <pkg> --spawn --so libsgmainso \
  --method doCommandNative --cmd 70102 --cmd-arg 2 \
  --remote 127.0.0.1:27099 --transport frida \
  --out traces/<run> --duration 30 --max-records 24000
```

该 app 会在被 Stalker 挂上后让 adbd 的 subprocess 路径失效，因此**必须用
`--transport frida`**（host 驱动分块回传，全程不 fork）；详见
`docs/TOOLING_GAPS.md` 第 8 条。
