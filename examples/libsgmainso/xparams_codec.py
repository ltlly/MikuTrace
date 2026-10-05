"""SG 70102 五个输出参数的编解码参考实现（SG 6.8.260602 / 千问 7.3.6.3039）。

五个参数的结构结论（由 135 组真值向量 + 6 个独立进程验证）：

| 参数 | 传输编码 | 载荷字节 | 变化性 |
|---|---|---|---|
| `x-sign`    | 标准 Base64（`+/`），无 padding | 76 定长 | 编码层=2 字节交替掩码；载荷=常量模板+计数器+每调用随机量 |
| `x-mini-wua`| 标准 Base64（`+/`），带 padding | 155 定长 | 每调用全变 |
| `x-sgext`   | 标准 Base64（`+/`），带 padding | 467..688 **变长** | 每调用变化，长度随内容变化 |
| `x-umt`     | 标准 Base64 | 24 定长 | **设备级恒定**（跨 6 个进程取值唯一） |
| `wua`       | `TPEO_` 前缀 + **标准 Base64**（`+/`），带 padding | 208（少数 192） | 每调用全变 |

`x-sign` 的载荷布局见 `xsign_format.md` / `xsign_codec.py`；本模块负责五个参数的
统一编解码与一致性校验。

**未确定**：四个每调用变化参数的**生成算法**。已确定它们的编码层可无损剥离，
但明文来源需要 native 生产者侧逻辑（见 known_offsets.json 的 trace_findings）。

用法：
    python3 xparams_codec.py --selftest
    python3 xparams_codec.py --decode <json>          # {"x-sign": "...", "wua": "..."}
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib

import xsign_codec as xs

# ── 传输层 ────────────────────────────────────────────────────────────
WUA_PREFIX = "TPEO_"


def b64_decode(s: str, url: bool = False) -> bytes:
    core = s.strip().rstrip("=")
    if url:
        core = core.replace("-", "+").replace("_", "/")
    return base64.b64decode(core + "=" * ((4 - len(core) % 4) % 4))


def b64_encode(b: bytes, url: bool = False) -> str:
    s = base64.b64encode(b).decode()
    if url:
        s = s.replace("+", "-").replace("/", "_")
    return s


def decode_wua(wua: str) -> dict:
    """wua = 5 字符常量前缀 + 标准 Base64 载荷。

    注意: 前缀里的 '_' 容易让人误判成 base64url, 但载荷部分实际只用标准字母表
    (含 '+' '/' , 字符集恰为 64 个字母数字 + '=')。
    """
    if not wua.startswith(WUA_PREFIX):
        raise ValueError(f"wua 缺少 {WUA_PREFIX!r} 前缀")
    return {"prefix": WUA_PREFIX, "payload": b64_decode(wua[len(WUA_PREFIX):])}


def encode_wua(payload: bytes) -> str:
    return WUA_PREFIX + b64_encode(payload)


# ── x-mini-wua: 前 2 字节交替掩码 ─────────────────────────────────────
# 实测: 偶数位取值只有 {0x68,0x69,0x6a,0x6b}, 奇数位取值恒为 4 的倍数,
# 且异或掉后位置 0/1 归零 —— 与 x-sign 的 2 字节掩码同构。
MINI_WUA_MASK_START = 2


def unmask_mini_wua(b: bytes) -> bytes:
    m0, m1 = b[0], b[1]
    out = bytearray(b)
    for i in range(MINI_WUA_MASK_START, len(b)):
        out[i] ^= (m0 if i % 2 == 0 else m1)
    return bytes(out)


def apply_mask_mini_wua(n: bytes, mask2: bytes) -> bytes:
    m0, m1 = mask2[0], mask2[1]
    out = bytearray(n)
    for i in range(MINI_WUA_MASK_START, len(b_out := n)):
        out[i] = n[i] ^ (m0 if i % 2 == 0 else m1)
    out[0], out[1] = m0, m1
    return bytes(out)


# ── 五个参数的统一拆解 ─────────────────────────────────────────────────
def decode_all(sample: dict) -> dict:
    out = {}
    if sample.get("x-sign"):
        out["x-sign"] = xs.decode(sample["x-sign"], sample.get("x-umt"))
    if sample.get("x-mini-wua"):
        raw = b64_decode(sample["x-mini-wua"])
        out["x-mini-wua"] = {
            "mask": raw[:2].hex(),
            "payload": unmask_mini_wua(raw).hex(),
        }
    if sample.get("x-sgext"):
        raw = b64_decode(sample["x-sgext"])
        out["x-sgext"] = {"header": raw[:2].hex(), "payload": raw[2:].hex(),
                          "length": len(raw)}
    if sample.get("x-umt"):
        out["x-umt"] = b64_decode(sample["x-umt"]).hex()
    if sample.get("wua"):
        d = decode_wua(sample["wua"])
        out["wua"] = {"prefix": d["prefix"], "payload": d["payload"].hex()}
    return out


def _load_vectors():
    p = pathlib.Path(__file__).resolve().parent / "test_vectors.json"
    d = json.loads(p.read_text())
    out = []
    for key in ("oracle_vectors", "diff_vectors", "fixed_vectors"):
        for v in d.get(key, []):
            v = dict(v)
            if not v.get("x-sign") and v.get("sign"):
                v["x-sign"] = v["sign"]
            if v.get("x-sign"):
                out.append(v)
    return out


def _selftest() -> int:
    V = _load_vectors()
    print(f"向量 {len(V)}")
    fails = []

    # 1) x-sign 载荷级往返
    ok = 0
    for v in V:
        d = xs.decode(v["x-sign"])
        back = xs.encode({k: d[k] for k in
                          ("a", "nonce", "device_blob", "tail_a", "counter", "mask", "header")})
        if b64_decode(back) == b64_decode(v["x-sign"]):
            ok += 1
    print(f"x-sign     decode->encode 载荷往返 {ok}/{len(V)}")
    if ok != len(V):
        fails.append("x-sign")

    # 2) x-umt: 设备级恒定
    umts = {v["x-umt"] for v in V if v.get("x-umt")}
    print(f"x-umt      全量取值 {len(umts)} 种: {sorted(umts)}")
    print(f"           解码长度 {sorted({len(b64_decode(u)) for u in umts})} 字节")
    if len(umts) != 1:
        fails.append("x-umt-const")

    # 3) 其余三项: 编码层可无损剥离 + 长度恒定性
    for name, exp in (("x-mini-wua", 155), ("x-sgext", None), ("wua", None)):
        vals = [v[name] for v in V if v.get(name)]
        if name == "wua":
            decoded = [b64_decode(x[len(WUA_PREFIX):]) for x in vals]
        else:
            decoded = [b64_decode(x) for x in vals]
        lens = sorted({len(b) for b in decoded})
        note = "定长" if len(lens) == 1 else f"变长 {lens[:4]}…({len(lens)} 种)"
        print(f"{name:11s} n={len(vals)} 解码长度 {note}")
        if exp is not None and lens != [exp]:
            fails.append(name)

    # 4) wua 前缀恒定性
    w = [v["wua"] for v in V if v.get("wua")]
    pre_ok = all(x.startswith(WUA_PREFIX) for x in w)
    print(f"wua        前缀 {WUA_PREFIX!r} 恒定: {pre_ok} ({len(w)} 个样本)")
    if not pre_ok:
        fails.append("wua-prefix")
    # 往返
    rt = sum(1 for x in w
             if encode_wua(b64_decode(x[len(WUA_PREFIX):])) == x)
    print(f"wua        base64url 往返 {rt}/{len(w)}")
    if rt != len(w):
        fails.append("wua-rt")

    # 5) x-mini-wua 掩码可逆
    mw = [b64_decode(v["x-mini-wua"]) for v in V if v.get("x-mini-wua")]
    rt = sum(1 for b in mw
             if apply_mask_mini_wua(unmask_mini_wua(b), b[:2]) == b)
    print(f"x-mini-wua 2 字节掩码往返 {rt}/{len(mw)}")
    if rt != len(mw):
        fails.append("mini-wua-mask")
    m0s = sorted({b[0] for b in mw})
    m1s = sorted({b[1] for b in mw})
    print(f"           掩码字节0 取值 {['%02x' % x for x in m0s]}")
    print(f"           掩码字节1 均为 4 的倍数: {all(x % 4 == 0 for x in m1s)} ({len(m1s)} 种)")

    # 6) x-sgext 头 2 字节恒定
    sg = [b64_decode(v["x-sgext"]) for v in V if v.get("x-sgext")]
    hdr0 = sorted({b[0] for b in sg})
    hdr01 = sorted({b[1] for b in sg})
    print(f"x-sgext   字节0 恒定取值 {['%02x' % x for x in hdr0]}; "
          f"字节1 取值 {len(hdr01)} 种 (样本 {len(sg)})")
    if len(hdr0) != 1:
        fails.append("sgext-header0")

    print("\n失败项:", fails if fails else "无")
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--decode", help="JSON dict of the five params")
    a = ap.parse_args()
    if a.decode:
        print(json.dumps(decode_all(json.loads(a.decode)), indent=2))
        return 0
    if a.selftest:
        return _selftest()
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
