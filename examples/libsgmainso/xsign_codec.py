"""x-sign 载荷编解码参考实现（SG 6.8.260602 / 千问 7.3.6.3039）。

范围声明（重要）：

**已完全确定、可逐字节复现**
  - 外层编码：标准 Base64 字母表（含 '+' / '/'，非 base64url），解码固定 76 字节
  - 外层掩码：2 字节交替，`n[i] = b[i] ^ b[74 + (i & 1)]`，仅对 i >= 10；
    掩码字节就是载荷自己的最后两字节
  - 归一化后的字段边界（对 30 次同参连续调用实测，见 FIELDS）

**未确定、本实现不猜测**
  - 44 字节设备/会话常量块（device_blob）的生成过程
  - 11 字节每调用变化量（nonce）的生成过程
  - 计数器初值的播种源

这三项需要 native 生产者逻辑或设备会话密钥。本实现把它们当作**外部输入**：
给定这三项即可逐字节复现设备输出，但无法自行生成。

用法：
    python3 xsign_codec.py --selftest
    python3 xsign_codec.py --decode <x-sign> [--umt <base64>]
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import struct

REC_SIGN_LEN = 76
MASK_START = 10
MASK_EVEN, MASK_ODD = 74, 75
COUNTER_OFF = 72                      # 大端 16 位计数器
LEN_FIELD_OFF, LEN_FIELD = 22, bytes.fromhex("00000183")
BLOB_OFF, BLOB_LEN = 26, 44
HEADER = bytes.fromhex("6b364c827d34e710")   # env=0；env=2 时前 4 字节与第 6 字节改变

# 归一化后的字段布局（偏移, 长度, 名称, 30 次同参调用内是否恒定）
FIELDS = [
    (0, 8, "header", True),    # 常量（随 env 变）
    (8, 1, "pad8", True),      # 恒为 0x00
    (9, 1, "a", False),        # 每调用变化
    (10, 1, "pad10", True),    # 恒为 0x00
    (11, 11, "nonce", False),  # 每调用全变
    (22, 4, "len_field", True),  # 恒为 00000183 = 387（语义未确定）
    (26, 44, "device_blob", True),  # 设备/会话常量；内含 16 字节 x-umt
    (70, 2, "tail_a", False),  # 每调用变化（来源未定）
    (72, 2, "counter", False),  # 大端 16 位，每次 70102 调用 +0x10
    (74, 2, "mask", False),    # 掩码自身
]


def b64decode(s: str) -> bytes:
    t = s.rstrip("=")
    return base64.b64decode(t + "=" * (-len(t) % 4))


def b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode().rstrip("=")


def unmask(b: bytes) -> bytes:
    if len(b) != REC_SIGN_LEN:
        raise ValueError(f"期望 {REC_SIGN_LEN} 字节, 得到 {len(b)}")
    k0, k1 = b[MASK_EVEN], b[MASK_ODD]
    out = bytearray(b)
    for i in range(MASK_START, REC_SIGN_LEN):
        out[i] ^= (k0 if i % 2 == 0 else k1)
    return bytes(out)


def apply_mask(n: bytes, mask: bytes) -> bytes:
    k0, k1 = mask[0], mask[1]
    out = bytearray(n)
    for i in range(MASK_START, REC_SIGN_LEN):
        out[i] ^= (k0 if i % 2 == 0 else k1)
    return bytes(out)


def decode(xsign: str, umt_b64: str | None = None) -> dict:
    raw = b64decode(xsign)
    n = unmask(raw)
    out: dict = {"encoded_len": len(raw)}
    for off, ln, name, _ in FIELDS:
        out[name] = n[off:off + ln].hex()
    out["counter"] = struct.unpack_from(">H", n, COUNTER_OFF)[0]
    out["a"] = n[9]
    out["mask"] = raw[MASK_EVEN:MASK_ODD + 1].hex()
    if umt_b64:
        umt = b64decode(umt_b64)
        out["umt_offset_in_blob"] = bytes.fromhex(out["device_blob"]).find(umt)
    return out


def encode(f: dict) -> str:
    """从结构化字段逐字节重建 x-sign。缺失的外部输入明确报错，不猜测。"""
    need = ["a", "nonce", "device_blob", "tail_a", "counter", "mask"]
    missing = [k for k in need if k not in f]
    if missing:
        raise KeyError("以下字段是外部输入（生成过程未确定），必须由调用方提供: "
                       + ", ".join(missing))
    n = bytearray(REC_SIGN_LEN)
    n[0:8] = bytes.fromhex(f.get("header", HEADER.hex()))
    n[8] = 0
    n[9] = f["a"] & 0xFF
    n[10] = 0
    n[11:22] = bytes.fromhex(f["nonce"])
    n[LEN_FIELD_OFF:LEN_FIELD_OFF + 4] = LEN_FIELD
    blob = bytes.fromhex(f["device_blob"])
    if len(blob) != BLOB_LEN:
        raise ValueError(f"device_blob 必须是 {BLOB_LEN} 字节, 得到 {len(blob)}")
    n[BLOB_OFF:BLOB_OFF + BLOB_LEN] = blob
    n[70:72] = bytes.fromhex(f["tail_a"])
    struct.pack_into(">H", n, COUNTER_OFF, f["counter"] & 0xFFFF)
    # 归一化空间里 74/75 恒为 0；掩码是 apply 阶段才产生的字节
    n[74:76] = b"\x00\x00"
    mask = bytes.fromhex(f["mask"])
    if len(mask) != 2:
        raise ValueError("mask 必须是 2 字节")
    return b64encode(apply_mask(bytes(n), mask))


def _selftest() -> int:
    here = pathlib.Path(__file__).resolve().parent
    d = json.loads((here / "test_vectors.json").read_text())
    vecs = [v for v in (d.get("oracle_vectors", []) + d.get("fixed_vectors", [])
                        + d.get("diff_vectors", []))
            if v.get("x-sign") or v.get("sign")]
    for v in vecs:
        if not v.get("x-sign") and v.get("sign"):
            v["x-sign"] = v["sign"]
    total = ok = 0
    counters, blobs, umt_pos = [], set(), set()
    for v in vecs:
        total += 1
        x = v["x-sign"]
        dec = decode(x, v.get("x-umt"))
        counters.append(dec["counter"])
        blobs.add(dec["device_blob"])
        if v.get("x-umt") and dec.get("umt_offset_in_blob", -1) >= 0:
            umt_pos.add(dec["umt_offset_in_blob"])
        back = encode({"a": dec["a"], "nonce": dec["nonce"], "device_blob": dec["device_blob"],
                       "tail_a": dec["tail_a"], "counter": dec["counter"],
                       "mask": dec["mask"], "header": dec["header"]})
        # 判定口径: 载荷 76 字节必须逐字节相同。字符串层面最后一个 base64 字符
        # 的低 4 位是编码器未清零的丢弃位, 不属于签名内容 (实测 135 组里仅 4 组
        # 恰好为 0), 因此不作为一致性判据。
        if b64decode(back) == b64decode(x):
            ok += 1
        else:
            print(f"  载荷不匹配 {v.get('tag') or v.get('i')}: {x[:24]}… vs {back[:24]}…")
    steps = sorted({b - a for a, b in zip(counters, counters[1:]) if 0 < b - a < 0x10000})
    print(f"向量 {total}, decode->encode 载荷逐字节还原 {ok}")
    print(f"计数器步长取值集合: {steps} (期望 [16] = 每次调用 +0x10)")
    print(f"device_blob 取值种类: {len(blobs)} (同进程内期望 1)")
    print(f"x-umt 在 blob 内偏移集合: {sorted(umt_pos)}")
    return 0 if (ok == total and steps == [16] and len(blobs) == 1) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--decode")
    ap.add_argument("--umt")
    a = ap.parse_args()
    if a.decode:
        print(json.dumps(decode(a.decode, a.umt), indent=2))
        return 0
    if a.selftest:
        return _selftest()
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
