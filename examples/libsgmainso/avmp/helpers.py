"""AVMP native helper 原语（从 JIT 区反汇编还原，libsgmainso-6.8.260602）。

JIT 区的 native helper 全部带 canary 前缀：
    sub sp, sp, #N
    ... mrs x?, tpidr_el0 / ldr [x?, #0x28]   (栈保护)
    mov wN, #<canary> ; ldr wM, [page, #0x68] ; add
    <udf 里的密钥> ldrsw / eor / mvn / add    (解出 br 目标)
真正函数体在 stub 之后的 JIT 流里，**全部在 JIT 区内**（不是动态解密到别处），
只是入口做了控制流平坦化。本模块给出语义等价实现。

## 已知原语

### sbox_xor_16 @ JIT+0xf124（设备地址 0x743c226ad4）
字节级 S 盒变换，展开成 16 字节一组：

    out[i] = in[i] ^ S[ (&out[i]) & 0xff ]

S 盒基址 = `ctx + 0x1e0`（从 `ldr x9, [x19, #0x1e0]` 读出）。
函数签名：`(ctx, key_or_sbox_owner, state) -> void`，就地改写缓冲区。

反汇编证据（每组 8 字节，展开 4 组共 16 字节）：

    0x...b3c  and  x8, x20, #0xff      ; 目的地址低 8 位
    0x...b40  ldr  x9, [x19, #0x1e0]   ; S 盒
    0x...b48  ldrb w8, [x9, x8]        ; S[idx]
    0x...b4c  ldrb w9, [x20]           ; in[i]
    0x...b50  eor  w8, w9, w8          ; in[i] ^ S[idx]
    0x...b58  strb w8, [x20]           ; out[i]
    ...                                   ; 后索引 ldrb w9,[x10,#1]! 逐字节推进

16 字节的展开顺序是 unrolled 的：先 `ldrb w9,[x20]` 取 in[0]，
之后用 `ldrb w9, [x10, #1]!` 预取下一字节，最后一组是 `ldrb w9,[x20,#0xe]!`。

### mem_rw @ JIT+0xe9b8（设备地址 0x743c226368）

注意它**不是** canary stub，而是一段 inline 小函数（紧跟在另一个 helper 的
`ret` 之后），所以不出现在 `find_canary_stubs()` 的结果里。
VM 的 load/store 辅助：

    x8 = *(x1 + 0x240)
    x8 = *(x8 + 0x1a0)
    return x8 + x2

frame_id 539/540 通过它做「基址 + 偏移」的内存访问。
"""


def sbox_xor_16(buf, sbox, offset=0):
    """就地对 buf[offset:offset+16] 做 sbox_xor_16。

    buf   可写 bytearray
    sbox  256 字节的替换表（设备侧来自 ctx+0x1e0）
    """
    for i in range(16):
        p = offset + i
        buf[p] ^= sbox[p & 0xFF]


def mem_rw(ctx, off):
    """VM 的 load 寻址辅助：返回 `*( *(ctx + 0x240) + 0x1a0 ) + off`。

    对应 JIT+0xe9b8：
        ldr x8, [x1, #0x240]     ; x8 = *(ctx + 0x240)      一级
        ldr x8, [x8, #0x1a0]     ; x8 = *(x8 + 0x1a0)       二级
        add x0, x8, x2           ; + off
    返回的是**地址**，不解引用第三次（真实解引用由调用方的 ldr 指令完成）。
    """
    ptr1 = int.from_bytes(ctx[0x240:0x248], "little")
    ptr2 = int.from_bytes(ctx[ptr1 + 0x1A0:ptr1 + 0x1A8], "little")
    return ptr2 + off


def locate_helpers(jit_base, jit_data):
    """按**指令模式**在 JIT 区里定位已知 helper 的偏移。

    不能硬编码偏移：JIT 每次运行的布局/基址都不同（同一份 so 在不同
    进程里编出来的 handler 地址完全不一样）。所以这里用特征定位：

    * ``sbox_xor_16`` —— 读 ``[ctx+0x1e0]`` 取 S 盒且有 >=2 个 ``strb``
    * ``mem_rw``      —— 连续 ``ldr [xN,#0x240]`` / ``ldr [xN,#0x1a0]``
    """
    from .arm64 import MD

    def body(addr, size=0x400):
        off = addr - jit_base
        if off < 0 or off + size > len(jit_data):
            return []
        return list(MD.disasm(jit_data[off:off + size], addr))

    out = {}
    for addr, _ in find_canary_stubs(jit_base, jit_data):
        ins = body(addr)
        if not ins:
            continue
        if any("#0x1e0" in i.op_str for i in ins[:60]) and \
                sum(1 for i in ins[:60] if i.mnemonic == "strb") >= 2:
            out.setdefault("sbox_xor_16", addr - jit_base)
        for k, i in enumerate(ins):
            if k + 1 < len(ins) and i.mnemonic == "ldr" and "#0x240" in i.op_str \
                    and ins[k + 1].mnemonic == "ldr" and "#0x1a0" in ins[k + 1].op_str:
                out.setdefault("mem_rw", addr - jit_base)
                break
    # mem_rw 是 inline 小函数（不是 canary stub），全 JIT 区按指令模式找:
    #   ldr xN, [x1, #0x240] ... ldr xM, [xN, #0x1a0] ; add x0, xM, x2
    if "mem_rw" not in out:
        dec = {}
        for off in range(0, len(jit_data) - 0x30, 4):
            ins = next(MD.disasm(jit_data[off:off + 4], jit_base + off), None)
            if ins is not None:
                dec[off] = (ins.mnemonic, ins.op_str)
        offs = sorted(dec)
        for k, off in enumerate(offs):
            m, o = dec[off]
            if m != "ldr" or "#0x240" not in o:
                continue
            for j in range(k + 1, min(k + 6, len(offs))):
                m2, o2 = dec[offs[j]]
                if m2 == "ldr" and "#0x1a0" in o2:
                    out["mem_rw"] = off
                    break
            if "mem_rw" in out:
                break
    return out


def find_inline_helpers(jit_base, jit_data):
    """扫出 inline 小函数（无 canary 前缀，紧跟别的函数 `ret` 之后）。

    特征：`stp x29, x30, [sp, #-0x20]!` + 三四条指令 + `ldp ... [sp], #0x20` + `ret`。
    设备侧 mem_rw 属于这一类。
    """
    import struct

    out = []
    for off in range(0, len(jit_data) - 0x20, 4):
        (w,) = struct.unpack_from("<I", jit_data, off)
        if (w & 0xFFC07FFF) != 0xA9007BFD:  # stp x29,x30,[sp,#-0x20]!
            continue
        out.append(jit_base + off)
    return out


def find_canary_stubs(jit_base, jit_data):
    """在 JIT 区里扫出全部 canary stub（`sub sp,sp,#imm` + `mrs x?, tpidr_el0`）。

    返回 [(绝对地址, 栈帧大小), ...]，设备侧实测 40 个。
    """
    import struct

    out = []
    for off in range(0, len(jit_data) - 0x20, 4):
        (w,) = struct.unpack_from("<I", jit_data, off)
        if (w & 0xFFC003FF) != 0xD10003FF:
            continue
        for q in range(4, 0x20, 4):
            (w2,) = struct.unpack_from("<I", jit_data, off + q)
            if (w2 & 0xFFFFFFE0) == 0xD53BD040:  # mrs x?, tpidr_el0
                out.append((jit_base + off, (w >> 10) & 0xFFF))
                break
    return out
