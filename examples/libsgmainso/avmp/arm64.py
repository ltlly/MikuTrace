"""AVMP handler 所需的 ARM64 子集解释器（capstone 解码 + 直接解释助记符）。

handler 机器码由设备侧 hook libsgmainso+0x17c680 的 dispatch 表 x23[frame_id]
落盘得到（avmp/handlers.txt，每条 192 字节）。

VM 结构（见 static_findings.md 2.11）：
  x21  帧指针，16 字节/帧
  x25  寄存器文件，8 字节/槽
  x23  frame_id -> handler 地址表
  x27  [x27+8] 保存帧指针
"""

import re

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

MASK64 = (1 << 64) - 1
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.detail = False


def _sx(v, bits):
    v &= (1 << bits) - 1
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def s64(v):
    return _sx(v, 64)


def s32(v):
    return _sx(v, 32)


class Memory:
    """字节可寻址内存。分配稀疏页；越界读返回 0，写入自动分配。"""

    def __init__(self):
        self.pages = {}

    def _pg(self, addr, create):
        key = addr >> 12
        pg = self.pages.get(key)
        if pg is None:
            if not create:
                return None
            pg = bytearray(0x1000)
            self.pages[key] = pg
        return pg

    def read(self, addr, size):
        out = 0
        for i in range(size):
            pg = self._pg(addr + i, False)
            if pg is not None:
                out |= pg[(addr + i) & 0xFFF] << (8 * i)
        return out

    def write(self, addr, size, value):
        value &= (1 << (size * 8)) - 1
        for i in range(size):
            pg = self._pg(addr + i, True)
            pg[(addr + i) & 0xFFF] = (value >> (8 * i)) & 0xFF

    def read_cstr(self, addr, limit=8192):
        out = bytearray()
        while len(out) < limit:
            b = self.read(addr + len(out), 1)
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def write_bytes(self, addr, data):
        for i, b in enumerate(data):
            self.write(addr + i, 1, b)

    def snapshot(self, addr, size):
        return bytes(self.read(addr + i, 1) for i in range(size))


class Cpu:
    """x0..x30 + sp/pc + NZCV。"""

    def __init__(self, mem):
        self.x = [0] * 31
        self.sp = 0
        self.pc = 0
        self.mem = mem
        self.n = 1
        self.z = 0
        self.c = 0
        self.v = 0
        self.steps = 0
        self.max_steps = 50_000_000
        self.halted = False
        self.callbacks = {}

    def g(self, n):
        return self.sp if n == 31 else self.x[n]

    def s(self, n, v):
        v &= MASK64
        if n == 31:
            self.sp = v
        else:
            self.x[n] = v

    def w(self, n):
        return self.g(n) & 0xFFFFFFFF

    def sw(self, n, v):
        self.s(n, v & 0xFFFFFFFF)

    # ---- 条件码 -----------------------------------------------------
    def set_nz(self, val):
        val &= 0xFFFFFFFF
        self.n = 1 if val & 0x80000000 else 0
        self.z = 1 if val == 0 else 0

    def set_add(self, a, b, r):
        a &= 0xFFFFFFFF
        b &= 0xFFFFFFFF
        r &= 0xFFFFFFFF
        self.set_nz(r)
        self.c = 1 if r < a else 0
        self.v = 1 if s32(a) + s32(b) != s32(r) else 0

    def set_sub(self, a, b, r):
        a &= 0xFFFFFFFF
        b &= 0xFFFFFFFF
        r &= 0xFFFFFFFF
        self.set_nz(r)
        self.c = 1 if a >= b else 0
        self.v = 1 if s32(a) - s32(b) != s32(r) else 0

    def cond(self, c):
        return {
            0: self.z == 1, 1: self.z == 0, 2: self.c == 1, 3: self.c == 0,
            4: self.n == 1, 5: self.n == 0, 6: self.v == 1, 7: self.v == 0,
            8: self.c == 1 and self.z == 0, 9: self.c == 0 or self.z == 1,
            10: self.n == self.v, 11: self.n != self.v,
            12: self.z == 0 and self.n == self.v,
            13: self.z == 1 or self.n != self.v,
            14: self.z == 0, 15: self.z == 1,
        }[c]


_RN = re.compile(r"^(?:x|w)(\d+)$")
_RM = re.compile(r"^(?:x|w)(\d+)$")


def _reg(tok):
    m = _RN.match(tok)
    if not m:
        raise ValueError("not a register: %r" % tok)
    n = int(m.group(1))
    if n == 31 and tok[0] == "w":
        n = 31
    return n, tok[0]


def _memop(op_str):
    """`[xN, #imm]` / `[xN]` / `[xN, xM]` / `[xN, wM, sxtw #k]` -> (rn, offset_expr)"""
    body = op_str.strip()
    if body.endswith("]!"):
        body = body[:-1]          # 后索引寻址
    body = body[1:-1]
    parts = [p.strip() for p in body.split(",")]
    rn, _ = _reg(parts[0])
    if len(parts) == 1:
        return rn, ("imm", 0)
    if len(parts) == 2:
        if parts[1].startswith("#"):
            return rn, ("imm", int(parts[1][1:], 0))
        m, _w = _reg(parts[1])
        return rn, ("reg", m)
    if len(parts) == 3 and "lsl" in parts[2]:
        m, _w = _reg(parts[1])
        k = int(parts[2].split("#")[1], 0)
        return rn, ("sxtw", (m, k))
    if len(parts) == 3 and parts[2].startswith("sxtw"):
        m, _w = _reg(parts[1])
        k = int(parts[2].split("#")[1], 0)
        return rn, ("sxtw", (m, k))
    raise ValueError("unsupported memop %r" % op_str)


class AvmpVm:
    """AVMP VM：帧(x21) + 寄存器文件(x25) + frame_id->handler 表。"""

    HALT = "halt"
    NATIVE = "native"

    def __init__(self, handlers, mem, native_hook=None):
        self.handlers = handlers
        self.mem = mem
        self.frame = 0
        self.frame_area = 0x200000000
        self.xtab_area = None
        self.regs = [0] * 256
        self.native_hook = native_hook or (lambda addr, cpu: 0)
        self.steps = 0
        self.next_handler = None
        self.max_steps = 5_000_000
        self.trace = []
        self.halted = False

    # ---- 帧与寄存器 -------------------------------------------------
    def dispatch(self, addr):
        """执行一条 JIT handler：从真实地址反汇编，遇到 br/ret 即止。"""
        cpu = Cpu(self.mem)
        addr &= MASK64
        cpu.s(30, addr)
        cpu.s(21, self.frame_area + self.frame)
        cpu.s(25, REGS_AREA)
        cpu.s(27, SAVE_AREA)
        if self.xtab_area is not None:
            cpu.s(23, self.xtab_area)
        cpu.pc = addr
        # 跳板（id=2 之类）用 `br` 跳到 JIT 流里紧邻的下一个内联 handler，
        # 只有写了 [x27+8]（保存帧指针）才代表本帧结束、要换帧。
        for _ in range(64):
            moved = False
            for ins in MD.disasm(self.mem.snapshot(cpu.pc, HANDLER_MAX), cpu.pc):
                self._frame_saved = False
                self.exec_one(cpu, ins)
                if cpu.halted:
                    break
                if ins.mnemonic == "br":
                    if self._frame_saved:
                        self._frame_saved = False
                        break
                    moved = True
                    break
                if ins.mnemonic in ("ret", "eret"):
                    cpu.halted = True
                    break
            if cpu.halted or not moved:
                break
        # handler 对 x21 的写回即 VM 的帧推进
        self.frame = (cpu.g(21) - self.frame_area) & MASK64


    def run(self, max_steps=None):
        limit = max_steps or self.max_steps
        while self.steps < limit and not self.halted:
            self.step()
        return self.halted

    def step(self, handler=None):
        """执行当前帧的 handler。

        VM 的 handler 选择规则：帧 F 自己开头 2 字节就是 **F 的 handler id**
        （前一帧末尾的 `ldrh w?, [x21,#0x10]!` 读的正是下一帧 F 的 id，
        再经 x23 表取出并 `br` 过去）。所以 handler(F) = x23[id_at(F)]。
        """
        if handler is None:
            handler = self.handlers.get(self.frame_id())
            if handler is None:
                raise KeyError(
                    "frame 0x%x 的 handler id=%d 不在 handlers_map 中"
                    % (self.frame, self.frame_id())
                )
        self.steps += 1
        self._cur_fid = self.frame_id()
        self.dispatch(handler & MASK64)
        return handler

    def frame_id(self):
        """本帧的 handler id。

        id 在**帧内 +0x10** 处（不是帧首）。已用设备侧权威执行序列核对：
        `u16_at(F+0x10)` 与记录到的真实 handler id 107/107 一致，
        而 `u16_at(F+0)` / `u16_at(F+0x2..0xe)` 全都不匹配。
        """
        return int.from_bytes(
            self.mem.snapshot(self.frame_area + self.frame + 0x10, 2), "little"
        )

    def frame_bytes(self):
        """当前帧的 16 字节。x21 指向帧首，+0x10 是下一帧的 handler id。"""
        return self.mem.snapshot(self.frame_area + self.frame, 16)

    def frame_u8(self, i):
        return self.mem.read(self.frame_area + self.frame + i, 1)

    def read_frame(self, cpu, off, size):
        return self.mem.read(self.frame_area + self.frame + off, size)

    def exec_one(self, cpu, ins):
        m = ins.mnemonic
        o = ins.op_str
        try:
            self._exec(cpu, m, o, ins)
        except NotImplementedError:
            raise
        except Exception as exc:  # pragma: no cover - 诊断用
            raise RuntimeError(
                "handler %s: %s %s @0x%x (frame=0x%x) failed: %s"
                % (self._cur_fid, m, o, ins.address, self.frame, exc)
            ) from exc

    _cur_fid = 0

    def _exec(self, cpu, m, o, ins):
        m0 = m

        # ---- 分支 / 调用 ----
        if m == "b" and ins.op_str.startswith("#"):
            cpu.pc = (ins.address + int(ins.op_str[1:], 0)) & MASK64
            return
        if m == "br":
            cpu.pc = cpu.g(int(o.split(",")[0][1:] if o[0] == "x" else 0))
            return
        if m == "bl" and o.startswith("#"):
            target = (ins.address + int(o[1:], 0)) & MASK64
            if target in self.native_hook_addr:
                r = self.native_hook_addr[target](cpu)
                cpu.s(0, r & MASK64)
                return
            raise NotImplementedError("bl to 0x%x" % target)
        if m0 == "bl":
            parts = o.split(",")
            cpu.s(int(parts[0][1:]), (ins.address + 4) & MASK64)
            return
        if m.startswith("b.") and m != "b":
            cc = m[2:]
            num = {"eq": 0, "ne": 1, "hs": 2, "lo": 3, "mi": 4, "pl": 5,
                   "vs": 6, "vc": 7, "hi": 8, "ls": 9, "ge": 10, "lt": 11,
                   "gt": 12, "le": 13, "al": 14, "nv": 15}[cc]
            if o.startswith("#"):
                if cpu.cond(num):
                    cpu.pc = (ins.address + int(o[1:], 0)) & MASK64
                return
            return
        if m in ("cbz", "cbnz"):
            rn, w32 = _reg(o.split(",")[0])
            val = cpu.w(rn) if w32 == "w" else cpu.g(rn)
            zero = val == 0
            if (m == "cbz") == zero:
                cpu.pc = (ins.address + 4) & MASK64
            return
        if m in ("tbz", "tbnz"):
            parts = o.split(",")
            rn, _ = _reg(parts[0])
            bit = int(parts[1][1:], 0)
            is_set = (cpu.g(rn) >> bit) & 1 == 1
            if (m == "tbz") != is_set:
                cpu.pc = (ins.address + 4) & MASK64
            return
        if m in ("ret", "eret"):
            cpu.halted = True
            return
        if m == "nop":
            return

        # ---- 访存 ----
        if m in ("ldr", "ldrb", "ldrh", "ldrsb", "ldrsh", "ldrsw", "ldur",
                 "ldurb", "ldurh", "ldp", "ldurx"):
            if o.count(",") == 1 and o.split(",")[1].strip().startswith("#"):
                parts = [p.strip() for p in o.split(",")]
                rt, _ = _reg(parts[0])
                # capstone 对 LDR-literal 直接给出解析后的绝对地址
                tgt = int(parts[1][1:], 0) & MASK64
                size = {"ldrb": 1, "ldrh": 2, "ldrsb": 1, "ldrsh": 2,
                        "ldrsw": 4}.get(m, 8)
                raw = self.mem.read(tgt, size)
                v = raw
                if m == "ldrsb":
                    v = _sx(raw, 8) & MASK64
                elif m == "ldrsh":
                    v = _sx(raw, 16) & MASK64
                elif m == "ldrsw":
                    v = s32(raw) & MASK64
                elif size == 4:
                    v = s32(raw) & MASK64
                cpu.s(rt, v)
                return
            return self._load(cpu, m, o)
        if m in ("str", "strb", "strh", "stur", "sturb", "sturh", "stp", "stxr",
                 "stlxr"):
            return self._store(cpu, m, o)

        # ---- 立即数运算 ----
        if m in ("mov", "movz"):
            parts = [p.strip() for p in o.split(",")]
            rd, _ = _reg(parts[0])
            imm = int(parts[1][1:], 0) if parts[1].startswith("#") else 0
            if m == "movz" and len(parts) > 2:
                imm << int(parts[2][1:], 0)
            cpu.s(rd, imm & (MASK64 if parts[0][0] == "x" else 0xFFFFFFFF))
            return
        if m in ("movn",):
            parts = [p.strip() for p in o.split(",")]
            rd, _ = _reg(parts[0])
            imm = int(parts[1][1:], 0)
            cpu.s(rd, ~imm & (MASK64 if parts[0][0] == "x" else 0xFFFFFFFF))
            return
        if m in ("movk",):
            parts = [p.strip() for p in o.split(",")]
            rd, _ = _reg(parts[0])
            shift = int(parts[2][1:], 0)
            keep = cpu.g(rd)
            msk = 0xFFFF << shift
            cpu.s(rd, (keep & ~msk) | (int(parts[1][1:], 0) << shift))
            return
        if m in ("mvn",):
            parts = [p.strip() for p in o.split(",")]
            rd, _ = _reg(parts[0])
            rn, _ = _reg(parts[1])
            cpu.s(rd, ~cpu.g(rn) & MASK64)
            return
        if m in ("adrp", "adr"):
            parts = [p.strip() for p in o.split(",")]
            rd, _ = _reg(parts[0])
            imm = int(parts[1][1:], 0)
            if m == "adrp":
                imm <<= 12
            cpu.s(rd, ((ins.address & ~0xFFF) + imm) & MASK64)
            return
        if m in ("add", "adds", "sub", "subs", "cmp", "cmn", "neg", "negs"):
            return self._alu(cpu, m, o)

        # ---- 逻辑 / 移位 / 乘法 ----
        if m in ("and", "ands", "orr", "eor", "bic", "bics", "orn", "eon", "tst"):
            return self._logic(cpu, m, o)
        if m in ("lsl", "lsr", "asr", "ror", "lslv", "lsrv", "asrv", "rorv"):
            return self._shift(cpu, m, o)
        if m in ("mul", "madd", "msub", "smull", "umull", "sdiv", "udiv",
                 "smulh", "umulh"):
            return self._mul(cpu, m, o)
        if m in ("ubfx", "sbfx", "ubfm", "sbfm", "lsl", "lsr", "asr", "extr",
                 "ror"):
            return self._bitfield(cpu, m, o)
        if m in ("csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc",
                 "cneg"):
            return self._condsel(cpu, m, o)
        if m in ("sxtw", "sxtb", "sxth", "uxtw", "uxtb", "uxth", "lsl"):
            return self._extend(cpu, m, o)
        if m in ("dup", "ins", "umov", "movi"):
            return self._dup(cpu, m, o)
        if m in ("ccmp", "ccmn", "cinc", "csinv"):
            return self._condsel(cpu, m, o)
        if m in ("fmov", "fadd", "fsub", "fmul", "fdiv", "fcmp", "scvtf",
                 "fcvtzs", "frint", "fabs", "fneg"):
            raise NotImplementedError("fp insn %s %s" % (m, o))
        raise NotImplementedError("insn %s %s @0x%x" % (m, o, ins.address))

    # ---- 分组实现 ---------------------------------------------------
    def _load(self, cpu, m, o):
        if m == "ldp":
            parts = [p.strip() for p in o.split(",")]
            a, b = parts[0], parts[1]
            rest = ",".join(parts[2:]).strip()[1:-1]
            rn, off = _memop("[" + rest + "]")
            base = cpu.g(rn) + self._off(cpu, off)
            rt1, _ = _reg(a)
            rt2, _ = _reg(b)
            cpu.s(rt1, self.mem.read(base, 8))
            cpu.s(rt2, self.mem.read(base + 8, 8))
            return
        parts = [p.strip() for p in o.split(",")]
        rt, wide = _reg(parts[0])
        rn, off = _memop(",".join(parts[1:]))
        post = o.rstrip().endswith("]!")
        if rn in (21, 25, 27) and self._spec_load(cpu, rn, off, rt, wide, m):
            if post:
                cpu.s(rn, (cpu.g(rn) + self._off(cpu, off)) & MASK64)
            return
        base = (cpu.g(rn) if wide == "x" else cpu.w(rn)) + self._off(cpu, off)
        size = {"b": 1, "h": 2, "w": 4, "": 8}[_sizeletter(m)]
        raw = self.mem.read(base & MASK64, size)
        if m in ("ldrb", "ldurb"):
            v = raw
        elif m in ("ldrsb",):
            v = _sx(raw, 8) & MASK64
        elif m in ("ldrh", "ldurh"):
            v = raw
        elif m in ("ldrsh",):
            v = _sx(raw, 16) & MASK64
        elif m in ("ldrsw",):
            v = s32(raw) & MASK64
        else:
            v = raw if size == 8 else s32(raw) & MASK64
        self._wd(cpu, rt, wide, v)
        if post:
            cpu.s(rn, (cpu.g(rn) + self._off(cpu, off)) & MASK64)
        return

    def _store(self, cpu, m, o):
        if m == "stp":
            parts = [p.strip() for p in o.split(",")]
            rt1, _ = _reg(parts[0])
            rt2, _ = _reg(parts[1])
            rest = ",".join(parts[2:]).strip()[1:-1]
            rn, off = _memop("[" + rest + "]")
            base = cpu.g(rn) + self._off(cpu, off)
            self.mem.write(base & MASK64, 8, cpu.g(rt1))
            self.mem.write((base + 8) & MASK64, 8, cpu.g(rt2))
            return
        parts = [p.strip() for p in o.split(",")]
        rt, wide = _reg(parts[0])
        rn, off = _memop(",".join(parts[1:]))
        post = o.rstrip().endswith("]!")
        if rn in (21, 25, 27) and self._spec_store(cpu, rn, off, rt, wide, m):
            if post:
                cpu.s(rn, (cpu.g(rn) + self._off(cpu, off)) & MASK64)
            return
        base = (cpu.g(rn) if wide == "x" else cpu.w(rn)) + self._off(cpu, off)
        size = {"b": 1, "h": 2, "w": 4, "": 8}[_sizeletter(m)]
        val = cpu.g(rt) if (wide == "x" and size == 8) else cpu.w(rt)
        self.mem.write(base & MASK64, size, val)
        if post:
            cpu.s(rn, (cpu.g(rn) + self._off(cpu, off)) & MASK64)
        return

    def _spec_load(self, cpu, rn, off, rt, wide, m):
        """x21=帧 x25=寄存器文件 x27=帧指针保存槽。

        槽本身是 8 字节，但 handler 可以用 ldrb/ldrh/ldr 窄读一个槽，
        因此读出的宽度仍然按指令走，W 寄存器写回要零扩展。
        """
        size = {"b": 1, "h": 2, "w": 4, "": 8}[_sizeletter(m)]
        if rn == 21:
            base = self.frame_area + self.frame + self._off(cpu, off)
            self._wd(cpu, rt, wide, self._load_val(m, size,
                                                    self.mem.read(base & MASK64, size)))
            return True
        if rn == 25:
            idx = off[1] // 8 if off[0] == "imm" else self._off(cpu, off) // 8
            self._wd(cpu, rt, wide, self._load_val(m, size, self.regs[idx]))
            return True
        if rn == 27:
            self._wd(cpu, rt, wide, self._load_val(
                m, size, self.mem.read(SAVE_AREA + self._off(cpu, off), size)))
            return True
        if rn == 23 and self.xtab_area is not None:
            addr = self.xtab_area + self._off(cpu, off)
            self._wd(cpu, rt, wide, self._load_val(
                m, size, self.mem.read(addr & MASK64, size)))
            return True
        return False

    def _load_val(self, m, size, raw):
        if size == 8:
            return raw
        if m in ("ldrb", "ldurb", "ldrh", "ldurh"):
            return raw & ((1 << (size * 8)) - 1)
        if m in ("ldrsb", "ldrsb "):
            return _sx(raw, 8) & MASK64
        if m in ("ldrsh",):
            return _sx(raw, 16) & MASK64
        return s32(raw) & MASK64


    def _spec_store(self, cpu, rn, off, rt, wide, m):
        if rn == 21:
            target = self.frame_area + self.frame + self._off(cpu, off)
            self.mem.write(target & MASK64, 8, cpu.g(rt))
            return True
        if rn == 25:
            idx = off[1] // 8 if off[0] == "imm" else self._off(cpu, off) // 8
            self._set_reg(idx, cpu.g(rt))
            return True
        if rn == 27:
            if self._off(cpu, off) == 8:
                self.saved_frame = self.frame
                self._frame_saved = True
            self.mem.write(SAVE_AREA + self._off(cpu, off), 8, cpu.g(rt))
            return True
        return False

    def _get_reg(self, idx):
        """槽索引可能来自设备指针(任意 64 位); 越界视为未初始化的空槽。"""
        if 0 <= idx < len(self.regs):
            return self.regs[idx]
        if idx < 0:
            return 0
        return 0

    def _set_reg(self, idx, v):
        if idx < 0:
            return
        if idx >= len(self.regs):
            grow = min(idx + 1, len(self.regs) * 4)
            self.regs.extend([0] * (grow - len(self.regs)))
        self.regs[idx] = v & MASK64

    def _wd(self, cpu, rt, wide, v):
        """W 寄存器写回要零扩展到 64 位（ARM64 语义）。"""
        cpu.s(rt, (v & 0xFFFFFFFF) if wide == "w" else v & MASK64)

    def _off(self, cpu, off):
        kind = off[0]
        if kind == "imm":
            return off[1]
        if kind == "reg":
            return s64(cpu.g(off[1]))
        if kind == "sxtw":
            m, k = off[1]
            return s32(cpu.w(m)) << k
        raise ValueError(off)

    def _alu(self, cpu, m, o):
        parts = [p.strip() for p in o.split(",")]
        if m in ("cmp", "cmn", "tst"):
            a, b = self._two(cpu, parts)
            r = (a - b) if m in ("cmp", "tst") else (a + b)
            r &= 0xFFFFFFFF
            if m == "tst":
                cpu.set_nz(a & b)
            elif m == "cmp":
                cpu.set_sub(a, b, r)
            else:
                cpu.set_add(a, b, r)
            return
        if m in ("neg", "negs"):
            rn, _ = _reg(parts[1])
            a = cpu.g(rn)
            r = (-a) & MASK64
            cpu.set_sub(0, a, r & 0xFFFFFFFF)
            cpu.s(int(parts[0][1:]), r)
            return
        rd, wide = _reg(parts[0])
        a, b = self._two(cpu, parts[1:])
        r = (a + b) if m.startswith("add") else (a - b)
        if m.endswith("s"):
            if m.startswith("add"):
                cpu.set_add(a, b, r & 0xFFFFFFFF)
            else:
                cpu.set_sub(a, b, r & 0xFFFFFFFF)
        if wide == "w":
            r &= 0xFFFFFFFF
        cpu.s(rd, r & MASK64)
        return

    def _two(self, cpu, parts):
        a_tok = parts[0]
        b_tok = parts[1]
        ra, wa = _reg(a_tok)
        a = cpu.g(ra) if wa == "x" else cpu.w(ra)
        if b_tok.startswith("#"):
            return a, int(b_tok[1:], 0)
        if b_tok.startswith("x") or b_tok.startswith("w"):
            rb, wb = _reg(b_tok)
            b = cpu.g(rb) if wb == "x" else cpu.w(rb)
            if len(parts) > 2:
                b = self._shifted(cpu, rb, parts[2], wb)
            return a, b
        raise ValueError(parts)

    def _shifted(self, cpu, rb, shift_tok, wb):
        toks = [t.strip() for t in shift_tok.split()]
        amt = cpu.g(int(toks[0][1:])) if toks[0][0] == "x" else cpu.w(int(toks[0][1:]))
        typ = toks[1] if len(toks) > 1 else "lsl"
        return self._do_shift(cpu.g(rb) if wb == "x" else cpu.w(rb), typ, amt)

    def _do_shift(self, v, typ, amt):
        if typ == "lsl":
            return v << amt
        if typ == "lsr":
            return (v & 0xFFFFFFFF) >> (amt & 31)
        if typ == "asr":
            return s32(v) >> (amt & 31) if amt & 31 else s32(v)
        if typ == "ror":
            a = amt & 31
            r = v & 0xFFFFFFFF
            return ((r >> a) | (r << (32 - a))) & 0xFFFFFFFF if a else r
        raise ValueError(typ)

    def _logic(self, cpu, m, o):
        parts = [p.strip() for p in o.split(",")]
        if m == "tst":
            a, b = self._two(cpu, parts)
            cpu.set_nz(a & b)
            return
        rd, wide = _reg(parts[0])
        a, b = self._two(cpu, parts[1:])
        if m in ("and", "ands"):
            v = a & b
        elif m in ("bic", "bics"):
            v = a & ~b
        elif m == "orr":
            v = a | b
        elif m == "orn":
            v = a | ~b
        elif m == "eor":
            v = a ^ b
        elif m == "eon":
            v = a ^ ~b
        else:
            raise ValueError(m)
        if m.endswith("s"):
            cpu.set_nz(v)
        if wide == "w":
            v &= 0xFFFFFFFF
        cpu.s(rd, v & MASK64)
        return

    def _shift(self, cpu, m, o):
        parts = [p.strip() for p in o.split(",")]
        if len(parts) == 2 and m in ("lslv", "lsrv", "asrv", "rorv"):
            rd, _ = _reg(parts[0])
            ra, _ = _reg(parts[1])
            rb, _ = _reg(parts[2])
            typ = {"lslv": "lsl", "lsrv": "lsr", "asrv": "asr", "rorv": "ror"}[m]
            cpu.s(rd, self._do_shift(cpu.g(ra), typ, cpu.g(rb)) & MASK64)
            return
        rd, wide = _reg(parts[0])
        ra, _ = _reg(parts[1])
        amt_tok = parts[2]
        if amt_tok.startswith("#"):
            amt = int(amt_tok[1:], 0)
        else:
            amt = cpu.g(int(amt_tok[1:]))
        v = self._do_shift(cpu.g(ra) if wide == "x" else cpu.w(ra), m, amt)
        cpu.s(rd, v & (MASK64 if wide == "x" else 0xFFFFFFFF))
        return

    def _bitfield(self, cpu, m, o):
        parts = [p.strip() for p in o.split(",")]
        rd, wide = _reg(parts[0])
        rn, _ = _reg(parts[1])
        imms = int(parts[2][1:], 0)
        immr = int(parts[3][1:], 0)
        src = cpu.g(rn)
        nbits = 64 if wide == "x" else 32
        # 语义等价于 UBFM/SBFM: (N-imms) 为旋转量
        if imms >= immr:
            v = (src >> immr) & ((1 << (imms - immr + 1)) - 1)
        else:
            rot = nbits - immr
            v = ((src >> immr) | (src << rot)) & ((1 << nbits) - 1)
            v &= (1 << (imms + 1)) - 1
        if m in ("sbfx", "sbfm"):
            v = _sx(v, imms - immr + 1) & MASK64
        self._wd(cpu, rd, wide, v)
        return

    def _mul(self, cpu, m, o):
        parts = [p.strip() for p in o.split(",")]
        rd, wide = _reg(parts[0])
        if m == "mul":
            ra, _ = _reg(parts[1])
            rb, _ = _reg(parts[2])
            v = cpu.g(ra) * cpu.g(rb)
        elif m in ("madd", "msub"):
            ra, _ = _reg(parts[1])
            rb, _ = _reg(parts[2])
            rc, _ = _reg(parts[3])
            v = cpu.g(ra) * cpu.g(rb) + (cpu.g(rc) if m == "madd" else -cpu.g(rc))
        elif m in ("umull", "smull"):
            ra, _ = _reg(parts[1])
            rb, _ = _reg(parts[2])
            v = cpu.g(ra) * cpu.g(rb)
        elif m in ("udiv", "sdiv"):
            ra, _ = _reg(parts[1])
            rb, _ = _reg(parts[2])
            d = cpu.g(rb)
            v = (cpu.g(ra) // d) if d else 0
            if m == "sdiv":
                q = abs(s64(cpu.g(ra))) // abs(s64(d))
                if (cpu.g(ra) < 0) != (d < 0):
                    q = -q
                v = q
        else:
            raise ValueError(m)
        cpu.s(rd, v & (MASK64 if wide == "x" else 0xFFFFFFFF))
        return

    def _condsel(self, cpu, m, o):
        parts = [p.strip() for p in o.split(",")]
        if m in ("cset", "csetm"):
            cc = _cond_id(parts[1])
            rd, _ = _reg(parts[0])
            cpu.s(rd, (1 if cpu.cond(cc) else 0) if m == "cset" else
                  (MASK64 if cpu.cond(cc) else 0))
            return
        rd, _ = _reg(parts[0])
        rn, _ = _reg(parts[1])
        rest = parts[2:]
        cc = _cond_id(rest[0])
        if m in ("csel", "csinc"):
            alt = rest[1] if len(rest) > 1 else "xzr"
        else:
            alt = rest[1] if len(rest) > 1 else "xzr"
        a = cpu.g(rn)
        if m in ("csinc", "cinc"):
            rb, _ = _reg(alt)
            b = cpu.g(rb) + 1
        elif m in ("csinv", "cneg"):
            rb, _ = _reg(alt)
            b = ~cpu.g(rb) & MASK64
        elif m == "csneg":
            rb, _ = _reg(alt)
            b = -cpu.g(rb) & MASK64
        else:
            b = a
        cpu.s(rd, a if cpu.cond(cc) else b)
        return

    def _extend(self, cpu, m, o):
        parts = [p.strip() for p in o.split(",")]
        rd, _ = _reg(parts[0])
        rn, _ = _reg(parts[1])
        v = cpu.g(rn)
        if m == "sxtw":
            v = s32(v) & MASK64
        elif m == "sxtb":
            v = _sx(v, 8) & MASK64
        elif m == "sxth":
            v = _sx(v, 16) & MASK64
        elif m == "uxtb":
            v = v & 0xFF
        elif m == "uxth":
            v = v & 0xFFFF
        elif m == "uxtw":
            v = v & 0xFFFFFFFF
        cpu.s(rd, v)
        return

    def _dup(self, cpu, m, o):
        parts = [p.strip() for p in o.split(",")]
        rd, _ = _reg(parts[0])
        if len(parts) == 1:
            cpu.s(rd, cpu.s(31))
            return
        rn, _ = _reg(parts[1])
        cpu.s(rd, cpu.g(rn))
        return

    native_hook_addr = {}


def _sizeletter(m):
    for ch in m:
        if ch in "bhw":
            return ch
    return ""


def _cond_id(tok):
    tok = tok.strip().lstrip("#")
    if tok.startswith("!"):
        tok = "eq" if tok[1:] == "eq" else "ne"
    return {
        "eq": 0, "ne": 1, "hs": 2, "lo": 3, "mi": 4, "pl": 5, "vs": 6, "vc": 7,
        "hi": 8, "ls": 9, "ge": 10, "lt": 11, "gt": 12, "le": 13, "al": 14,
        "nv": 15, "": 14,
    }[tok]


FRAME_AREA = 0x200000000
REGS_AREA = 0x300000000
SAVE_AREA = 0x400000000
HANDLER_AREA = 0x500000000


HANDLER_MAX = 0x100


def load_jit(path):
    """`JIT_BASE <addr> SIZE <n>` + hex -> (base, bytes)

    handler 之间的跳板（`ldr x16, <绝对地址>; br x16`）要解析字面量，
    所以必须把整段 JIT 区按**真实地址**装载，不能只装单个 handler。
    """
    with open(path) as fh:
        head = fh.readline().split()
        meta = {}
        for i, tok in enumerate(head[:-1]):
            if not tok or not tok[0].isalpha():
                continue
            try:
                meta[tok] = int(head[i + 1], 0)
            except ValueError:
                continue
        chunks = []
        for line in fh:
            line = line.strip()
            if line:
                chunks.append(line)
        data = bytes.fromhex("".join(chunks))
    if "JIT_BASE" not in meta:
        raise ValueError("jit.bin 缺少 JIT_BASE 头: %r" % head[:6])
    return meta["JIT_BASE"], data