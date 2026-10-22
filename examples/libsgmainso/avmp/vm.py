"""AVMP VM 离线解释器：把 x-sign 生成程序还原成可离线重算的纯计算。

VM 结构（libsgmainso-6.8.260602.so，dispatcher libsgmainso+0x17c680）：

    x21   帧指针，16 字节/帧；帧 +0x10 的 2 字节是**下一帧的 handler id**
    x25   寄存器文件，8 字节/槽
    x23   frame_id -> JIT handler 地址表（handler 是运行时生成代码）
    x27   [x27+8] 保存帧指针

每条 JIT handler 的机器码由设备侧 hook dispatcher 后按 x23[frame_id] 落盘
（avmp/handlers.txt）。本模块直接解释这些机器码，因此还原出的行为与设备
逐指令一致，而不是重新实现一遍算法。

数据来源见 avmp/README.md。
"""

import os

from .arm64 import MASK64, AvmpVm, Memory, load_jit

HERE = os.path.dirname(os.path.abspath(__file__))


def _read_frames(path):
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
        chunks = [ln.strip() for ln in fh if ln.strip()]
        data = bytes.fromhex("".join(chunks))
    return meta, data


def _read_regs(path):
    with open(path) as fh:
        fh.readline()
        chunks = [ln.strip() for ln in fh if ln.strip()]
        return bytes.fromhex("".join(chunks))


def _read_vminit(path):
    """读设备侧导出的 VM 初值: 入口帧 + x21/x23/x25/x27 + x27 上下文本体。

    没有这组数据就只能跑「单条 handler」——寄存器初值是我合成的常量，
    ctx+0x240 之类全是 0，mem_rw 算出的随机缓冲地址自然是空地址。
    """
    if not os.path.exists(path):
        return None
    out = {"entry": None, "ctx": {}, "ctx240": None, "buf": None}
    with open(path) as fh:
        for line in fh:
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "ENTRY" and parts[1].startswith("{"):
                import json
                out["entry"] = json.loads(parts[1])
            elif parts[0] == "X27_CTX" and len(parts) >= 3:
                out["ctx"][int(parts[1], 0)] = bytes.fromhex(parts[2])
            elif parts[0] == "CTX240_DATA" and len(parts) >= 3:
                out["ctx240"] = (int(parts[1], 0), bytes.fromhex(parts[2]))
            elif parts[0] == "BUF_DATA" and len(parts) >= 3:
                out["buf"] = (int(parts[1], 0), bytes.fromhex(parts[2]))
    return out if out["entry"] else None


class XsignVm:
    """一次 x-sign 生成程序的可重算实例。"""

    def __init__(self, handlers=None, frames=None, regs=None, jit=None,
                 use_vminit=False):
        # 帧数组优先用 vmframes2.txt: 它是在 VM **较晚**的命中点导出的, 此时
        # 字节码已解码进帧, 分支偏移字段(frame[0xc])不再为 0
        # (早期快照非零帧 44%, 晚期 76%)。
        f2 = os.path.join(HERE, "vmframes2.txt")
        self.frame_meta, self.frame_data = _read_frames(
            frames or (f2 if os.path.exists(f2)
                        else os.path.join(HERE, "frames.txt"))
        )
        r3 = os.path.join(HERE, "vmregs3.txt")
        self.regs_data = _read_regs(
            regs or (r3 if os.path.exists(r3)
                     else os.path.join(HERE, "regs.txt"))
        )
        self.jit_base, self.jit_data = load_jit(
            jit or os.path.join(HERE, "jit.bin")
        )
        # x23 表: frame_id -> handler 地址。use_vminit 时优先用
        # vmxtab.txt —— 它与 vmframes2/vminit 同一次运行; xtab.txt 可能
        # 来自另一次运行, 那样 handler id 会解析成陈旧值(全不匹配)。
        xf = os.path.join(HERE, "vmxtab.txt")
        if not os.path.exists(xf):
            xf = os.path.join(HERE, "xtab.txt")
        self.xtab = {}
        with open(xf) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit():
                    # 地址列可能是 0x 前缀的十六进制(xtab.txt)，
                    # 也可能是纯十进制(vmxtab.txt) —— 按前缀判断, 不能一律按 16 进制
                    self.xtab[int(parts[0])] = (int(parts[1], 16)
                                               if parts[1].lower().startswith("0x")
                                               else int(parts[1]))
        self.mem = Memory()
        # 帧数组按 FRAME_BASE 装载, 并把 16 字节对齐到 0 偏移
        base = self.frame_meta.get("FRAME_BASE")
        self.frame_area = 0x200000000
        # 设备侧 frames.txt 的起点已按 16 字节对齐(见 vmrun.js)
        with self.mem.quiet():
            self.mem.write_bytes(self.frame_area, self.frame_data)
            self.mem.write_bytes(REGS_AREA, self.regs_data)
            self.mem.write_bytes(SAVE_AREA, bytes(0x200))
        # JIT 区按真实地址装载：handler 之间的跳板/字面量必须能解析
        with self.mem.quiet():
            self.mem.write_bytes(self.jit_base, self.jit_data)
        self.canary_pages = self._load_canary_pages(
            os.path.join(HERE, "canary_pages.txt")
        )
        # 设备侧导出的真实 VM 初值(入口帧 / x21,x23,x25,x27 / x27 上下文)。
        # **默认不启用**: 见 README「为什么 vminit 还没接上」——
        # 帧数组与寄存器初值虽是同一次 dump, 但帧的分支偏移字段
        # (frame[0xc]) 在那一刻仍为 0, 离线执行会原地打转。
        # 需要时显式传 use_vminit=True。
        self.vminit = _read_vminit(os.path.join(HERE, "vminit.txt"))
        self.entry = None
        self._use_vminit = bool(self.vminit)
        self.reg_x23 = self.reg_x25 = self.reg_x27 = None
        if self.vminit:
            with self.mem.quiet():
                for addr, data in self.vminit["ctx"].items():
                    self.mem.write_bytes(addr, data)
                if self.vminit.get("ctx240"):
                    self.mem.write_bytes(self.vminit["ctx240"][0],
                                         self.vminit["ctx240"][1])
                if self.vminit.get("buf"):
                    self.mem.write_bytes(self.vminit["buf"][0],
                                         self.vminit["buf"][1])
            e = self.vminit["entry"]
            self.entry = int(e["x21"], 16)
            self.reg_x23 = int(e["x23"], 16)
            self.reg_x25 = int(e["x25"], 16)
            self.reg_x27 = int(e["x27"], 16)

    def _load_canary_pages(self, path):
        """装载 canary 全局页（设备侧按需逐页 dump）。

        helper 入口的自解密跳转依赖 ``ldr wG, [adrp_page, #0x68]`` 读到的
        canary 全局值；这些页散落在 JIT 区之外（其他映射段），无法靠范围
        覆盖，只能按需逐页读。缺了它们，helper 的 br 目标会算错。
        """
        if not os.path.exists(path):
            return {}
        pages = {}
        with open(path) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 3 and parts[0] == "PAGE":
                    pages[int(parts[1])] = bytes.fromhex(parts[2])
        with self.mem.quiet():
            for pg, data in pages.items():
                self.mem.write_bytes(pg, data)
        return pages

    def _fix_jit_range(self, base, data):
        """设备侧写 JITBASE 时高位丢失(曾把 0x743b600000 写成 0x3b600000)。

        以 x23 表里 handler 地址的众数桶为准重新定位 JIT 区; 这比信任
        头部字段可靠, 因为 x23 表本身就是"handler 地址"的权威来源。
        """
        import collections
        addrs = [a for a in self.xtab.values()
                 if a and 0x7000000000 <= a < 0x8000000000]
        if not addrs:
            return base, data
        bucket = collections.Counter(a & ~0xFFFFF for a in addrs).most_common(1)[0][0]
        lo = min(a for a in addrs if bucket <= a < bucket + 0x100000)
        hi = max(a for a in addrs if bucket <= a < bucket + 0x100000)
        start = lo - 0x10000
        end = hi + 0x10000
        if not (base <= start and end <= base + len(data)):
            return base, data          # 现有 dump 已覆盖, 不动
        # 从 data 里裁出 [start, end)
        return start, data[start - base:end - base]

    def new_vm(self, native=None):
        """建一个装好 JIT 区 / x23 表 / 帧数组 / 寄存器文件的 VM 实例。"""
        # x23 表要能被 handler 的 ldr [x23, w, lsl #3] 解析
        if XTAB_AREA not in self.mem.pages:
            tbl = bytearray(0x2000)
            for k, a in self.xtab.items():
                if k * 8 + 8 <= 0x2000:
                    tbl[k * 8:k * 8 + 8] = a.to_bytes(8, "little")
            self.mem.write_bytes(XTAB_AREA, bytes(tbl))
        vm = AvmpVm(
            {k: a for k, a in self.xtab.items()
             if self.jit_base <= a < self.jit_base + len(self.jit_data)},
            self.mem, native,
        )
        vm.xtab_area = XTAB_AREA
        if self.reg_x23 is not None:
            vm.reg_x23 = self.reg_x23
            vm.reg_x25 = self.reg_x25
            vm.reg_x27 = self.reg_x27
        vm.code_lo = self.jit_base
        vm.code_hi = self.jit_base + len(self.jit_data)
        vm.regs = list(
            int.from_bytes(self.regs_data[i * 8:i * 8 + 8], "little")
            for i in range(len(self.regs_data) // 8)
        )
        # 同源自检: x23 表必须与 JIT 区同一次运行, 否则 handler id 会解析
        # 成陈旧值(表现为"所有帧 id 都查不到", 很容易误判成帧内容有问题)。
        inrange = sum(
            1 for a in vm.handlers.values()
            if self.jit_base <= a < self.jit_base + len(self.jit_data)
        )
        vm.xtab_in_jit = inrange
        if not getattr(self, "_use_vminit", False) and inrange == 0:
            raise RuntimeError(
                "默认 artifacts(xtab.txt) 与 jit.bin 非同源: 0/%d 条 handler 落在 "
                "[0x%x,0x%x) 内。请用 use_vminit=True 走 vmxtab/vmframes2 那套, "
                "或重新采集同源的 frames/xtab/jit。"
                % (len(vm.handlers), self.jit_base,
                   self.jit_base + len(self.jit_data))
            )
        if self._use_vminit and inrange * 2 < max(len(vm.handlers), 1):
            raise RuntimeError(
                "x23 表与 JIT 区非同源: %d/%d 条 handler 落在 [0x%x,0x%x) 内。"
                "需要同一次运行同时导出 jit.bin 与 vmxtab.txt。"
                % (inrange, len(vm.handlers), self.jit_base,
                   self.jit_base + len(self.jit_data))
            )
        vm.native_hook_addr = dict(native or {})
        return vm

    def run(self, entry=0, max_steps=5_000_000, native=None):
        vm = self.new_vm(native)
        vm.frame = entry
        vm.regs = list(
            int.from_bytes(self.regs_data[i * 8:i * 8 + 8], "little")
            for i in range(len(self.regs_data) // 8)
        )
        # 指针重定位：dump 出的绝对地址在离线环境无意义，统一映射到本地区域
        remap = {
            self.frame_meta["X25"]: REGS_AREA,
            self.frame_meta["X27"]: SAVE_AREA,
            self.frame_meta["X23"]: self.jit_base,
        }
        for i in range(len(vm.regs)):
            v = vm.regs[i]
            if v in remap:
                vm.regs[i] = remap[v]
            elif self.frame_area <= v < self.frame_area + len(self.frame_data):
                vm.regs[i] = v
        # handlers.txt 里的地址是设备地址；JIT 区已按原地址装载，无需搬迁
        # x23 表要能被 handler 的 ldr [x23, w, lsl #3] 解析
        if XTAB_AREA not in self.mem.pages:
            tbl = bytearray(0x2000)
            for k, a in self.xtab.items():
                if k * 8 + 8 <= 0x2000:
                    tbl[k * 8:k * 8 + 8] = a.to_bytes(8, "little")
            self.mem.write_bytes(XTAB_AREA, bytes(tbl))
        vm.xtab_area = XTAB_AREA
        if self.reg_x23 is not None:
            vm.reg_x23 = self.reg_x23
            vm.reg_x25 = self.reg_x25
            vm.reg_x27 = self.reg_x27
        vm.code_lo = self.jit_base
        vm.code_hi = self.jit_base + len(self.jit_data)
        # 同源自检: x23 表必须与 JIT 区同一次运行, 否则 handler id 会解析
        # 成陈旧值(表现为"所有帧 id 都查不到", 很容易误判成帧内容有问题)。
        inrange = sum(
            1 for a in vm.handlers.values()
            if self.jit_base <= a < self.jit_base + len(self.jit_data)
        )
        vm.xtab_in_jit = inrange
        if not getattr(self, "_use_vminit", False) and inrange == 0:
            raise RuntimeError(
                "默认 artifacts(xtab.txt) 与 jit.bin 非同源: 0/%d 条 handler 落在 "
                "[0x%x,0x%x) 内。请用 use_vminit=True 走 vmxtab/vmframes2 那套, "
                "或重新采集同源的 frames/xtab/jit。"
                % (len(vm.handlers), self.jit_base,
                   self.jit_base + len(self.jit_data))
            )
        if self._use_vminit and inrange * 2 < max(len(vm.handlers), 1):
            raise RuntimeError(
                "x23 表与 JIT 区非同源: %d/%d 条 handler 落在 [0x%x,0x%x) 内。"
                "需要同一次运行同时导出 jit.bin 与 vmxtab.txt。"
                % (inrange, len(vm.handlers), self.jit_base,
                   self.jit_base + len(self.jit_data))
            )
        vm.native_hook_addr = dict(native or {})
        vm.run(max_steps=max_steps)
        return vm


REGS_AREA = 0x300000000
SAVE_AREA = 0x400000000
HANDLER_AREA = 0x500000000
XTAB_AREA = 0x600000000


def snapshot(vm, addr, size):
    return vm.mem.snapshot(addr, size)


def main(argv=None):
    import argparse
    import binascii

    ap = argparse.ArgumentParser(description="AVMP VM 离线解释器")
    ap.add_argument("--entry", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--max-steps", type=int, default=200000)
    ap.add_argument("--mem", type=lambda v: int(v, 0), default=None,
                    help="dump 指定地址长度的内存")
    ap.add_argument("--regs", type=lambda v: int(v, 0), default=None,
                    help="dump 寄存器文件")
    ap.add_argument("--verify-seq", action="store_true",
                    help="用 seq.txt 的设备侧执行序列校验 frame_id() 语义")
    args = ap.parse_args(argv)

    x = XsignVm()
    if args.verify_seq:
        base = x.frame_meta["FRAME_BASE"] & ~0xF
        vm = x.new_vm()
        ok = bad = 0
        with open(os.path.join(HERE, "seq.txt")) as fh:
            for line in fh:
                if line.startswith("FRAME_BASE"):
                    continue
                parts = line.split()
                if len(parts) != 2:
                    continue
                addr, want = int(parts[0], 16), int(parts[1])
                if not (base <= addr < base + len(x.frame_data)):
                    continue
                vm.frame = addr - base
                if vm.frame_id() == want:
                    ok += 1
                else:
                    bad += 1
        print("frame_id() 对照设备记录: 一致 %d / 不一致 %d" % (ok, bad))
        return 0
    vm = x.run(entry=args.entry, max_steps=args.max_steps)
    print("steps=%d halted=%s frame=0x%x" % (vm.steps, vm.halted, vm.frame))
    if args.mem is not None:
        data = snapshot(vm, args.mem, 128)
        print("mem 0x%x: %s" % (args.mem, binascii.hexlify(data).decode()))
    if args.regs is not None:
        for i in range(args.regs):
            print("  reg[%d] = 0x%x" % (i, vm.regs[i]))


if __name__ == "__main__":
    main()
