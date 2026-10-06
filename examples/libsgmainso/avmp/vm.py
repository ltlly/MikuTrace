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


class XsignVm:
    """一次 x-sign 生成程序的可重算实例。"""

    def __init__(self, handlers=None, frames=None, regs=None, jit=None):
        self.frame_meta, self.frame_data = _read_frames(
            frames or os.path.join(HERE, "frames.txt")
        )
        self.regs_data = _read_regs(regs or os.path.join(HERE, "regs.txt"))
        self.jit_base, self.jit_data = load_jit(
            jit or os.path.join(HERE, "jit.bin")
        )
        # x23 表: frame_id -> handler 地址(与 jit 区同一次运行落盘)
        self.xtab = {}
        with open(os.path.join(HERE, "xtab.txt")) as fh:
            for line in fh:
                parts = line.split()
                if len(parts) == 2 and parts[0].isdigit():
                    self.xtab[int(parts[0])] = int(parts[1], 16)
        self.mem = Memory()
        # 帧数组按 FRAME_BASE 装载, 并把 16 字节对齐到 0 偏移
        base = self.frame_meta.get("FRAME_BASE")
        self.frame_area = 0x200000000
        # 设备侧 frames.txt 的起点已按 16 字节对齐(见 vmrun.js)
        self.mem.write_bytes(self.frame_area, self.frame_data)
        self.mem.write_bytes(REGS_AREA, self.regs_data)
        self.mem.write_bytes(SAVE_AREA, bytes(0x200))
        # JIT 区按真实地址装载：handler 之间的跳板/字面量必须能解析
        self.mem.write_bytes(self.jit_base, self.jit_data)

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
        vm.regs = list(
            int.from_bytes(self.regs_data[i * 8:i * 8 + 8], "little")
            for i in range(len(self.regs_data) // 8)
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
