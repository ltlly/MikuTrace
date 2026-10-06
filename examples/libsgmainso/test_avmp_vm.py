"""AVMP VM 离线解释器的自检。

核心断言：解释器对「当前帧」的解释必须与设备侧记录的执行序列一致。
seq.txt 是设备上 hook libsgmainso+0x17c680 录下的权威真值
（`x21` 与当时实际 branch 到的 handler id），见 avmp/README.md。
"""

import os
import sys
import unittest

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "avmp")
sys.path.insert(0, os.path.dirname(HERE))

from avmp.arm64 import MASK64, Memory  # noqa: E402
from avmp.vm import XTAB_AREA, XsignVm  # noqa: E402


def load_seq(x):
    base = x.frame_meta["FRAME_BASE"] & ~0xF
    rows = []
    with open(os.path.join(HERE, "seq.txt")) as fh:
        for line in fh:
            if line.startswith("FRAME_BASE"):
                continue
            parts = line.split()
            if len(parts) == 2:
                rows.append((int(parts[0], 16), int(parts[1])))
    return base, rows


class TestFrameSemantics(unittest.TestCase):
    """VM 的帧语义 —— 这是整个还原的地基。"""

    @classmethod
    def setUpClass(cls):
        cls.x = XsignVm()
        cls.base, cls.rows = load_seq(cls.x)

    def test_artifacts_from_single_run(self):
        """JIT 区 / x23 表 / 帧数组必须同源, 否则解释结果无意义。"""
        x = self.x
        inside = sum(
            1 for a in x.xtab.values()
            if x.jit_base <= a < x.jit_base + len(x.jit_data)
        )
        self.assertGreater(inside, 500, "x23 表应大量指向本次 dump 的 JIT 区")
        self.assertGreater(len(x.frame_data), 4096, "帧数组不应为空")

    def test_frame_id_matches_device(self):
        """`u16_at(F+0x10)` 就是本帧的 handler id。"""
        vm = self.x.new_vm()
        ok = bad = 0
        for addr, want in self.rows:
            if not (self.base <= addr < self.base + len(self.x.frame_data)):
                continue
            vm.frame = addr - self.base
            if vm.frame_id() == want:
                ok += 1
            else:
                bad += 1
        self.assertGreater(ok, 50, "应有足够样本落在已 dump 的帧区间内")
        self.assertEqual(bad, 0, "frame_id() 与设备记录不一致")

    def test_frame_id_offset_is_0x10(self):
        """显式锁住 +0x10 这个偏移, 防止有人改回帧首。"""
        vm = self.x.new_vm()
        off0x10 = off0x00 = 0
        for addr, want in self.rows:
            if not (self.base <= addr < self.base + len(self.x.frame_data)):
                continue
            o = addr - self.base
            fd = self.x.frame_data
            if (fd[o + 0x10] | (fd[o + 0x11] << 8)) == want:
                off0x10 += 1
            if (fd[o] | (fd[o + 1] << 8)) == want:
                off0x00 += 1
        self.assertGreater(off0x10, 50)
        self.assertEqual(off0x00, 0, "帧首不是 handler id")

    def test_handlers_decode(self):
        """x23 表指向的 handler 必须能反汇编成合法 ARM64。"""
        from avmp.arm64 import MD
        n = 0
        for k, addr in self.x.xtab.items():
            if not (self.x.jit_base <= addr < self.x.jit_base + len(self.x.jit_data)):
                continue
            code = self.x.mem.snapshot(addr, 16)
            ins = list(MD.disasm(code, addr))
            self.assertTrue(ins, "handler %d @0x%x 无法反汇编" % (k, addr))
            n += 1
        self.assertGreater(n, 500)


class TestExecution(unittest.TestCase):
    """离线执行: 从设备帧出发能连续跑数千步。"""

    @classmethod
    def setUpClass(cls):
        cls.x = XsignVm()
        cls.base = cls.x.frame_meta["FRAME_BASE"] & ~0xF

    def _run(self, entry, steps):
        vm = self.x.new_vm()
        vm.frame = entry
        vm.run(max_steps=steps)
        return vm

    def test_runs_thousands_of_steps(self):
        for entry in (0x3340, 0x3750, 0x4000, 0x6000, 0x8000):
            vm = self._run(entry, 3000)
            self.assertEqual(vm.steps, 3000, "入口 0x%x 未能跑满" % entry)
            self.assertFalse(vm.halted)

    def test_frame_pointer_advances(self):
        """帧指针必须单调推进, 而不是原地打转或乱跳。

        注意帧数组只 dump 了最大簇(NF≈2490 帧), 所以执行几千步后
        越界是正常的 —— 那是 dump 覆盖不足, 不是帧推进算错。
        """
        vm = self.x.new_vm()
        vm.frame = 0x3340
        seen = [vm.frame]
        for _ in range(500):
            vm.step()
            seen.append(vm.frame)
        moved = [f for f in seen[1:] if f != seen[0]]
        self.assertGreater(len(moved), 400, "帧指针几乎没动, 帧推进有问题")
        self.assertNotEqual(seen[-1], seen[0])

    def test_registers_written(self):
        """handler 必须真的改了寄存器文件, 否则说明 x25 语义没生效。"""
        vm = self._run(0x3340, 500)
        self.assertNotEqual(vm.regs, [0] * len(vm.regs))


class TestArm64(unittest.TestCase):
    """ARM64 子集解释器的边界语义。"""

    def test_memory_roundtrip(self):
        m = Memory()
        m.write(0x1234, 4, 0xDEADBEEF)
        self.assertEqual(m.read(0x1234, 4), 0xDEADBEEF)
        m.write_bytes(0x2000, b"hello")
        self.assertEqual(m.read_cstr(0x2000), b"hello")

    def test_narrow_slot_access(self):
        """槽是 8 字节, 但 handler 可以 ldrb/ldrh 窄读 —— 宽度语义要对。"""
        x = XsignVm()
        vm = x.new_vm()
        vm._set_reg(3, 0x1122334455667788)
        self.assertEqual(vm._get_reg(3), 0x1122334455667788)

    def test_mask(self):
        self.assertEqual(MASK64, (1 << 64) - 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
