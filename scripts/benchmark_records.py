"""用固定字段读取任务比较统一入口与 Python seek/read；不是完整分析能力基准。"""

import argparse
import json
import os
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECORD_SIZE = 272
DIRECT_READ = """import json, struct, sys
with open(sys.argv[1], 'rb') as stream:
    stream.seek(int(sys.argv[2]) * 272 + 8)
    value = struct.unpack('<Q', stream.read(8))[0]
print(json.dumps({'value': hex(value)}))
"""


def encode_bl(pc, target):
    return 0x94000000 | (((target - pc) // 4) & 0x03FFFFFF)


def write_detail_trace(call, count):
    """生成含独立内存地址、load/store 和重复动态边的确定性 trace。"""
    base = 0x100000
    pattern = (
        (base, 0xD503201F),
        (base + 4, 0xD503201F),
        (base + 8, 0xF9000020),
        (base + 12, 0xF9400022),
        (base + 16, encode_bl(base + 16, base + 0x100)),
        (base + 0x100, 0xD503201F),
        (base + 0x104, 0xD65F03C0),
        (base + 0x14, 0x17FFFFFB),
    )
    call.mkdir(parents=True)
    with (call / 'trace.bin').open('wb') as stream:
        pending = bytearray()
        for idx in range(count):
            loop, phase = divmod(idx, len(pattern))
            pc, inst = pattern[phase]
            value = 0x4142430000000000 | loop
            regs = [0] * 31
            regs[0] = value
            regs[1] = 0x10000000 + loop * 8
            regs[2] = value if phase >= 4 else 0
            regs[8] = base + 0x100
            regs[30] = base + 0x14
            pending += struct.pack('<Q', pc)
            pending += b''.join(struct.pack('<Q', reg) for reg in regs)
            pending += struct.pack('<QII', 0x70000000, 0, inst)
            if len(pending) >= RECORD_SIZE * 4096:
                stream.write(pending)
                pending.clear()
        stream.write(pending)
    (call / 'meta.json').write_text(json.dumps({
        'callIdx': 1, 'tid': 100, 'records': count, 'ms': 1,
        'retval': '0x0', 'truncated': False, 'last_insn_is_ret': False,
        'known_offsets': {'0x0': 'f_loop', '0x100': 'f_helper'},
        'module': {'name': 'libfixture.so', 'base': hex(base), 'size': 0x10000},
    }))


def run_detail_suite(binary, rounds):
    if rounds < 1:
        raise ValueError('rounds 必须大于零')
    time_bin = shutil.which('/usr/bin/time') or shutil.which('time')
    if not time_bin:
        raise RuntimeError('detail suite 需要 GNU time 以采集峰值 RSS')
    env = dict(os.environ, TRACEMIKU_CLI_BIN=str(binary.resolve()))
    runs = []

    def measure(root, name, command, cold=False, validator=None):
        if cold:
            for sidecar in Path(command[1]).parent.glob('trace.bin.memshadow.*.bin'):
                sidecar.unlink()
        timing = root / f'{name}.time'
        started = time.perf_counter_ns()
        proc = subprocess.run([
            time_bin, '-v', '-o', str(timing), str(ROOT / 'tracemiku'),
            *map(str, command),
        ], cwd=ROOT, env=env, capture_output=True, timeout=300, check=False)
        wall_ns = time.perf_counter_ns() - started
        timing_text = timing.read_text()
        payload = json.loads(proc.stdout)
        if proc.returncode:
            raise RuntimeError(f'{name} 失败: {payload} {proc.stderr.decode()}')
        if validator:
            validator(payload)
        rss = re.search(r'Maximum resident set size \(kbytes\): (\d+)', timing_text)
        result = {
            'name': name, 'command': list(map(str, command)), 'cold': cold,
            'exit_status': proc.returncode, 'wall_ns_external': wall_ns,
            'max_rss_kib': int(rss.group(1)) if rss else None,
            'stdout': payload, 'time_log': timing_text,
        }
        runs.append(result)

    def check_record(payload, detail=False):
        row = payload['records'][0]
        assert row['idx'] == 2
        regs = row['detail']['regs'] if detail else row['regs']
        assert regs['x0'] == '0x4142430000000000'

    def check_memory(payload):
        assert payload['returned'] == 2
        assert payload['events'][0]['bytes'] == [0, 0, 0, 0, 0, 67, 66, 65]

    def check_cfg(payload):
        assert payload['status'] == 'ready'
        assert payload['total_edges'] == 4
        assert payload['blocks'][0]['executions'] > 0

    with tempfile.TemporaryDirectory(prefix='tracemiku-detail-bench-') as temporary:
        root = Path(temporary)
        for count in (50_000, 200_000):
            call = root / f'call_001_tid100_{count}r_1ms'
            write_detail_trace(call, count)
            for round_id in range(1, rounds + 1):
                measure(root, f'{count}-ordinary-r{round_id}', [
                    'records', call, '--start', '2', '--count', '1', '--regs', 'x0'],
                    validator=lambda payload: check_record(payload))
                measure(root, f'{count}-detail-r{round_id}', [
                    'records', call, '--start', '2', '--count', '1', '--detail'],
                    cold=round_id == 1, validator=lambda payload: check_record(payload, True))
                measure(root, f'{count}-memory-r{round_id}', [
                    'mem-accesses', call, '--addr', '0x10000000', '--size', '8', '--limit', '200'],
                    cold=round_id == 1, validator=check_memory)
                measure(root, f'{count}-cfg-r{round_id}', ['cfg', call], validator=check_cfg)

    groups = {}
    for run in runs:
        group = run['name'].rsplit('-r', 1)[0]
        groups.setdefault(group, []).append(run)
    summary = {name: {
        'rounds': len(items),
        'median_wall_ns_external': statistics.median(r['wall_ns_external'] for r in items),
        'median_max_rss_kib': statistics.median(r['max_rss_kib'] for r in items),
    } for name, items in groups.items()}
    return {
        'scope': '合成 ARM64 trace：每八条记录含一次 8 字节 load/store、call/ret 和重复动态回边；'
                 '50,000 与 200,000 条使用相同生成器。计时包含统一入口新进程启动。',
        'binary': str(binary.resolve()), 'runs': runs, 'summary': summary,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=int, default=1_000_000, help='合成 NOP 记录数，1..10000000')
    parser.add_argument('--rounds', type=int, default=7, help='预热后交替测量轮数，1..100')
    parser.add_argument('--detail-suite', action='store_true',
                        help='测量 5 万/20 万条内存与重复分支 trace 的 records、detail、MemShadow 和 CFG')
    parser.add_argument('--output', type=Path, help='另存完整 JSON 测量证据')
    args = parser.parse_args()
    if not 1 <= args.records <= 10_000_000 or not 1 <= args.rounds <= 100:
        parser.error('records 或 rounds 超出范围')
    binary = Path(os.environ.get('TRACEMIKU_CLI_BIN', ROOT / 'rust/target/debug/tracemiku-cli'))
    if not binary.is_file():
        parser.error('请先运行 make cli，避免把编译计入查询耗时')
    env = dict(os.environ, TRACEMIKU_CLI_BIN=str(binary.resolve()))
    if args.detail_suite:
        report = run_detail_suite(binary, args.rounds)
        text = json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            args.output.write_text(text + '\n')
        print(text)
        return
    with tempfile.TemporaryDirectory(prefix='tracemiku-record-query-') as temporary:
        call = Path(temporary) / f'call_001_tid1_{args.records}r_1ms'
        call.mkdir()
        record = bytearray(RECORD_SIZE)
        struct.pack_into('<Q', record, 0, 0x100000)
        struct.pack_into('<Q', record, 8, 0x42)
        struct.pack_into('<I', record, 268, 0xd503201f)
        with (call / 'trace.bin').open('wb') as stream:
            remaining = args.records
            while remaining:
                count = min(10_000, remaining)
                stream.write(record * count)
                remaining -= count
        (call / 'meta.json').write_text(json.dumps({
            'records': args.records,
            'module': {'name': 'libfixture.so', 'base': '0x100000', 'size': 4096},
        }))
        reader = Path(temporary) / 'read_one.py'
        reader.write_text(DIRECT_READ)
        idx = str(args.records // 2)
        commands = {
            'python_seek_read': [sys.executable, str(reader), str(call / 'trace.bin'), idx],
            'records': [sys.executable, str(ROOT / 'tracemiku'), 'records', str(call),
                        '--start', idx, '--count', '1', '--regs', 'x0'],
        }
        samples = {name: [] for name in commands}
        output_bytes = {}
        for round_id in range(args.rounds + 1):
            order = list(commands.items())
            if round_id % 2:
                order.reverse()
            for name, command in order:
                start = time.perf_counter()
                result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                                        check=True, timeout=60)
                elapsed = (time.perf_counter() - start) * 1000
                value = json.loads(result.stdout)
                actual = (value['records'][0]['regs']['x0'] if name == 'records' else value['value'])
                if actual != '0x42':
                    raise RuntimeError(f'{name} 返回错误值: {actual}')
                if round_id:
                    samples[name].append(elapsed)
                output_bytes[name] = len(result.stdout)
        print(json.dumps({
            'fixture_records': args.records, 'fixture_bytes': args.records * RECORD_SIZE,
            'instruction': 'NOP', 'rounds': args.rounds, 'binary': str(binary.resolve()),
            'samples_ms': samples,
            'median_ms': {name: statistics.median(values) for name, values in samples.items()},
            'output_bytes': output_bytes, 'same_requested_value': True,
            'scope': '固定 x0 原始值；records 另含一条反汇编和分页元数据。计时含新进程启动，文件缓存已预热。',
        }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
