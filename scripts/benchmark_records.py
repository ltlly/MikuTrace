"""用固定字段读取任务比较统一入口与 Python seek/read；不是完整分析能力基准。"""

import argparse
import json
import os
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--records', type=int, default=1_000_000, help='合成 NOP 记录数，1..10000000')
    parser.add_argument('--rounds', type=int, default=7, help='预热后交替测量轮数，1..100')
    args = parser.parse_args()
    if not 1 <= args.records <= 10_000_000 or not 1 <= args.rounds <= 100:
        parser.error('records 或 rounds 超出范围')
    binary = Path(os.environ.get('TRACEMIKU_CLI_BIN', ROOT / 'rust/target/debug/tracemiku-cli'))
    if not binary.is_file():
        parser.error('请先运行 make cli，避免把编译计入查询耗时')
    env = dict(os.environ, TRACEMIKU_CLI_BIN=str(binary.resolve()))
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
