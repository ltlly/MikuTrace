/** 执行生产 C 源码，注入短写/EINTR/ENOSPC，验证极小缓冲不会丢弃或复制记录。 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { execFileSync } from "node:child_process";
import ts from "typescript";

const sources: string[] = [];
const pointer = { writeS32() {}, toString() { return "0x1"; } };
const state: any = { simdSidecar: true, semanticEvents: false };
for (const key of ["ringBuf", "headBuf", "tailBuf", "ringRecsBuf", "traceIoState", "simdIoState",
    "simdRingBuf", "simdRingRecsBuf", "simdStrideBuf", "simdHeadBuf", "simdTailBuf", "active"]) state[key] = pointer;
const common = {
    Memory: { alloc() { return pointer; } },
    NativeFunction: function () { return () => {}; },
    SystemFunction: function () { return () => ({ value: 1, errno: 0 }); },
    CModule: class { constructor(src: string) { sources.push(src); } },
};
function load(file: string, modules: Record<string, unknown>): any {
    const exports = {};
    const source = ts.transpileModule(fs.readFileSync(file, "utf8"), {
        compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.CommonJS },
    }).outputText;
    vm.runInNewContext(source, { ...common, exports, require(name: string) {
        assert.ok(name in modules, `unexpected dependency ${name}`);
        return modules[name];
    } });
    return exports;
}
const utils = { getExport() { return pointer; }, log() {} };
const io = load("src/core/native_io.ts", { "./utils": utils, "./state": { STATE: state } });
const producer = load("src/core/cmodule.ts", {
    "./utils": utils, "./native_io": io,
    "./state": { STATE: state, REC_SIZE: 272, RING_RECS: 3, SIMD_REC_SIZE: 520 },
});
producer.buildCModule();
assert.equal(sources.length, 2);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tracemiku-native-writer-"));
try {
    fs.mkdirSync(path.join(tmp, "gum"));
    fs.writeFileSync(path.join(tmp, "gum/gumstalker.h"), `
#include <stdint.h>
typedef struct { uint64_t pc, sp, nzcv, x[31]; unsigned char v[32][16]; } GumCpuContext;
`);
    fs.writeFileSync(path.join(tmp, "writer.c"), sources.join("\n") + `
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>

unsigned char ring[3 * 272], simd_ring[2 * 520];
unsigned long long ring_recs = 3, simd_ring_recs = 2, simd_stride = 1;
volatile unsigned long long head, tail, simd_head, simd_tail;
unsigned long long first_pc;
int trace_io[6], simd_io[6], mutex[16], active = 1;
static unsigned long writes, interruptions, no_space, waits, syncs;
static int disk_full;
static atomic_int observed_enospc, producer_completed;

int lock(void *m) { return pthread_mutex_lock(m); }
int unlock(void *m) { return pthread_mutex_unlock(m); }
int *io___errno(void) { return &errno; }
int io_usleep(unsigned int duration) { assert(duration == 100000); waits++; return disk_full ? usleep(duration) : 0; }
int io_open(const char *p, int flags, int mode) { return open(p, flags, mode); }
long io_pwrite64(int fd, const void *buf, unsigned long size, long long offset) {
    return pwrite(fd, buf, size > 2 ? 2 : size, offset);
}
long io_write(int fd, const void *buf, unsigned long size) {
    if (disk_full) {
        long result = write(fd, buf, size);
        if (result < 0 && errno == ENOSPC) atomic_store(&observed_enospc, 1);
        return result;
    }
    writes++;
    if (writes % 23 == 0) { interruptions++; errno = EINTR; return -1; }
    if (writes % 31 == 0 || writes % 31 == 1) { no_space++; errno = ENOSPC; return -1; }
    return write(fd, buf, size > 37 ? 37 : size);
}
int io_fsync(int fd) {
    if (disk_full) return fsync(fd);
    syncs++;
    if (syncs == 1) { errno = EINTR; return -1; }
    if (syncs == 2) { errno = ENOSPC; return -1; }
    return fsync(fd);
}
static void *release_space(void *unused) {
    (void)unused;
    while (!atomic_load(&observed_enospc)) usleep(1000);
    unsigned long long blocked_head = head;
    usleep(300000);
    assert(!atomic_load(&producer_completed) && head == blocked_head && tail < head);
    assert(unlink("filler.bin") == 0);
    return NULL;
}
int main(int argc, char **argv) {
    disk_full = argc == 2 && strcmp(argv[1], "disk-full") == 0;
    unsigned long long total = disk_full ? 1003 : 10003;
    FILE *trace = disk_full ? fopen("trace.bin", "w+b") : tmpfile();
    FILE *simd = disk_full ? fopen("simd.bin", "w+b") : tmpfile();
    assert(trace && simd);
    trace_io[0] = fileno(trace); simd_io[0] = fileno(simd);
    pthread_t releaser;
    if (disk_full) {
        int fd = open("filler.bin", O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0);
        char block[4096] = {0};
        while (write(fd, block, sizeof(block)) > 0) {}
        assert(errno == ENOSPC); close(fd);
        assert(pthread_create(&releaser, NULL, release_space, NULL) == 0);
    }
    unsigned int instruction = 0xd503201f;
    GumCpuContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pc = (unsigned long long)&instruction;
    for (unsigned long long i = 0; i < total; i++) {
        for (int r = 0; r < 31; r++) ctx.x[r] = i * 100 + r;
        memset(ctx.v, i % 256, sizeof(ctx.v));
        ctx.sp = i * 16; ctx.nzcv = i;
        unsigned long long mapped[2] = {0x1000 + i * 4, 0xd503201f};
        on_insn(&ctx, i % 17 == 0 ? mapped : NULL);
        assert(ctx.pc == (unsigned long long)&instruction);
    }
    flush_trace(); flush_simd();
    atomic_store(&producer_completed, 1);
    if (disk_full) { assert(pthread_join(releaser, NULL) == 0); assert(atomic_load(&observed_enospc)); }
    assert(head == total && tail == head && simd_head == head && simd_tail == head);
    assert(first_pc == 0x1000);
    assert(((unsigned long long *)trace_io)[2] == total * 272);
    assert(((unsigned long long *)simd_io)[2] == total * 520);
    if (!disk_full) assert(interruptions > 0 && no_space > 0 && waits >= no_space);
    assert(trace_io[1] == 0 && simd_io[1] == 0);
    rewind(trace); rewind(simd);
    for (unsigned long long i = 0; i < total; i++) {
        unsigned long long rec[34], vec[65];
        assert(fread(rec, 272, 1, trace) == 1);
        assert(fread(vec, 520, 1, simd) == 1);
        assert(rec[0] == (i % 17 == 0 ? 0x1000 + i * 4 : (unsigned long long)&instruction));
        for (int r = 0; r < 31; r++) assert(rec[r + 1] == i * 100 + r);
        assert(rec[32] == i * 16);
        assert((unsigned int)rec[33] == (unsigned int)i);
        assert((unsigned int)(rec[33] >> 32) == instruction);
        assert(vec[0] == i);
        for (int b = 8; b < 520; b++) assert(((unsigned char *)vec)[b] == i % 256);
    }
    assert(fgetc(trace) == EOF && fgetc(simd) == EOF);
    // 结束锁定写入窗口；晚到的 worker callout 不能写进已封口文件。
    on_insn(&ctx, NULL);
    assert(head == total && simd_head == total);
    unsigned int patch = 1234;
    write_at(trace_io, (unsigned char *)&patch, 4, 12);
    assert(((unsigned long long *)trace_io)[2] == total * 272);
    assert(pread(fileno(trace), &instruction, 4, 12) == 4 && instruction == patch);
    fclose(trace); fclose(simd);
    puts(disk_full ? "native writer: real tmpfs ENOSPC + blocked producer + space recovery + exact GPR/SIMD bytes: PASS"
        : "native writer: tiny buffers + short writes + EINTR + ENOSPC + SIMD + seal: PASS");
}
`);
    execFileSync("cc", ["-O2", "-pthread", "-I", tmp, path.join(tmp, "writer.c"), "-o", path.join(tmp, "test")], { stdio: "pipe" });
    process.stdout.write(execFileSync(path.join(tmp, "test"), [], { encoding: "utf8", timeout: 30000 }));
    if (process.argv.includes("--disk-full")) {
        const mountpoint = path.join(tmp, "volume");
        fs.mkdirSync(mountpoint);
        const script = `import subprocess,sys
volume, binary = sys.argv[1:]
subprocess.run(['mount', '-t', 'tmpfs', '-o', 'size=1M', 'tmpfs', volume], check=True)
try:
    subprocess.run([binary, 'disk-full'], cwd=volume, check=True, timeout=10)
finally:
    subprocess.run(['umount', volume], check=True)
`;
        process.stdout.write(execFileSync("unshare", ["--user", "--map-root-user", "--mount", "--",
            "python3", "-c", script, mountpoint, path.join(tmp, "test")], { encoding: "utf8", timeout: 15000 }));
    }
} finally { fs.rmSync(tmp, { recursive: true, force: true }); }
