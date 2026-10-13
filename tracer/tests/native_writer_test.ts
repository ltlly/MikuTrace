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

unsigned char ring[3 * 272], simd_ring[2 * 520];
unsigned long long ring_recs = 3, simd_ring_recs = 2, simd_stride = 1;
volatile unsigned long long head, tail, simd_head, simd_tail;
int trace_io[6], simd_io[6], mutex[16], active = 1;
static unsigned long writes, interruptions, no_space, waits, syncs;

int lock(void *m) { return pthread_mutex_lock(m); }
int unlock(void *m) { return pthread_mutex_unlock(m); }
int *io___errno(void) { return &errno; }
int io_usleep(unsigned int duration) { assert(duration == 100000); waits++; return 0; }
int io_open(const char *p, int flags, int mode) { return open(p, flags, mode); }
long io_pwrite64(int fd, const void *buf, unsigned long size, long long offset) {
    return pwrite(fd, buf, size > 2 ? 2 : size, offset);
}
long io_write(int fd, const void *buf, unsigned long size) {
    writes++;
    if (writes % 23 == 0) { interruptions++; errno = EINTR; return -1; }
    if (writes % 31 == 0 || writes % 31 == 1) { no_space++; errno = ENOSPC; return -1; }
    return write(fd, buf, size > 37 ? 37 : size);
}
int io_fsync(int fd) {
    syncs++;
    if (syncs == 1) { errno = EINTR; return -1; }
    if (syncs == 2) { errno = ENOSPC; return -1; }
    return fsync(fd);
}
int main(void) {
    FILE *trace = tmpfile(), *simd = tmpfile();
    assert(trace && simd);
    trace_io[0] = fileno(trace); simd_io[0] = fileno(simd);
    unsigned int instruction = 0xd503201f;
    GumCpuContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.pc = (unsigned long long)&instruction;
    for (unsigned long long i = 0; i < 10003; i++) {
        for (int r = 0; r < 31; r++) ctx.x[r] = i * 100 + r;
        memset(ctx.v, i % 256, sizeof(ctx.v));
        ctx.sp = i * 16; ctx.nzcv = i;
        on_insn(&ctx, NULL);
    }
    flush_trace(); flush_simd();
    assert(head == 10003 && tail == head && simd_head == head && simd_tail == head);
    assert(((unsigned long long *)trace_io)[2] == 10003 * 272);
    assert(((unsigned long long *)simd_io)[2] == 10003 * 520);
    assert(interruptions > 0 && no_space > 0 && waits >= no_space);
    assert(trace_io[1] == 0 && simd_io[1] == 0);
    rewind(trace); rewind(simd);
    for (unsigned long long i = 0; i < 10003; i++) {
        unsigned long long rec[34], vec[65];
        assert(fread(rec, 272, 1, trace) == 1);
        assert(fread(vec, 520, 1, simd) == 1);
        assert(rec[0] == (unsigned long long)&instruction);
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
    assert(head == 10003 && simd_head == 10003);
    unsigned int patch = 1234;
    write_at(trace_io, (unsigned char *)&patch, 4, 12);
    assert(((unsigned long long *)trace_io)[2] == 10003 * 272);
    assert(pread(fileno(trace), &instruction, 4, 12) == 4 && instruction == patch);
    fclose(trace); fclose(simd);
    puts("native writer: tiny buffers + short writes + EINTR + ENOSPC + SIMD + seal: PASS");
}
`);
    execFileSync("cc", ["-O2", "-pthread", "-I", tmp, path.join(tmp, "writer.c"), "-o", path.join(tmp, "test")], { stdio: "pipe" });
    process.stdout.write(execFileSync(path.join(tmp, "test"), [], { encoding: "utf8", timeout: 30000 }));
} finally { fs.rmSync(tmp, { recursive: true, force: true }); }
