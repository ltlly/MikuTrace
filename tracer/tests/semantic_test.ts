import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import ts from "typescript";

function pointer(value: number | string | bigint) {
    const address = BigInt.asUintN(64, BigInt(value));
    return {
        address,
        toString: () => `0x${address.toString(16)}`,
        toInt32: () => Number(BigInt.asIntN(32, address)),
        toUInt32: () => Number(BigInt.asUintN(32, address)),
        compare: (other: any) => address < other.address ? -1 : address > other.address ? 1 : 0,
        isNull: () => address === 0n,
    };
}

function buffer(bytes: number[]) {
    return {
        ...pointer(0x10000), bytes: Uint8Array.from(bytes), reads: [] as number[],
        readByteArray(size: number) {
            this.reads.push(size);
            assert.ok(size <= 128, "payload read must stay bounded");
            return this.bytes.slice(0, size).buffer;
        },
    };
}

const descriptors = new Map<number, string>();
const streams = new Map<string, number>();
const internalFds = new Set<number>();
let internal = false;
const callbacks = new Map<string, any>();
const state: any = {
    semanticEvents: true, semanticHooksInstalled: false, semanticEventBuf: [],
    semanticEventSeq: 0, fnEntered: true, preEntryActive: false, primaryTid: 42,
};
const exports: any = {};
const code = ts.transpileModule(readFileSync(new URL("../src/sidecar/semantic.ts", import.meta.url), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;
runInNewContext(code, {
    exports, ptr: pointer,
    Memory: { alloc: () => ({ text: "", readUtf8String() { return this.text; } }), allocUtf8String: (text: string) => text },
    NativeFunction: function (address: any) {
        if (address.name === "fileno") return (stream: any) => streams.get(stream.toString()) ?? -1;
        assert.equal(address.name, "readlink");
        return (path: string, output: any, size: number) => {
            assert.equal(size, 160);
            const fd = Number(path.split("/").at(-1));
            const name = descriptors.get(fd);
            if (name === undefined) return -1;
            output.text = name.slice(0, size);
            return output.text.length;
        };
    },
    Interceptor: { attach: (address: any, handlers: any) => callbacks.set(address.name, handlers) },
    require: (name: string) => {
        if (name === "../core/native_io") return { internalFds, internalIoActive: () => internal };
        if (name === "../core/state") return { STATE: state };
        if (name === "../transport/manifest") return { persistEvents() {} };
        assert.equal(name, "../core/utils");
        return { log() {}, getExport: (name: string) => ({ name, isNull: () => false }),
            ptrToStringMaybe: (value: any) => value.text ?? null, currentTraceIdx: () => 7,
            syscallName: (nr: number) => ({ 57: "close", 64: "write" })[nr] ?? `syscall_${nr}` };
    },
});
exports.installSemanticHooksOnce();
const required = ["close", "fclose", "dup", "dup2", "dup3", "fopen", "fdopen", "lseek", "lseek64",
    "fstat", "newfstatat", "access", "faccessat", "unlink", "unlinkat", "rename", "renameat"];
for (const name of required) assert.ok(callbacks.has(name), name);

function invoke(name: string, args: any[], result = 0, during = () => {}) {
    const context = { threadId: 42 };
    const count = state.semanticEventBuf.length;
    const padded = [...args, ...Array.from({ length: 7 }, () => pointer(0))];
    callbacks.get(name).onEnter.call(context, padded);
    during();
    callbacks.get(name).onLeave.call(context, pointer(result));
    return state.semanticEventBuf.length === count ? null : state.semanticEventBuf.at(-1);
}
const string = (text: string) => ({ ...pointer(0x20000), text });
let event = invoke("open", [string("/old"), pointer(0), pointer(0)], 3, () => descriptors.set(3, "/old"));
assert.equal(event.args.result_fd, 3);
assert.equal(event.args.result_fd_path, "/old");
const payload = buffer([0x11, 0x22, 0x33, 0x44]);
event = invoke("read", [pointer(3), payload, pointer(4)], 2, () => payload.bytes.set([0xaa, 0xbb]));
assert.equal(event.args.fd_path, "/old");
assert.equal(event.args.data_hex, "aabb");
assert.equal(event.args.data_truncated, false);
assert.deepEqual(payload.reads, [2]);
event = invoke("write", [pointer(3), payload, pointer(4)], 4, () => payload.bytes.fill(0));
assert.equal(event.args.data_hex, "aabb3344");
event = invoke("close", [pointer(3)], 0, () => descriptors.delete(3));
assert.equal(event.args.fd_path, "/old");
event = invoke("read", [pointer(3), payload, pointer(4)], -1);
assert.equal(event.args.fd_path, undefined);
assert.equal(event.args.data_hex, undefined);
invoke("open", [string("/new"), pointer(0), pointer(0)], 3, () => descriptors.set(3, "/new"));
event = invoke("pread64", [pointer(3), payload, pointer(4), pointer(0)], 1);
assert.equal(event.args.fd_path, "/new");
assert.equal(event.args.data_hex, "00");
descriptors.set(9, "/replaced");
event = invoke("dup2", [pointer(3), pointer(9)], 9, () => descriptors.set(9, descriptors.get(3)!));
assert.equal(event.args.arg1_fd_path, "/replaced");
assert.equal(event.args.result_fd_path, "/new");
invoke("close", [pointer(3)], 0, () => descriptors.delete(3));
assert.equal(invoke("read", [pointer(9), payload, pointer(4)], 1).args.fd_path, "/new");
state.fnEntered = false;
invoke("close", [pointer(9)], 0, () => descriptors.delete(9));
descriptors.set(9, "/between-calls");
state.fnEntered = true;
assert.equal(invoke("fstat", [pointer(9), pointer(0)]).args.fd_path, "/between-calls");

const stream = pointer(0x5000);
event = invoke("fopen", [string("/stdio"), string("r")], 0x5000, () => {
    descriptors.set(10, "/stdio"); streams.set(stream.toString(), 10);
});
assert.equal(event.args.result_fd_path, "/stdio");
event = invoke("fdopen", [pointer(10), string("r")], 0x5000);
assert.equal(event.args.fd_path, "/stdio");
event = invoke("fclose", [stream], 0, () => { descriptors.delete(10); streams.delete(stream.toString()); });
assert.equal(event.args.fd_path, "/stdio");
assert.equal(invoke("read", [pointer(10), payload, pointer(4)], -1).args.fd_path, undefined);

for (const name of ["read", "pread64", "write", "pwrite64"]) {
    const data = buffer(Array.from({ length: 256 }, () => 0xab));
    event = invoke(name, [pointer(9), data, pointer("0x100000001"), pointer(0)], 200);
    assert.equal(event.args.data_hex, "ab".repeat(128));
    assert.equal(event.args.data_truncated, true);
    assert.deepEqual(data.reads, [128]);
}
for (const result of [0, -1]) {
    const data = buffer([1]);
    invoke("read", [pointer(9), data, pointer(1)], result);
    assert.deepEqual(data.reads, []);
}
const unreadable = { ...pointer(0x1000), readByteArray() { throw new Error("unmapped"); } };
event = invoke("write", [pointer(9), unreadable, pointer(10)], -1);
assert.equal(event.args.data_hex, null);
assert.equal(event.args.data_truncated, true);
assert.match(event.args.data_error, /unmapped/);

internalFds.add(99);
streams.set(stream.toString(), 99);
for (const name of ["read", "write", "pread64", "pwrite64", "close", "dup", "dup2", "dup3",
    "fdopen", "lseek", "lseek64", "fstat", "newfstatat", "faccessat", "unlinkat", "renameat", "openat", "ioctl"]) {
    assert.equal(invoke(name, [pointer(99), payload, pointer(4), pointer(0)]), null, name);
}
assert.equal(invoke("dup2", [pointer(9), pointer(99)]), null);
assert.equal(invoke("fclose", [stream]), null);
assert.equal(invoke("mmap", [pointer(0), pointer(0), pointer(0), pointer(0), pointer(99)]), null);
assert.equal(invoke("syscall", [pointer(64), pointer(99), payload, pointer(4)]), null);
internal = true;
assert.equal(invoke("open", [string("/collector"), pointer(0)]), null);
assert.equal(invoke("unlink", [string("/collector")]), null);
console.log("semantic: FD lifecycle + kernel path attribution + bounded read/write payload + internal FD filtering: PASS");
