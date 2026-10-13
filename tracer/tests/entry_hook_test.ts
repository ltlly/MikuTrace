/** 故障注入验证真实入口安装器的原子发布、回滚与第三方改写保护。 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import ts from "typescript";

const source = ts.transpileModule(readFileSync("src/core/entry.ts", "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;

function fixture(fault = "") {
    const words = new Map<bigint, number>([[0x1000n, 0xd503201f]]);
    let detached = 0, patched = 0, faultUsed = false;
    let handlers: any;
    class Pointer {
        value: bigint;
        constructor(value: bigint) { this.value = value; }
        add(n: number) { return new Pointer(this.value + BigInt(n)); }
        toString() { return `0x${this.value.toString(16)}`; }
        compare(other: Pointer) { return Number(this.value - other.value); }
        readU32() { return words.get(this.value) || 0; }
        writeU32(n: number) { words.set(this.value, n); }
        writePointer() {}
    }
    const target = new Pointer(0x1000n);
    function instruction(address: Pointer) {
        return { address, mnemonic: fault === "exclusive" ? "ldaxr" : fault === "lr" ? "mov" : "nop",
            operands: [{}, { type: "reg", value: "lr" }],
            regsAccessed: { read: fault === "ips" ? ["w16", "x17"] : [], written: [] } };
    }
    const exports: any = {};
    vm.runInNewContext(source, {
        exports, Process: { pageSize: 4096 }, Instruction: { parse: instruction },
        Memory: {
            alloc: (_size: number, options?: any) => new Pointer(options ? 0x2000n : 0x3000n),
            protect: () => fault !== "protect",
            patchCode(address: Pointer, _size: number, write: (p: Pointer) => void) {
                if (address.value === target.value) {
                    patched++;
                    if (fault === "race") target.writeU32(0xdeadbeef);
                    write(address);
                    if (fault === "patch-after-write" && !faultUsed) {
                        faultUsed = true; throw new Error("patch-after-write");
                    }
                } else {
                    // 某些后端不向调用方传播 callback 异常。
                    try { write(address); } catch (_) {}
                }
            },
        },
        Arm64Writer: class {
            offset = 0;
            putPushRegReg() { this.offset += 4; }
            putPopRegReg() { this.offset += 4; }
            putNop() { this.offset += 4; }
            putBImm() { this.offset += 4; }
            flush() {} dispose() {}
        },
        Arm64Relocator: class {
            input = instruction(target); eoi = false;
            readOne() { return fault === "relocate" ? 0 : 4; }
            writeOne() { return true; } dispose() {}
        },
        Interceptor: { attach: (_address: Pointer, callbacks: any) => {
            handlers = callbacks;
            if (fault === "attach") throw new Error("attach");
            return { detach() { detached++; } };
        } },
    });
    return { exports, target, words, detached: () => detached, patched: () => patched, handlers: () => handlers };
}

for (const fault of ["exclusive", "lr", "relocate", "protect", "attach"]) {
    const f = fixture(fault);
    assert.throws(() => f.exports.attachEntryHook(f.target, {}), undefined, fault);
    assert.equal(f.target.readU32(), 0xd503201f, fault);
    assert.equal(f.patched(), 0, "不能在准备失败时改写入口");
}
for (const fault of ["race", "patch-after-write"]) {
    const f = fixture(fault);
    assert.throws(() => f.exports.attachEntryHook(f.target, {}), undefined, fault);
    assert.equal(f.target.readU32(), fault === "race" ? 0xdeadbeef : 0xd503201f);
    assert.equal(f.detached(), 1);
    f.exports.releaseEntryHook();
    assert.equal(f.detached(), 1);
}
const f = fixture();
f.exports.attachEntryHook(f.target, {});
assert.notEqual(f.target.readU32(), 0xd503201f);
assert.equal(f.exports.entryInstruction({ toString: () => "0x2018" }).pc.toString(), "0x1000");
assert.equal(f.exports.isEntryRedirect(f.target), true);
f.exports.releaseEntryHook(); f.exports.releaseEntryHook();
assert.equal(f.target.readU32(), 0xd503201f);
assert.equal(f.detached(), 1, "停止必须幂等");
const changed = fixture();
changed.exports.attachEntryHook(changed.target, {});
changed.target.writeU32(0xdeadbeef);
assert.throws(() => changed.exports.releaseEntryHook(), /changed before restoring/);
assert.equal(changed.target.readU32(), 0xdeadbeef, "不能覆盖其他 hook 的修改");
const stack = fixture();
stack.exports.attachEntryHook(stack.target, { onEnter(this: any) {
    assert.equal(this.context.sp.toString(), "0x1010", "回调必须看到原始栈参数地址");
    throw new Error("callback failure");
} });
const context = { context: { sp: stack.target } };
assert.throws(() => stack.handlers().onEnter.call(context, []), /callback failure/);
assert.equal(context.context.sp.toString(), "0x1000", "异常路径也必须恢复桥栈帧");
console.log("entry hook: atomic patch + rollback + conflict + idempotent restore: PASS");
