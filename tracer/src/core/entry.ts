/**
 * 在独立入口桥上安装 Interceptor，原函数被搬移的指令仍经过 Stalker。
 * 用一个对齐的 B 指令接入桥，避免覆盖短函数；不读取 Frida 私有结构。
 */
export interface EntryInstruction {
    pc: NativePointer;
    instruction: number;
    data: NativePointer;
}

interface EntryHook {
    target: NativePointer;
    code: NativePointer;
    size: number;
    original: number;
    redirect: number;
    listener: InvocationListener;
    instructions: Map<string, EntryInstruction>;
    released: boolean;
}

const REDIRECT_BYTES = 4;
const BRIDGE_PADDING = 16;
let installed: EntryHook | null = null;

export function attachEntryHook(target: NativePointer, callbacks: ScriptInvocationListenerCallbacks): void {
    if (installed) throw new Error("capture entry already installed");
    if ((BigInt(target.toString()) & 3n) !== 0n) throw new Error("unaligned ARM64 entry");
    for (let offset = 0; offset < BRIDGE_PADDING; offset += 4) {
        const ins = Instruction.parse(target.add(offset)) as Arm64Instruction;
        // 原子窗口不能被拆到两个翻译块；读取 LR 的跳板也不能用普通搬移替代
        // Frida 的 caller-address 修正。此类入口明确失败，不退回漏采集路径。
        if (/^(ldax?[rp]|ldxr|ldxp|stlx?[rp]|stxr|stxp|clrex)/.test(ins.mnemonic)) {
            throw new Error(`exclusive instruction in entry prologue: ${ins}`);
        }
        if (ins.mnemonic === "mov" && ins.operands[1]?.type === "reg" &&
            ["lr", "x30"].includes(String(ins.operands[1].value))) {
            throw new Error(`caller-address-sensitive entry prologue: ${ins}`);
        }
        if (["ret", "retaa", "retab", "br", "braa", "braaz", "brab", "brabz", "b"].includes(ins.mnemonic)) break;
    }
    // 直接 B 返回原函数，避免在原始指令之间增加寄存器改写。
    const code = Memory.alloc(Process.pageSize, { near: target, maxDistance: 0x07ff0000 });
    const distance = BigInt(code.toString()) - BigInt(target.toString());
    if (distance < -0x8000000n || distance >= 0x8000000n || (distance & 3n) !== 0n) {
        throw new Error("entry bridge is outside ARM64 direct branch range");
    }
    const redirect = (0x14000000 | Number((distance >> 2n) & 0x03ffffffn)) >>> 0;
    const originalOpcode = target.readU32();
    const instructions = new Map<string, EntryInstruction>();
    let relocationError: unknown = null;
    Memory.patchCode(code, Process.pageSize, writable => {
        const writer = new Arm64Writer(writable, { pc: code });
        const relocator = new Arm64Relocator(target, writer);
        try {
            // Interceptor 的 thunk 会使用两个 IP；在进入它之前保存，恢复后才
            // 执行原指令。不能靠“前 16 字节没用 IP”推断后续函数也不使用。
            writer.putPushRegReg("x16", "x17");
            for (let i = 0; i < 4; i++) writer.putNop();
            writer.putPopRegReg("x16", "x17");
            let read = 0;
            while (read < REDIRECT_BYTES) {
                read = relocator.readOne();
                if (!read) throw new Error("entry ends before complete relocation");
                const ins = relocator.input!;
                const data = Memory.alloc(16);
                data.writePointer(ins.address);
                data.add(8).writeU32(ins.address.readU32());
                instructions.set(code.add(writer.offset).toString(), {
                    pc: ins.address, instruction: ins.address.readU32(), data,
                });
                if (!relocator.writeOne()) throw new Error("entry relocation failed");
            }
            if (!relocator.eoi) writer.putBImm(target.add(read));
            writer.flush();
        } catch (error) {
            // patchCode 回调抛错在某些 GumJS 后端只发 error 消息；显式带回调用层。
            relocationError = error;
        } finally {
            relocator.dispose(); writer.dispose();
        }
    });
    if (relocationError) throw relocationError;
    if (!Memory.protect(code, Process.pageSize, "r-x")) throw new Error("entry bridge is not executable");
    const listener = Interceptor.attach(code.add(4), {
        onEnter(args) {
            // 调用者参数及快照应看到原 SP；返回桥前恢复其内部栈帧。
            const bridgeSp = this.context.sp;
            this.context.sp = bridgeSp.add(16);
            try { callbacks.onEnter?.call(this, args); }
            finally { this.context.sp = bridgeSp; }
        },
        onLeave(retval) { callbacks.onLeave?.call(this, retval); },
    });
    // 在发布跳转前持有桥和 metadata；失败回滚期间也可能已有其他线程进入桥。
    const hook: EntryHook = { target, code, size: REDIRECT_BYTES, listener, instructions,
        original: originalOpcode, redirect, released: false };
    installed = hook;
    try {
        // 单条 4 字节对齐写入；其他线程只会看到完整的原指令或完整 B 指令。
        // 异步目标自修改/其他 hook 改写时拒绝覆盖，不覆盖第三方修改。
        let patchError: unknown = null;
        Memory.patchCode(target, REDIRECT_BYTES, writable => {
            if (target.readU32() !== originalOpcode) patchError = new Error("entry changed while arming");
            else writable.writeU32(redirect);
        });
        if (patchError) throw patchError;
    } catch (error) {
        // patchCode 若在写入后失败，必须恢复原入口；不能让 GC 回收仍可执行的桥。
        if (target.readU32() === redirect) restoreEntry(hook);
        listener.detach(); hook.released = true;
        throw error;
    }
}

export function entryInstruction(address: NativePointer): EntryInstruction | undefined {
    return installed?.instructions.get(address.toString());
}

export function isEntryRedirect(address: NativePointer): boolean {
    return !!installed && address.compare(installed.target) >= 0 &&
        address.compare(installed.target.add(installed.size)) < 0;
}

export function entryAddress(): NativePointer | null { return installed?.target || null; }

export function releaseEntryHook(): void {
    if (!installed || installed.released) return;
    restoreEntry(installed);
    installed.listener.detach();
    installed.released = true;
    // 小型桥及映射保留到 eternalized Script 所在进程退出，避免释放其他线程
    // 已进入但未返回的桥。采集器停止后不会再创建新的桥。
}

function restoreEntry(hook: EntryHook): void {
    let patchError: unknown = null;
    Memory.patchCode(hook.target, hook.size, writable => {
        if (hook.target.readU32() !== hook.redirect) patchError = new Error("entry changed before restoring");
        else writable.writeU32(hook.original);
    });
    if (patchError) throw patchError;
}
