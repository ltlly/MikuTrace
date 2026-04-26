// 轻量 agent — 只抓 doCommandNative 的输入参数和返回值。不用 Stalker.
// 利用 JNIEnv API 读取 Java 对象内容 (jstring → utf8, byte[] → hex, int → int).

const STATE = {
    soPattern: null, methodName: "doCommandNative", fnOffset: 0x57770,
    cmdValue: 70102, cmdArg: 2,
    target: null, fnHooked: false,
    callIdx: 0,
    env: null,
};

function log(...a) { send({ type: "log", msg: a.map(String).join(" ") }); }

// 通过 vtable 拿 JNIEnv 函数指针 (idx 见 jni.h)
const JNI_FN = {
    GetVersion: 4, FindClass: 6, GetObjectClass: 31,
    NewStringUTF: 167, GetStringUTFChars: 169, ReleaseStringUTFChars: 170,
    GetStringUTFLength: 168,
    GetArrayLength: 171, GetObjectArrayElement: 173,
    GetByteArrayElements: 184, ReleaseByteArrayElements: 192,
    GetMethodID: 33, CallObjectMethod: 34, CallIntMethod: 49,
    GetStaticMethodID: 113, CallStaticObjectMethod: 114,
    IsSameObject: 24, NewLocalRef: 25, DeleteLocalRef: 23,
};

function call_jni(env, fn_idx, ret_t, args_t) {
    const fnTable = env.readPointer();
    const fp = fnTable.add(fn_idx * 8).readPointer();
    return new NativeFunction(fp, ret_t, args_t);
}

function jstring_to_utf8(env, jstr) {
    if (jstr.isNull()) return null;
    try {
        const getUtf = call_jni(env, JNI_FN.GetStringUTFChars, 'pointer', ['pointer','pointer','pointer']);
        const releaseUtf = call_jni(env, JNI_FN.ReleaseStringUTFChars, 'void', ['pointer','pointer','pointer']);
        const cstr = getUtf(env, jstr, NULL);
        const s = cstr.readCString();
        releaseUtf(env, jstr, cstr);
        return s;
    } catch (e) { return `<read err: ${e}>`; }
}

function bytes_to_hex(env, jba, max_len = 256) {
    if (jba.isNull()) return null;
    try {
        const getLen = call_jni(env, JNI_FN.GetArrayLength, 'int', ['pointer','pointer']);
        const getEls = call_jni(env, JNI_FN.GetByteArrayElements, 'pointer', ['pointer','pointer','pointer']);
        const releaseEls = call_jni(env, JNI_FN.ReleaseByteArrayElements, 'void', ['pointer','pointer','pointer','int']);
        const len = getLen(env, jba);
        const els = getEls(env, jba, NULL);
        const dump_n = Math.min(len, max_len);
        const buf = els.readByteArray(dump_n);
        const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
        releaseEls(env, jba, els, 0);
        return { len, hex, truncated: len > max_len };
    } catch (e) { return `<read err: ${e}>`; }
}

function describe_jobject(env, obj, depth = 0) {
    if (obj.isNull()) return "null";
    if (depth > 2) return "<...>";
    try {
        // GetObjectClass + GetClass.getName()
        const getCls = call_jni(env, JNI_FN.GetObjectClass, 'pointer', ['pointer','pointer']);
        const cls = getCls(env, obj);
        // call cls.getName() -> jstring
        const getMethodID = call_jni(env, JNI_FN.GetMethodID, 'pointer', ['pointer','pointer','pointer','pointer']);
        const callObj = call_jni(env, JNI_FN.CallObjectMethod, 'pointer', ['pointer','pointer','pointer']);
        const nameStr = Memory.allocUtf8String("getName");
        const sigStr = Memory.allocUtf8String("()Ljava/lang/String;");
        const mid = getMethodID(env, cls, nameStr, sigStr);
        if (mid.isNull()) return `<class ?>`;
        const cnameJStr = callObj(env, cls, mid);
        const cname = jstring_to_utf8(env, cnameJStr);
        // 根据类名细化处理
        if (cname === "java.lang.String") {
            const s = jstring_to_utf8(env, obj);
            return { type: cname, value: s };
        }
        if (cname === "[B") {
            const ba = bytes_to_hex(env, obj);
            return { type: cname, ...ba };
        }
        if (cname === "java.lang.Integer" || cname === "java.lang.Long") {
            // call .longValue()
            const mid2 = getMethodID(env, cls, Memory.allocUtf8String("longValue"), Memory.allocUtf8String("()J"));
            if (!mid2.isNull()) {
                const callLong = call_jni(env, 51, 'int64', ['pointer','pointer','pointer']);  // CallLongMethod
                const v = callLong(env, obj, mid2);
                return { type: cname, value: v.toString() };
            }
        }
        // toString fallback
        try {
            const tsId = getMethodID(env, cls, Memory.allocUtf8String("toString"), Memory.allocUtf8String("()Ljava/lang/String;"));
            if (!tsId.isNull()) {
                const tsRet = callObj(env, obj, tsId);
                return { type: cname, toString: jstring_to_utf8(env, tsRet) };
            }
        } catch (_) {}
        return { type: cname };
    } catch (e) { return `<describe err: ${e}>`; }
}

function dump_args(env, this_, cmdId, args_array) {
    const out = { call: STATE.callIdx, cmd: cmdId, this: this_.toString(),
                  args: [] };
    if (args_array.isNull()) {
        out.args = "null"; return out;
    }
    try {
        const getLen = call_jni(env, JNI_FN.GetArrayLength, 'int', ['pointer','pointer']);
        const getEl = call_jni(env, JNI_FN.GetObjectArrayElement, 'pointer', ['pointer','pointer','int']);
        const n = getLen(env, args_array);
        out.args_count = n;
        for (let i = 0; i < Math.min(n, 16); i++) {
            const el = getEl(env, args_array, i);
            out.args.push(describe_jobject(env, el));
        }
        if (n > 16) out.args.push(`<...+${n-16} more>`);
    } catch (e) { out.args_err = String(e); }
    return out;
}

function hook() {
    if (STATE.fnHooked) return true;
    if (!STATE.target) return false;
    const fp = STATE.target.base.add(STATE.fnOffset);
    log(`[+] hook ${STATE.methodName} @ ${fp} filter cmd==${STATE.cmdValue}`);
    Interceptor.attach(fp, {
        onEnter(args) {
            const cmd = args[STATE.cmdArg].toInt32();
            if (cmd !== STATE.cmdValue) { this._skip = true; return; }
            STATE.callIdx++;
            const env = args[0]; const this_ = args[1]; const arr = args[3];
            this._tid = this.threadId; this._t0 = Date.now();
            this._env = env;
            const dumped = dump_args(env, this_, cmd, arr);
            log(`[>] call #${STATE.callIdx} tid=${this._tid}`);
            send({ type: "args", call_idx: STATE.callIdx, tid: this._tid,
                   data: dumped });
        },
        onLeave(retv) {
            if (this._skip) return;
            const elapsed = Date.now() - this._t0;
            // ret is jobject — describe it
            const env = this._env;
            let desc = "?";
            try {
                if (!retv.isNull()) desc = describe_jobject(env, retv);
                else desc = "null";
            } catch (e) { desc = `<err: ${e}>`; }
            log(`[<] call #${STATE.callIdx} ret=${retv} elapsed=${elapsed}ms`);
            send({ type: "ret", call_idx: STATE.callIdx, tid: this._tid,
                   ms: elapsed, retval: retv.toString(), data: desc });
        }
    });
    STATE.fnHooked = true;
    return true;
}

function arm() {
    if (STATE.target) return true;
    for (const m of Process.enumerateModules()) {
        if (m.name.indexOf(STATE.soPattern) !== -1) {
            STATE.target = { name: m.name, base: m.base, end: m.base.add(m.size), size: m.size };
            log(`[+] target ${m.name} @ ${m.base}`);
            send({ type: "module", name: m.name, base: m.base.toString(), size: m.size, pid: Process.id });
            return true;
        }
    }
    return false;
}

rpc.exports = {
    init(opts) {
        opts = opts || {};
        STATE.soPattern = opts.soPattern || "libsgmainso";
        STATE.cmdValue = opts.cmdValue !== undefined ? opts.cmdValue : 70102;
        STATE.fnOffset = opts.fnOffset !== undefined ? opts.fnOffset : 0x57770;
        log(`[*] dump-args agent up`);
        send({ type: "hello", pid: Process.id, frida: Frida.version });
        arm();
        const tryHook = () => arm() && hook();
        if (!tryHook()) {
            const id = setInterval(() => { if (tryHook()) clearInterval(id); }, 50);
        }
        return "armed";
    },
    stats() { return { calls: STATE.callIdx, fnHooked: STATE.fnHooked }; }
};
