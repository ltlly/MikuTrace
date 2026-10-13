/** 在实际目录探测实现上模拟新安装 app、Android 多用户和显式只读目录。 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import vm from "node:vm";
import ts from "typescript";

const code = ts.transpileModule(readFileSync(new URL("../src/core/ring.ts", import.meta.url), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;

function fixture(explicit: string | null = null) {
    const app = "/data/user/10/dev.fixture";
    const dirs = new Set([app, "/blocked"]);
    const files = new Map<string, string>();
    const mkdirCalls: string[] = [];
    const state = { pkg: "dev.fixture", traceDir: explicit };
    const exports: any = {};
    const modules: any = {
        "./state": { STATE: state }, "./utils": { getExport: (name: string) => name, log() {} },
        "./native_io": { NativeFile: class {
            file: string;
            constructor(file: string) {
                this.file = file;
                if (!file.startsWith(app + "/") || !dirs.has(path.dirname(file))) throw new Error("EACCES");
            }
            write(data: string) { files.set(this.file, data); }
            close() {}
        } },
    };
    vm.runInNewContext(code, {
        exports, require: (name: string) => {
            assert.ok(name in modules, name);
            return modules[name];
        },
        Process: { id: 123 }, Memory: { allocUtf8String: (text: string) => text },
        File: { readAllBytes: (file: string) => new TextEncoder().encode(files.get(file)).buffer },
        NativeFunction: function (name: string) {
            if (name === "getuid") return () => 1012345;
            if (name === "unlink") return (file: string) => files.delete(file) ? 0 : -1;
            assert.equal(name, "mkdir");
            return (dir: string) => {
                mkdirCalls.push(dir);
                if (dirs.has(dir) || !dirs.has(path.dirname(dir))) return -1;
                dirs.add(dir); return 0;
            };
        },
    });
    return { exports, state, files, dirs, mkdirCalls, app };
}

const fresh = fixture();
assert.ok(!fresh.dirs.has(fresh.app + "/files"));
fresh.exports.ensureTraceDir();
assert.ok(fresh.state.traceDir?.startsWith(fresh.app + "/files/.miku/session_123_"));
assert.ok(fresh.mkdirCalls.indexOf(fresh.app + "/files") < fresh.mkdirCalls.indexOf(fresh.app + "/files/.miku"));
assert.equal(fresh.files.size, 0, "写入回读后的 probe 必须清理");
(fresh.state as any).traceFile = { close() { throw new Error("close failure"); } };
assert.throws(() => fresh.exports.closeTraceFile(), /close failure/, "关闭失败必须传给封口层");

const blocked = fixture("/blocked/explicit");
assert.throws(() => blocked.exports.ensureTraceDir(), /not writable/);
assert.deepEqual(blocked.mkdirCalls, ["/blocked/explicit"], "显式路径失败不能静默换目录");

// 设备 manifest 必须收集断线时积累的插件事件，并把文件列为必需回传项。
const artifactFiles = new Map<string, string>();
const manifestExports: any = {};
let pluginEvents = [{ phase: "install", status: "ok" }];
const manifestModules: any = {
    "../core/state": { STATE: {
        traceDir: "/spool", traceFilePath: "/spool/trace.bin", callIdx: 1,
        primaryTid: 42, started: 1000, includeRanges: [],
    }, REC_SIZE: 272 },
    "../core/utils": { getExport: () => "rename" },
    "../core/entry": { entryAddress: () => ({ toString: () => "0x1000" }) },
    "../core/external_writes": {},
    "../target_plugins": { drainTargetPluginEvents() {
        const events = pluginEvents; pluginEvents = []; return events;
    } },
    "../core/native_io": { syncDirectory() {}, NativeFile: class {
        file: string;
        bytes = 0;
        constructor(file: string) { this.file = file; artifactFiles.set(file, ""); }
        write(text: string) {
            artifactFiles.set(this.file, artifactFiles.get(this.file)! + text);
            this.bytes += new TextEncoder().encode(text).byteLength;
        }
        close() {}
    } },
};
vm.runInNewContext(ts.transpileModule(readFileSync(
    new URL("../src/transport/manifest.ts", import.meta.url), "utf8"), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText, {
    exports: manifestExports, Process: { id: 123, enumerateModules: () => [] },
    Memory: { allocUtf8String: (text: string) => text },
    require: (name: string) => { assert.ok(name in manifestModules, name); return manifestModules[name]; },
    SystemFunction: function () { return (from: string, to: string) => {
        artifactFiles.set(to, artifactFiles.get(from)!); artifactFiles.delete(from);
        return { value: 0 };
    }; },
});
manifestExports.prepareManifest("a".repeat(32));
manifestExports.beginManifest();
pluginEvents.push({ phase: "beforeTrace", status: "ok" });
manifestExports.sealManifest({ total: 3, truncated: false, firstPc: "0x1000", returnObserved: true }, true);
const sealed = JSON.parse(artifactFiles.get("/spool/call_1.json")!);
const eventsArtifact = sealed.files.find((file: any) => file.name === "target_plugin_events.jsonl");
assert.equal(eventsArtifact.records, 2);
assert.equal(eventsArtifact.bytes, artifactFiles.get(eventsArtifact.device_path)!.length);
assert.deepEqual(artifactFiles.get(eventsArtifact.device_path)!.trim().split("\n").map(line => JSON.parse(line)), [
    { phase: "install", status: "ok" }, { phase: "beforeTrace", status: "ok" },
]);
assert.equal(sealed.meta.event_counts["target_plugin_events.jsonl"], 2);
assert.equal(sealed.meta.capture_scope.entry_complete, true);
assert.equal(sealed.meta.capture_scope.return_observed, true);
assert.equal(JSON.parse(artifactFiles.get("/spool/session.json")!).state, "SEALED");
manifestModules["../core/state"].STATE.callIdx = 2;
manifestExports.beginManifest();
manifestExports.sealManifest({ total: 3, truncated: false, firstPc: "0x1004", returnObserved: true }, true);
const missingEntry = JSON.parse(artifactFiles.get("/spool/call_2.json")!);
assert.equal(missingEntry.meta.capture_scope.entry_complete, false);
assert.equal(missingEntry.meta.capture_scope.coverage_gaps, 1);
assert.equal(missingEntry.meta.truncated, true);
assert.equal(JSON.parse(artifactFiles.get("/spool/call2_coverage_gaps.jsonl")!).reason, "entry-not-observed");
console.log("device spool: fresh app directory + actual UID + write/read probe + fail closed: PASS");
