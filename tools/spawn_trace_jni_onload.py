#!/usr/bin/env python3
"""spawn_trace_jni_onload.py — Spawn 模式 trace JNI_OnLoad (解决 init 函数时序竞争)"""
import frida
import sys
import time
import pathlib

HERE = pathlib.Path(__file__).resolve().parent.parent

def on_message(msg, data):
    t = msg.get('type', '?')
    if t == 'send':
        p = msg.get('payload', msg)
        if isinstance(p, dict):
            ptype = p.get('type', '?')
            if ptype == 'log':
                print(f"[AGENT] {p.get('msg', '')}", flush=True)
            elif ptype == 'trace-begin':
                print(f"[TRACE-BEGIN] call#{p.get('callIdx')} tid={p.get('tid')} devicePath={p.get('devicePath','?')}", flush=True)
            elif ptype == 'trace-end':
                print(f"[TRACE-END] call#{p.get('callIdx')} records={p.get('recs',0)} ms={p.get('ms')} ret={p.get('retval')}", flush=True)
            elif ptype == 'hello':
                print(f"[HELLO] frida={p.get('frida')}", flush=True)
            else:
                print(f"[{ptype}] {p}", flush=True)
        else:
            print(f"[AGENT] {p}", flush=True)
    elif t == 'error':
        print(f"[ERROR] {msg.get('description', msg)}", flush=True)

def main():
    pkg = sys.argv[1] if len(sys.argv) > 1 else "com.kuaishou.nebula"
    so = sys.argv[2] if len(sys.argv) > 2 else "libkwsgmain"
    export = sys.argv[3] if len(sys.argv) > 3 else "JNI_OnLoad"
    duration = int(sys.argv[4]) if len(sys.argv) > 4 else 60

    # Load the agent
    agent_path = HERE / "tracer" / "agent_cmodule_v5.js"
    if not agent_path.exists():
        print(f"Agent not found: {agent_path}")
        return 1
    agent_code = agent_path.read_text()
    print(f"Loaded agent: {agent_path.name} ({len(agent_code)} bytes)")

    device = frida.get_usb_device(timeout=10)

    print(f"Spawning {pkg}...")
    pid = device.spawn([pkg])
    print(f"Spawned pid={pid}")

    session = device.attach(pid)
    script = session.create_script(agent_code)
    script.on('message', on_message)
    script.load()

    # Call init with SO targeting
    opts = {
        "soPattern": so,
        "exportName": export,
        "methodName": None,
        "fnOffset": None,
        "cmdValue": None,
        "cmdArg": None,
        "maxRecords": 5000000,
        "followAllThreads": False,
        "pkg": pkg,
        "includeSoPatterns": [],
        "deepTrace": False,
        "stalkerExcludePatterns": [],
        "boundaryDiffPatterns": [],
        "patchSuicide": False,
        "suicidePatchSpec": None,
        "hideRwxMaps": False,
        "jniHooks": [],
        "enableForkHook": False,
        "semanticEvents": False,
        "simdSidecar": False,
        "simdSampleStride": 1,
    }

    try:
        result = script.exports_sync.init(opts)
        print(f"Init result: {result}", flush=True)
    except Exception as e:
        print(f"Init error: {e}", flush=True)

    # Resume the app
    device.resume(pid)
    print(f"App resumed. Trace active for {duration}s...", flush=True)

    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass

    # Teardown
    print("Teardown...", flush=True)
    try:
        stats = script.exports_sync.stats()
        print(f"Stats: {stats}", flush=True)
    except: pass
    try:
        script.exports_sync.force_flush()
    except: pass
    try:
        script.unload()
    except: pass
    try:
        session.detach()
    except: pass
    print("Done.", flush=True)

if __name__ == '__main__':
    main()
