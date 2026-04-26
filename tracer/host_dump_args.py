#!/usr/bin/env python3
"""轻量参数/返回值抓取器 — 不做 trace, 只看 70102 的输入和输出."""
import frida, signal, time, json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).parent
AGENT = (ROOT / "agent_dump_args.js").read_text()


def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    cmd = int(sys.argv[2]) if len(sys.argv) > 2 else 70102
    out_file = sys.argv[3] if len(sys.argv) > 3 else f"/tmp/dump_{cmd}.json"

    mgr = frida.get_device_manager()
    device = mgr.add_remote_device("127.0.0.1:6699")
    pid = None
    for p in device.enumerate_processes():
        if p.name == "com.taobao.taobao": pid = p.pid; break
    if pid is None:
        r = subprocess.run(["adb","shell","pidof","com.taobao.taobao"], capture_output=True, text=True)
        if r.stdout.strip(): pid = int(r.stdout.strip().split()[0])
    if pid is None:
        print("[!] TB not running"); return 1

    print(f"[*] attach {pid}")
    sess = device.attach(pid)
    scr = sess.create_script(AGENT)
    calls = []
    def on_msg(m, data):
        if m["type"] == "send":
            p = m["payload"]
            t = p.get("type") if isinstance(p, dict) else None
            if t == "log":
                print(f"[ag] {p['msg']}")
            elif t == "args":
                print(f"\n=== call #{p['call_idx']} 入参 (tid={p['tid']}) ===")
                d = p["data"]
                print(f"  cmd: {d['cmd']}  this: {d['this']}")
                print(f"  args[{d.get('args_count','?')}]:")
                for i, a in enumerate(d.get("args", [])):
                    print(f"    [{i}] {json.dumps(a, ensure_ascii=False)}")
                calls.append(("args", p))
            elif t == "ret":
                print(f"\n=== call #{p['call_idx']} 返回 (tid={p['tid']}, {p['ms']}ms) ===")
                print(f"  retval: {p['retval']}")
                print(f"  data: {json.dumps(p['data'], ensure_ascii=False, indent=2)}")
                calls.append(("ret", p))
            elif t == "module":
                print(f"[ag] 模块 {p['name']} @ {p['base']}")
            elif t == "hello":
                print(f"[ag] frida={p['frida']}")
            else:
                print(f"[ag] {p}")
        elif m["type"] == "error":
            print(f"[err] {m.get('description')}")
    scr.on("message", on_msg)
    scr.load()
    scr.exports_sync.init({"cmdValue": cmd})
    print(f"[*] 等待 {duration}s 期间触发 cmd={cmd}; 在手机上操作 TB")
    stop = [False]
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__(0, True))
    t0 = time.time()
    while not stop[0] and time.time() - t0 < duration:
        time.sleep(0.5)
    print(f"\n[host] stats: {scr.exports_sync.stats()}")
    json.dump(calls, open(out_file, "w"), indent=2, ensure_ascii=False, default=str)
    print(f"[host] 已保存 {len(calls)} 条事件到 {out_file}")
    try: scr.unload()
    except: pass
    try: sess.detach()
    except: pass

if __name__ == "__main__":
    main()
