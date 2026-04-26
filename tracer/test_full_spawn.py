#!/usr/bin/env python3
"""More careful spawn-gating + full agent test:
  - Kill TB via adb until pidof returns empty (TB has auto-restart watchdog)
  - Then enable gating + am start
  - Catch MAIN spawn (not :channel)
  - Inject incremental agents from minimal -> full to find what triggers anti-debug
"""
import sys, time, frida, subprocess, pathlib

PKG = "com.taobao.taobao"
ACT = "com.taobao.taobao/com.taobao.tao.welcome.Welcome"

def adb(cmd, t=8):
    r = subprocess.run(["adb","shell"]+cmd.split() if isinstance(cmd,str) else ["adb","shell"]+cmd,
                       capture_output=True, text=True, timeout=t)
    return r.stdout.strip()

def adb_raw(cmd, t=8):
    r = subprocess.run(["adb","shell",cmd], capture_output=True, text=True, timeout=t)
    return r.stdout.strip()

def hard_kill_tb():
    print("[*] hard-killing TB ...")
    for i in range(8):
        adb_raw("am force-stop com.taobao.taobao")
        adb_raw("killall com.taobao.taobao 2>/dev/null; killall com.taobao.taobao:channel 2>/dev/null")
        time.sleep(0.5)
        p = adb_raw("pidof com.taobao.taobao; pidof com.taobao.taobao:channel")
        if not p:
            print(f"  [+] TB dead after {i+1} attempts")
            return True
        print(f"  [.] still alive: {p!r}")
    print("  [!] TB won't die")
    return False

AGENTS = {
    "noop": "send({type:'log',msg:'noop pid='+Process.id});\nrpc.exports = {init(){return 'ok'}}",
    "modules": """
        send({type:'log',msg:'modules pid='+Process.id});
        rpc.exports = {init(){
            const m = Process.enumerateModules();
            send({type:'log',msg:'modules: '+m.length});
            return 'ok';
        }}
    """,
    "hook_dlopen": """
        send({type:'log',msg:'hook_dlopen pid='+Process.id});
        rpc.exports = {init(){
            for (const sym of ['android_dlopen_ext', '__loader_android_dlopen_ext']) {
                const p = Module.findGlobalExportByName ? Module.findGlobalExportByName(sym) : Module.getGlobalExportByName(sym);
                if (!p) continue;
                Interceptor.attach(p, {
                    onEnter(args){
                        try{ this._path = args[0].readUtf8String(); } catch(_){this._path='?';}
                    },
                    onLeave(retv){
                        if (this._path && this._path.indexOf('libsgmainso') !== -1) {
                            send({type:'log',msg:'dlopen '+this._path+' = '+retv});
                        }
                    }
                });
                send({type:'log',msg:'hooked '+sym});
            }
            return 'ok';
        }}
    """,
    "stalker_arm": """
        send({type:'log',msg:'stalker_arm pid='+Process.id});
        rpc.exports = {init(){
            for (const sym of ['android_dlopen_ext','__loader_android_dlopen_ext']) {
                const p = Module.findGlobalExportByName ? Module.findGlobalExportByName(sym) : Module.getGlobalExportByName(sym);
                if (!p) continue;
                Interceptor.attach(p, {
                    onEnter(args){ try{this._path=args[0].readUtf8String();}catch(_){this._path='?';} },
                    onLeave(retv){
                        if (this._path && this._path.indexOf('libsgmainso') !== -1) {
                            send({type:'log',msg:'dlopen '+this._path+' = '+retv});
                            // resolve JNI_OnLoad and hook for trace
                            setImmediate(() => {
                                const m = Process.findModuleByName('libsgmainso-6.8.260403.so');
                                if (!m) { send({type:'log',msg:'mod not found'}); return; }
                                send({type:'log',msg:'mod base='+m.base+' size='+m.size.toString(16)});
                                const exp = m.findExportByName('JNI_OnLoad');
                                if (!exp) { send({type:'log',msg:'JNI_OnLoad not found'}); return; }
                                send({type:'log',msg:'JNI_OnLoad='+exp});
                                Interceptor.attach(exp, {
                                    onEnter(){
                                        const tid = this.threadId;
                                        send({type:'log',msg:'JNI_OnLoad enter tid='+tid});
                                        // start Stalker
                                        try {
                                            Stalker.follow(tid, {
                                                events: { call:false, ret:false, exec:false, block:false, compile:false },
                                                transform(it){
                                                    let ins; while ((ins=it.next())!==null) it.keep();
                                                }
                                            });
                                            send({type:'log',msg:'Stalker.follow ok'});
                                            this._tid = tid;
                                        } catch (e) {
                                            send({type:'log',msg:'follow err: '+e});
                                        }
                                    },
                                    onLeave(rv){
                                        if (this._tid) { try{Stalker.unfollow(this._tid);}catch(_){}; try{Stalker.flush();}catch(_){};}
                                        send({type:'log',msg:'JNI_OnLoad ret='+rv});
                                    }
                                });
                            });
                        }
                    }
                });
            }
            return 'ok';
        }}
    """,
}

def run_case(device, name, src, secs=15):
    print(f"\n========== CASE {name} ==========")
    if not hard_kill_tb(): return
    sessions = []

    def on_spawn(s):
        if s.identifier == PKG:
            print(f"  caught MAIN {s.identifier} pid={s.pid}")
            try:
                sess = device.attach(s.pid)
                scr = sess.create_script(src)
                scr.on("message", lambda m,d: print(f"  msg: {m.get('payload') if m['type']=='send' else m}"))
                scr.load()
                ret = scr.exports_sync.init()
                print(f"  init ret = {ret}")
                sessions.append((sess, scr))
            except Exception as e:
                print(f"  ATTACH FAIL: {e}")
        elif s.identifier and s.identifier.startswith(PKG):
            print(f"  caught sub {s.identifier} pid={s.pid} (not attaching)")
        try: device.resume(s.pid)
        except: pass

    device.on("spawn-added", on_spawn)
    device.enable_spawn_gating()
    adb_raw(f"am start -n {ACT}")
    t0 = time.time()
    last_pid = None
    while time.time() - t0 < secs:
        time.sleep(0.5)
        p = adb_raw("pidof com.taobao.taobao")
        cur = p if p else "DEAD"
        if cur != last_pid:
            print(f"  [poll t={time.time()-t0:.1f}s] tb pid: {cur}")
            last_pid = cur
            if cur == "DEAD" and time.time() - t0 > 1.5:
                print(f"  *** TB DIED at t={time.time()-t0:.1f}s ***")
                break
    device.disable_spawn_gating()
    try: device.off("spawn-added", on_spawn)
    except: pass
    for s,sc in sessions:
        try: sc.unload()
        except: pass
        try: s.detach()
        except: pass

def main():
    cases = sys.argv[1:] if len(sys.argv) > 1 else list(AGENTS.keys())
    mgr = frida.get_device_manager()
    device = mgr.add_remote_device("127.0.0.1:6699")
    for c in cases:
        if c not in AGENTS:
            print(f"unknown case {c}; available: {list(AGENTS)}"); continue
        run_case(device, c, AGENTS[c])

if __name__ == "__main__":
    main()
