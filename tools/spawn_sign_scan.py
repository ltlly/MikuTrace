#!/usr/bin/env python3
"""spawn_sign_scan.py — Spawn 模式扫描签名 SO 及其导出函数"""
import frida
import sys
import time

JS_CODE = r"""
var allSoS = {};
var signPats = [/cms/i, /nms/i, /sgmain/i, /sgsecurity/i, /turing/i,
                 /security/i, /sign/i, /guard/i, /lynx/i, /protect/i, /hodor/i,
                 /kwsgmain/i, /aegon/i, /godzilla/i, /ssl/i, /medusa/i, /argus/i,
                 /gorgon/i, /khronos/i, /ladon/i, /tyhon/i, /windvane/i];

function scanSOs() {
    var modules = Process.enumerateModules();
    modules.forEach(function(m) {
        if (allSoS[m.name]) return;
        allSoS[m.name] = true;
        for (var i = 0; i < signPats.length; i++) {
            if (signPats[i].test(m.name)) {
                send("[SO] " + m.name + " @ " + m.base + " size=" + m.size);
                try {
                    var exports = m.enumerateExports().filter(function(e) {
                        return e.type === "function" &&
                               /sign|encrypt|decrypt|hash|md5|sha|hmac|aes|rsa|base64|calc|compute|gen|JNI/i.test(e.name);
                    });
                    exports.slice(0, 20).forEach(function(e) {
                        send("  EXPORT: " + e.name + " @ " + e.address);
                    });
                    if (exports.length > 20)
                        send("  ... +" + (exports.length - 20) + " more exports");
                } catch(e) {}
                break;
            }
        }
    });
}

// Scan every 2 seconds
setInterval(scanSOs, 2000);
scanSOs();
send("[*] Spawn scanner active — watching SO loads...");
"""

def on_message(msg, data):
    if msg['type'] == 'send':
        print(msg['payload'], flush=True)
    elif msg['type'] == 'error':
        print(f"[ERROR] {msg.get('description', msg)}", flush=True)

def main():
    pkg = sys.argv[1] if len(sys.argv) > 1 else "com.ss.android.ugc.aweme"
    
    device = frida.get_usb_device(timeout=10)
    
    print(f"Spawning {pkg}...")
    pid = device.spawn([pkg])
    print(f"Spawned pid={pid}")
    
    session = device.attach(pid)
    script = session.create_script(JS_CODE)
    script.on('message', on_message)
    script.load()
    
    device.resume(pid)
    print(f"App resumed. Monitoring for {sys.argv[2] if len(sys.argv) > 2 else 60}s...", flush=True)
    
    try:
        duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()
        print("\nDone.", flush=True)

if __name__ == '__main__':
    main()
