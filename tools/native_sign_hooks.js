// native_sign_hooks.js — Hook native crypto 函数定位签名算法
// 用法: frida -U -n com.ss.android.ugc.aweme -l native_sign_hooks.js

var LOG_LIMIT = 5; // 每种函数最多打印几次
var counters = {};
var sos = {};

function logOnce(key, msgFn) {
    var c = counters[key] || 0;
    if (c < LOG_LIMIT) {
        console.log(msgFn(c));
        counters[key] = c + 1;
    }
}

// Hex dump helper (truncated)
function hex(ptr, len) {
    try {
        var bytes = ptr.readByteArray(Math.min(len || 64, 256));
        var hexStr = "";
        var arr = new Uint8Array(bytes);
        for (var i = 0; i < Math.min(arr.length, 64); i++) {
            hexStr += ("0" + arr[i].toString(16)).slice(-2);
        }
        if (arr.length > 64) hexStr += "...";
        return hexStr;
    } catch(e) { return "<read err>"; }
}

function str(ptr, maxLen) {
    try { return ptr.readCString(maxLen || 256) || ""; } 
    catch(e) { return "<read err>"; }
}

// ====== Scan and hook signing-related SOs ======
var signPatterns = [/cms/i, /nms/i, /sgmain/i, /sgsecurity/i, /turing/i, 
                     /security/i, /sign/i, /guard/i, /lynx/i, /protect/i];

Process.enumerateModules().forEach(function(m) {
    for (var i = 0; i < signPatterns.length; i++) {
        if (signPatterns[i].test(m.name)) {
            sos[m.name] = m;
            console.log("[SO] " + m.name + " @ " + m.base + " size=" + m.size);
            break;
        }
    }
});

// ====== Hook common crypto exports across ALL modules ======
var cryptoExports = ["MD5_Init", "MD5_Update", "MD5_Final", "MD5",
                      "SHA1_Init", "SHA256_Init", 
                      "HMAC", "hmac_sha1", "hmac_sha256",
                      "AES_encrypt", "AES_decrypt",
                      "AES_set_encrypt_key", "AES_set_decrypt_key",
                      "EVP_EncryptInit", "EVP_DigestInit",
                      "base64_encode", "base64_decode",
                      "gzcompress", "gzuncompress"];

var exportedFuncs = {};
Process.enumerateModules().forEach(function(m) {
    var exports = m.enumerateExports();
    exports.forEach(function(e) {
        if (e.type === "function") {
            var name = e.name.toLowerCase();
            for (var i = 0; i < cryptoExports.length; i++) {
                if (name.indexOf(cryptoExports[i].toLowerCase()) !== -1) {
                    if (!exportedFuncs[e.address]) {
                        exportedFuncs[e.address] = { name: e.name, mod: m.name };
                    }
                    break;
                }
            }
        }
    });
});

var hooked = 0;
Object.keys(exportedFuncs).forEach(function(addrStr) {
    var info = exportedFuncs[addrStr];
    try {
        var ptr = ptr(addrStr);
        Interceptor.attach(ptr, {
            onEnter: function(args) {
                var key = info.mod + "!" + info.name + " ENTER";
                logOnce(key, function(c) {
                    var line = "[" + key + " #" + c + "]";
                    if (info.name.indexOf("MD5") !== -1 || info.name.indexOf("SHA") !== -1) {
                        line += " data=" + hex(args[0], 64);
                    } else if (info.name.indexOf("AES") !== -1) {
                        line += " key/ctx=" + hex(args[0], 32);
                    } else if (info.name.indexOf("HMAC") !== -1) {
                        line += " key=" + hex(args[0], 32);
                    }
                    return line;
                });
            },
            onLeave: function(retval) {
                var key = info.mod + "!" + info.name + " LEAVE";
                logOnce(key, function(c) {
                    return "[" + key + " #" + c + "] ret=0x" + retval.toString(16);
                });
            }
        });
        hooked++;
    } catch(e) {}
});
console.log("[+] Hooked " + hooked + " crypto functions");

// ====== Hook strstr/strcmp to catch signing key strings ======
var signKeywords = ["sign", "argus", "gorgon", "khronos", "ladon", "medusa",
                     "hmac", "md5", "x-", "encrypt", "decrypt", "cookie",
                     "token", "session", "device_id"];

// ====== Periodic: check for newly loaded SOs ======
setInterval(function() {
    var now = Process.enumerateModules();
    now.forEach(function(m) {
        for (var i = 0; i < signPatterns.length; i++) {
            if (signPatterns[i].test(m.name) && !sos[m.name]) {
                sos[m.name] = m;
                console.log("[SO-NEW] " + m.name + " @ " + m.base + " size=" + m.size);
                // Log interesting exports
                var exports = m.enumerateExports();
                var interesting = exports.filter(function(e) {
                    return e.type === "function" && 
                           /sign|encrypt|decrypt|hash|md5|sha|hmac|aes|rsa|base64|url|calc|compute|gen/i.test(e.name);
                });
                interesting.slice(0, 10).forEach(function(e) {
                    console.log("  export: " + e.name + " @ " + e.address);
                });
            }
        }
    });
}, 5000);

console.log("[*] Native sign monitor running. Interact with the app...");
