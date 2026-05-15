// native_sign_hooks_v4.js — 用 send() 发送 hook 事件
var LOG_LIMIT = 5;
var counters = {};

function logOnce(key, msgFn) {
    var c = counters[key] || 0;
    if (c < LOG_LIMIT) {
        send(msgFn(c));
        counters[key] = c + 1;
    }
}

function hex(ptr, len) {
    try {
        var bytes = ptr.readByteArray(Math.min(len || 64, 256));
        var hexStr = "";
        var arr = new Uint8Array(bytes);
        for (var i = 0; i < Math.min(arr.length, 64); i++)
            hexStr += ("0" + arr[i].toString(16)).slice(-2);
        if (arr.length > 64) hexStr += "...";
        return hexStr;
    } catch(e) { return "<read err>"; }
}

var lynxsecurity = null;
var lynxbase = null;

function hookSecurityExports(mod) {
    mod.enumerateExports().forEach(function(e) {
        if (e.type !== 'function') return;
        if (/sign|verify|update|rsa|encrypt|decrypt|native/i.test(e.name)) {
            send('HOOK ' + mod.name + '!' + e.name + ' @ ' + e.address);
            try {
                Interceptor.attach(e.address, {
                    onEnter: function(args) {
                        var label = mod.name + '!' + e.name;
                        logOnce(label + '.ENTER', function(c) {
                            return '[' + label + ' #' + c + '] arg0=' + hex(args[0], 64) + ' arg1=' + hex(args[1], 32);
                        });
                    },
                    onLeave: function(retval) {
                        var label = mod.name + '!' + e.name;
                        logOnce(label + '.LEAVE', function(c) {
                            return '[' + label + ' #' + c + '] ret=' + (retval.isNull() ? 'null' : '0x' + retval.toString(16));
                        });
                    }
                });
            } catch(e2) { send('FAIL ' + mod.name + '!' + e.name + ': ' + e2); }
        }
    });
}

function hookBaseExports(mod) {
    mod.enumerateExports().forEach(function(e) {
        if (e.type !== 'function') return;
        if (/md5|sha|hash/i.test(e.name)) {
            send('HOOK ' + mod.name + '!' + e.name + ' @ ' + e.address);
            try {
                Interceptor.attach(e.address, {
                    onEnter: function(args) {
                        var label = mod.name + '!' + e.name;
                        logOnce(label + '.ENTER', function(c) {
                            return '[' + label + ' #' + c + '] arg0=' + hex(args[0], 64) + ' len=' + (args[1] ? args[1] : '?');
                        });
                    },
                    onLeave: function(retval) {
                        var label = mod.name + '!' + e.name;
                        logOnce(label + '.LEAVE', function(c) {
                            return '[' + label + ' #' + c + '] ret=' + hex(retval, 16);
                        });
                    }
                });
            } catch(e2) { send('FAIL ' + mod.name + '!' + e.name + ': ' + e2); }
        }
    });
}

Process.enumerateModules().forEach(function(m) {
    if (m.name === 'liblynxsecurity.so') {
        lynxsecurity = m;
        send('FOUND liblynxsecurity.so @ ' + m.base);
        hookSecurityExports(m);
    }
    if (m.name === 'liblynxbase.so') {
        lynxbase = m;
        send('FOUND liblynxbase.so @ ' + m.base);
        hookBaseExports(m);
    }
});

setInterval(function() {
    Process.enumerateModules().forEach(function(m) {
        if (m.name === 'liblynxsecurity.so' && !lynxsecurity) {
            lynxsecurity = m;
            send('NEW liblynxsecurity.so @ ' + m.base);
            hookSecurityExports(m);
        }
        if (m.name === 'liblynxbase.so' && !lynxbase) {
            lynxbase = m;
            send('NEW liblynxbase.so @ ' + m.base);
            hookBaseExports(m);
        }
    });
}, 3000);

send('READY');
