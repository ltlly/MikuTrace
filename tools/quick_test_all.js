// quick_test_all.js — hook liblynxsecurity.so 的所有导出函数（看是否被调用）
var target = 'liblynxsecurity.so';
var mod = null;
var totalHooked = 0;
var totalFired = 0;

Process.enumerateModules().forEach(function(m) {
    if (m.name === target) { mod = m; }
});

if (mod) {
    mod.enumerateExports().forEach(function(e) {
        if (e.type !== 'function') return;
        totalHooked++;
        try {
            Interceptor.attach(e.address, function() {
                totalFired++;
                if (totalFired <= 3) send('FIRED: ' + e.name + ' (total=' + totalFired + ')');
            });
        } catch(ex) {}
    });
    send('HOOKED ' + totalHooked + ' functions in ' + target);
} else {
    send(target + ' NOT FOUND YET');
}

// Periodic check
setInterval(function() {
    if (!mod) {
        Process.enumerateModules().forEach(function(m) {
            if (m.name === target && !mod) {
                mod = m;
                mod.enumerateExports().forEach(function(e) {
                    if (e.type !== 'function') return;
                    totalHooked++;
                    try {
                        Interceptor.attach(e.address, function() {
                            totalFired++;
                            if (totalFired <= 5) send('FIRED: ' + e.name + ' (total=' + totalFired + ')');
                        });
                    } catch(ex) {}
                });
                send('LATE_HOOKED ' + totalHooked + ' functions');
            }
        });
    }
}, 3000);
