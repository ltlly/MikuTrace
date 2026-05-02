// Minimal forking testbed for P1-C M1.
// Forks 3 children (one via fork(), one via vfork(), one via clone() syscall),
// each child sleeps 200ms and exits 0; parent waits, sleeps 5s total.
//
// Cross-compile (Android NDK r29, API 24):
//   aarch64-linux-android24-clang -static -o fork_test fork_test.c
// Push:  adb push fork_test /data/local/tmp/
//        adb shell chmod +x /data/local/tmp/fork_test
// Run:   adb shell /data/local/tmp/fork_test
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <signal.h>

static int g_clone_sleep_ms = 150;
static int clone_child(void *_arg) {
    usleep(g_clone_sleep_ms * 1000);
    return 0;
}

int main(int argc, char **argv) {
    int long_lived = (argc >= 2 && argv[1][0] == 'l');  // 'long' arg → children sleep 5s
    int sleep_ms = long_lived ? 5000 : 150;
    g_clone_sleep_ms = sleep_ms;
    fprintf(stderr, "[parent] pid=%d, sleeping 3s for frida attach (%s mode)\n",
            getpid(), long_lived ? "long-lived" : "short-lived");
    fflush(stderr);
    sleep(3);
    fprintf(stderr, "[parent] forking 3 children (each sleeps %dms)\n", sleep_ms);
    fflush(stderr);

    // 1. fork()
    pid_t c1 = fork();
    if (c1 == 0) {
        fprintf(stderr, "[child1 fork] pid=%d\n", getpid()); fflush(stderr);
        usleep(sleep_ms * 1000);
        _exit(0);
    }
    fprintf(stderr, "[parent] fork() → %d\n", c1); fflush(stderr);

    // 2. vfork()
    pid_t c2 = vfork();
    if (c2 == 0) {
        // vfork shares the parent's memory until exec/exit; minimize work
        _exit(0);
    }
    fprintf(stderr, "[parent] vfork() → %d\n", c2); fflush(stderr);

    // 3. clone() — bionic exposes via __bionic_clone or direct syscall.
    //    Use clone() libc wrapper if available.
    void *stack = malloc(64 * 1024);
    if (stack) {
        pid_t c3 = clone(clone_child, (char *)stack + 64*1024,
                         SIGCHLD, NULL);
        if (c3 < 0) {
            // clone returned in child path? Safe-guard
        } else {
            fprintf(stderr, "[parent] clone() → %d\n", c3); fflush(stderr);
        }
    }

    // wait for all
    int status;
    while (wait(&status) > 0) {}
    fprintf(stderr, "[parent] all children reaped, sleeping 1s\n"); fflush(stderr);
    sleep(1);
    return 0;
}
