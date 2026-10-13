/* 同版 GumJS + QEMU 运行真实 agent。测试主程序不构造或修补 trace 记录。 */
#include "frida-gumjs.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Linux fixture 提供 Android libc 的 errno 入口，writer 代码保持原样。 */
int *__errno(void) { return &errno; }
ssize_t pwrite64(int fd, const void *data, size_t size, off_t offset) { return pwrite(fd, data, size, offset); }
/* Devkit 同时包含 V8。只链接被测 QJS，误用另一个 backend 时立即失败。 */
unsigned long gum_v8_script_backend_get_type(void) { abort(); }

/* 明确设置 IP/SIMD 哨兵，验证入口桥没有悄悄改写调用者寄存器。 */
extern uint64_t invoke_target(void *target, uint64_t value);
__asm__(".text\n.global invoke_target\n.type invoke_target,%function\ninvoke_target:\n"
    "stp x19,x30,[sp,#-16]!\nmov x19,x0\nmov x0,x1\n"
    "mov x16,#0x1616\nmov x17,#0x1717\nmovi v0.16b,#0x5a\n"
    "blr x19\nldp x19,x30,[sp],#16\nret\n.size invoke_target,.-invoke_target\n");

static int script_failed;
static void on_message(const gchar *message, GBytes *data, gpointer user_data) {
    (void)data; (void)user_data;
    puts(message); fflush(stdout);
    JsonParser *parser = json_parser_new();
    if (json_parser_load_from_data(parser, message, -1, NULL)) {
        JsonObject *root = json_node_get_object(json_parser_get_root(parser));
        if (strcmp(json_object_get_string_member(root, "type"), "error") == 0) script_failed = 1;
    }
    g_object_unref(parser);
}

static void drain_messages(void) {
    GMainContext *context = g_main_context_get_thread_default();
    while (g_main_context_pending(context)) g_main_context_iteration(context, FALSE);
}

int main(int argc, char **argv) {
    if (argc != 6) return 2;
    setenv("TRACEMIKU_CASE", argv[2], 1); setenv("TRACEMIKU_OUT", argv[3], 1);
    void *library = dlopen(getenv("TRACEMIKU_LIBRARY"), RTLD_NOW | RTLD_GLOBAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    uint64_t (*target)(uint64_t) = dlsym(library, argv[2]);
    if (!target) return 2;
    uint32_t original = *(uint32_t *)target;
    gum_init_embedded();
    GumScriptBackend *backend = gum_script_backend_obtain_qjs();
    GError *error = NULL;
    gchar *source = NULL;
    if (!g_file_get_contents(argv[1], &source, NULL, &error)) {
        fprintf(stderr, "%s\n", error->message); return 2;
    }
    GumScript *script = gum_script_backend_create_sync(backend, "fixture", source, NULL, NULL, &error);
    if (error) { fprintf(stderr, "%s\n", error->message); return 2; }
    gum_script_set_message_handler(script, on_message, NULL, NULL);
    gum_script_load_sync(script, NULL);
    drain_messages();
    int count = getenv("TRACEMIKU_CALLS") ? atoi(getenv("TRACEMIKU_CALLS")) : 1;
    uint64_t result = 0;
    int result_ok = 1;
    for (int i = 0; i < count; i++) {
        result = invoke_target(target, strtoull(argv[4], NULL, 10));
        printf("FIXTURE_RESULT=%llu\n", (unsigned long long)result);
        result_ok &= strcmp(argv[5], "nonzero") == 0 ? result != 0 : result == strtoull(argv[5], NULL, 10);
        drain_messages();
    }
    /* 下一 JS tick 必须撤销入口，避免 eternalized 运行时清理依赖 host。 */
    for (int i = 0; i < 100 && *(volatile uint32_t *)target != original; i++) {
        usleep(10000); drain_messages();
    }
    drain_messages();
    int restored = *(uint32_t *)target == original;
    printf("FIXTURE_RESTORED=%d\n", restored);
    gum_script_unload_sync(script, NULL); g_object_unref(script); g_free(source);
    gum_deinit_embedded();
    if (!restored || !result_ok) return 1;
    return script_failed ? 2 : 0;
}
