#include "common/constant.h"
#include <stdlib.h>
#include <string.h>

char g_sys_trace_root_dir[512] = {0};

void init_sys_trace_root_dir() {
    const char *env_path = getenv("SYSTRACE_DUMP_PATH");
    if (env_path && env_path[0] != '\0') {
        strncpy(g_sys_trace_root_dir, env_path,
                sizeof(g_sys_trace_root_dir) - 1);
        size_t len = strlen(g_sys_trace_root_dir);
        if (len > 0 && g_sys_trace_root_dir[len - 1] != '/') {
            if (len < sizeof(g_sys_trace_root_dir) - 1) {
                g_sys_trace_root_dir[len] = '/';
                g_sys_trace_root_dir[len + 1] = '\0';
            }
        }
    } else {
        strncpy(g_sys_trace_root_dir, SYS_TRACE_ROOT_DIR,
                sizeof(g_sys_trace_root_dir) - 1);
    }
}

const char *get_sys_trace_root_dir() {
    if (g_sys_trace_root_dir[0] == '\0') {
        init_sys_trace_root_dir();
    }
    return g_sys_trace_root_dir;
}
