#include "common_hook.h"
#include "../../include/common/shared_constants.h"
#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>

uint64_t get_current_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

const char *get_so_name(uint64_t ip)
{
    Dl_info info;
    const char *so_name;
    if (dladdr((void *)ip, &info))
    {
        so_name = strrchr(info.dli_fname, '/');
        return (so_name != NULL) ? so_name + 1 : info.dli_fname;
    }
    return "unknown";
}

unw_word_t get_so_base(unw_word_t addr)
{
    Dl_info info;
    if (dladdr((void *)addr, &info) != 0)
    {
        return (unw_word_t)info.dli_fbase;
    }
    return 0;
}

void get_log_filename(char *buf, size_t buf_size, const char *path_suffix) {
    const char *rank_str = getenv("RANK") ? getenv("RANK") : getenv("RANK_ID");
    int rank = rank_str ? atoi(rank_str) : 0;

    char path[PATH_LEN] = {0};
    int ret = snprintf(path, sizeof(path), "%s/%s", SYS_TRACE_ROOT_DIR, path_suffix);
    if (ret < 0 || (size_t)ret >= sizeof(path)) {
        snprintf(buf, buf_size, "%s_trace_rank%d.pb", path_suffix, rank);
        return;
    }
    if (access(path, F_OK) != 0) {
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            perror("Failed to create directory");
            snprintf(buf, buf_size, "%s_trace_rank%d.pb", path_suffix, rank);
            return;
        }
    }
    snprintf(buf, buf_size, "%s/%s_trace_rank%d.pb", path, path_suffix, rank);
}

void *load_symbol(void *lib, const char *symbol_name)
{
    void *sym = dlsym(lib, symbol_name);
    if (!sym)
    {
        fprintf(stderr, "Failed to find symbol %s: %s\n", symbol_name,
                dlerror());
    }
    return sym;
}