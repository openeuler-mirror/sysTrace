#define _GNU_SOURCE
#include "../../include/common/constant.h"
#include "common_hook.h"
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef USE_JSON
typedef struct {
    uint64_t address;
    char *so_name;
} JSONStackFrame;

typedef struct {
    uint64_t alloc_ptr;
    size_t mem_size;
    int stage_id;
    int stage_type;
    JSONStackFrame **stack_frames;
    size_t n_stack_frames;
} JSONAllocEntry;

typedef struct {
    uint64_t alloc_ptr;
    int stage_id;
    int stage_type;
} JSONFreeEntry;

typedef struct {
    uint32_t pid;
    JSONAllocEntry **mem_alloc_stacks;
    size_t n_mem_alloc_stacks;
    JSONFreeEntry **mem_free_stacks;
    size_t n_mem_free_stacks;
} JSONProcMem;

#define TRACE_STRUCT JSONProcMem
#define ALLOC_STRUCT JSONAllocEntry
#define FREE_STRUCT JSONFreeEntry
#define FRAME_STRUCT JSONStackFrame
#else
#include "../../protos/systrace.pb-c.h"
#include <google/protobuf-c/protobuf-c.h>

#define TRACE_STRUCT ProcMem
#define ALLOC_STRUCT MemAllocEntry
#define FREE_STRUCT MemFreeEntry
#define FRAME_STRUCT StackFrame
#endif

typedef int drvError_t;
typedef enum aclrtMemMallocPolicy {
    ACL_MEM_MALLOC_HUGE_FIRST,
    ACL_MEM_MALLOC_HUGE_ONLY,
    ACL_MEM_MALLOC_NORMAL_ONLY,
    ACL_MEM_MALLOC_HUGE_FIRST_P2P,
    ACL_MEM_MALLOC_HUGE_ONLY_P2P,
    ACL_MEM_MALLOC_NORMAL_ONLY_P2P,
    ACL_MEM_TYPE_LOW_BAND_WIDTH = 0x0100,
    ACL_MEM_TYPE_HIGH_BAND_WIDTH = 0x1000,
} aclrtMemMallocPolicy;

typedef drvError_t (*halMemAllocFunc_t)(void **pp, unsigned long long size,
                                        unsigned long long flag);
typedef drvError_t (*halMemFreeFunc_t)(void *pp);
typedef drvError_t (*halMemCreateFunc_t)(void **handle, size_t size, void *prop,
                                         uint64_t flag);
typedef drvError_t (*halMemReleaseFunc_t)(void *handle);
typedef drvError_t (*aclrtMallocFunc_t)(void **devPtr, size_t size,
                                        aclrtMemMallocPolicy policy);
typedef drvError_t (*aclrtMallocCachedFunc_t)(void **devPtr, size_t size,
                                              aclrtMemMallocPolicy policy);
typedef drvError_t (*aclrtMallocAlign32Func_t)(void **devPtr, size_t size,
                                               aclrtMemMallocPolicy policy);
typedef drvError_t (*aclrtFreeFunc_t)(void *devPtr);

static halMemAllocFunc_t orig_halMemAlloc = NULL;
static halMemFreeFunc_t orig_halMemFree = NULL;
static halMemCreateFunc_t orig_halMemCreate = NULL;
static halMemReleaseFunc_t orig_halMemRelease = NULL;
static aclrtMallocFunc_t orig_aclrtMalloc = NULL;
static aclrtMallocCachedFunc_t orig_aclrtMallocCached = NULL;
static aclrtMallocAlign32Func_t orig_aclrtMallocAlign32 = NULL;
static aclrtFreeFunc_t orig_aclrtFree = NULL;

static pthread_key_t thread_data_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
extern int global_stage_id;
extern int global_stage_type;
static bool g_hbm_trace_enabled = false;

typedef struct {
    TRACE_STRUCT *proc_mem;
    time_t last_log_time;
} ThreadData;

void hbm_trace_set_enabled(bool enabled) { g_hbm_trace_enabled = enabled; }

static void free_proc_mem(TRACE_STRUCT *proc_mem) {
    if (!proc_mem)
        return;

    for (size_t i = 0; i < proc_mem->n_mem_alloc_stacks; i++) {
        ALLOC_STRUCT *entry = proc_mem->mem_alloc_stacks[i];
        for (size_t j = 0; j < entry->n_stack_frames; j++) {
            free((void *)entry->stack_frames[j]->so_name);
            free(entry->stack_frames[j]);
        }
        free(entry->stack_frames);
        free(entry);
    }
    for (size_t i = 0; i < proc_mem->n_mem_free_stacks; i++) {
        free(proc_mem->mem_free_stacks[i]);
    }

    free(proc_mem->mem_alloc_stacks);
    free(proc_mem->mem_free_stacks);
    proc_mem->n_mem_alloc_stacks = 0;
    proc_mem->mem_alloc_stacks = NULL;
    proc_mem->n_mem_free_stacks = 0;
    proc_mem->mem_free_stacks = NULL;
}

static void free_thread_data(void *data) {
    ThreadData *td = (ThreadData *)data;
    if (td && td->proc_mem) {
        free_proc_mem(td->proc_mem);
        free(td->proc_mem);
    }
    free(td);
}

static void make_key() {
    pthread_key_create(&thread_data_key, free_thread_data);
}

static ThreadData *get_thread_data() {
    ThreadData *td;
    pthread_once(&key_once, make_key);
    td = pthread_getspecific(thread_data_key);
    if (!td) {
        td = calloc(1, sizeof(ThreadData));
        td->proc_mem = calloc(1, sizeof(TRACE_STRUCT));
#ifndef USE_JSON
        proc_mem__init(td->proc_mem);
#endif
        const char *rank_str =
            getenv("RANK") ? getenv("RANK") : getenv("RANK_ID");
        td->proc_mem->pid = rank_str ? atoi(rank_str) : 0;
        td->last_log_time = time(NULL);
        pthread_setspecific(thread_data_key, td);
    }
    return td;
}

static char is_ready_to_write(ThreadData *td, time_t *current) {
    TRACE_STRUCT *proc_mem = td->proc_mem;
    if (!proc_mem ||
        (proc_mem->n_mem_alloc_stacks + proc_mem->n_mem_free_stacks == 0))
        return 0;
    *current = time(NULL);
    if (proc_mem->n_mem_alloc_stacks + proc_mem->n_mem_free_stacks <
        LOG_ITEMS_MIN) {
        if (*current - td->last_log_time < LOG_INTERVAL_SEC)
            return 0;
    }
    return 1;
}

static void write_trace_to_file() {
    if (!g_hbm_trace_enabled)
        return;
    time_t current;
    ThreadData *td = get_thread_data();
    if (!td || !is_ready_to_write(td, &current))
        return;

    if (pthread_mutex_trylock(&file_mutex) == 0) {
        char filename[256];
#ifdef USE_JSON
        get_log_filename(filename, sizeof(filename), "hbm", JSON);
        FILE *fp = fopen(filename, "ab");
        if (fp) {
            fprintf(fp, "{\"pid\":%u,\"alloc\":[", td->proc_mem->pid);
            for (size_t i = 0; i < td->proc_mem->n_mem_alloc_stacks; i++) {
                ALLOC_STRUCT *e = td->proc_mem->mem_alloc_stacks[i];
                fprintf(fp,
                        "%s{\"ptr\":\"0x%" PRIx64
                        "\",\"sz\":%zu,\"sid\":%d,\"st\":%d,\"stack\":[",
                        (i == 0 ? "" : ","), e->alloc_ptr, e->mem_size,
                        e->stage_id, e->stage_type);
                for (size_t j = 0; j < e->n_stack_frames; j++) {
                    fprintf(fp, "%s{\"so\":\"%s\",\"off\":\"0x%" PRIx64 "\"}",
                            (j == 0 ? "" : ","), e->stack_frames[j]->so_name,
                            e->stack_frames[j]->address);
                }
                fprintf(fp, "]}");
            }
            fprintf(fp, "],\"free\":[");
            for (size_t i = 0; i < td->proc_mem->n_mem_free_stacks; i++) {
                FREE_STRUCT *e = td->proc_mem->mem_free_stacks[i];
                fprintf(fp, "%s{\"ptr\":\"0x%" PRIx64 "\",\"sid\":%d}",
                        (i == 0 ? "" : ","), e->alloc_ptr, e->stage_id);
            }
            fprintf(fp, "]}\n");
            fclose(fp);
        }
#else
        get_log_filename(filename, sizeof(filename), "hbm", PB);
        size_t len = proc_mem__get_packed_size(td->proc_mem);
        uint8_t *buf = malloc(len);
        if (buf) {
            proc_mem__pack(td->proc_mem, buf);
            FILE *fp = fopen(filename, "ab");
            if (fp) {
                fwrite(buf, len, 1, fp);
                fclose(fp);
            }
            free(buf);
        }
#endif
        pthread_mutex_unlock(&file_mutex);
    }

    free_proc_mem(td->proc_mem);
    td->last_log_time = current;
}

static void exit_handler(void) { write_trace_to_file(); }

static void collect_stack_frames(ALLOC_STRUCT *entry) {
    unw_cursor_t cursor;
    unw_context_t context;
    unw_word_t ip;
    int frame_count = 0;
    const int max_frames = 32;

    unw_getcontext(&context);
    unw_init_local(&cursor, &context);

    entry->stack_frames = calloc(max_frames, sizeof(FRAME_STRUCT *));
    while (unw_step(&cursor) > 0 && frame_count < max_frames) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        const char *so_name = get_so_name(ip);
        unw_word_t so_base = get_so_base(ip);

        FRAME_STRUCT *frame = malloc(sizeof(FRAME_STRUCT));
#ifndef USE_JSON
        stack_frame__init(frame);
#endif
        frame->address = ip - so_base;
        frame->so_name = strdup(so_name);

        entry->stack_frames[frame_count++] = frame;
        entry->n_stack_frames++;
    }
}

static void add_mem_alloc_entry(void *pp, size_t size) {
    if (!g_hbm_trace_enabled)
        return;
    ThreadData *td = get_thread_data();
    ALLOC_STRUCT *entry = malloc(sizeof(ALLOC_STRUCT));
#ifndef USE_JSON
    mem_alloc_entry__init(entry);
#endif
    entry->alloc_ptr = (uint64_t)pp;
    entry->mem_size = size;
    entry->stage_id = global_stage_id;
    entry->stage_type = global_stage_type;
    entry->n_stack_frames = 0;
    entry->stack_frames = NULL;

    collect_stack_frames(entry);

    td->proc_mem->n_mem_alloc_stacks++;
    td->proc_mem->mem_alloc_stacks =
        realloc(td->proc_mem->mem_alloc_stacks,
                td->proc_mem->n_mem_alloc_stacks * sizeof(ALLOC_STRUCT *));
    td->proc_mem->mem_alloc_stacks[td->proc_mem->n_mem_alloc_stacks - 1] =
        entry;
}

static void add_mem_free_entry(void *pp) {
    if (!g_hbm_trace_enabled)
        return;
    ThreadData *td = get_thread_data();
    FREE_STRUCT *entry = malloc(sizeof(FREE_STRUCT));
#ifndef USE_JSON
    mem_free_entry__init(entry);
#endif
    entry->alloc_ptr = (uint64_t)pp;
    entry->stage_id = global_stage_id;
    entry->stage_type = global_stage_type;

    td->proc_mem->n_mem_free_stacks++;
    td->proc_mem->mem_free_stacks =
        realloc(td->proc_mem->mem_free_stacks,
                td->proc_mem->n_mem_free_stacks * sizeof(FREE_STRUCT *));
    td->proc_mem->mem_free_stacks[td->proc_mem->n_mem_free_stacks - 1] = entry;
}

int init_mem_trace() {
    void *lib =
        dlopen("/usr/local/Ascend/ascend-toolkit/latest/lib64/libascendcl.so",
               RTLD_LAZY);
    if (!lib) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return -1;
    }

    orig_halMemAlloc = (halMemAllocFunc_t)load_symbol(lib, "halMemAlloc");
    orig_halMemFree = (halMemFreeFunc_t)load_symbol(lib, "halMemFree");
    orig_halMemCreate = (halMemCreateFunc_t)load_symbol(lib, "halMemCreate");
    orig_halMemRelease = (halMemReleaseFunc_t)load_symbol(lib, "halMemRelease");
    orig_aclrtMalloc = (aclrtMallocFunc_t)load_symbol(lib, "aclrtMalloc");
    orig_aclrtMallocCached =
        (aclrtMallocCachedFunc_t)load_symbol(lib, "aclrtMallocCached");
    orig_aclrtMallocAlign32 =
        (aclrtMallocAlign32Func_t)load_symbol(lib, "aclrtMallocAlign32");
    orig_aclrtFree = (aclrtFreeFunc_t)load_symbol(lib, "aclrtFree");

    if (!orig_halMemAlloc || !orig_halMemFree || !orig_aclrtMalloc ||
        !orig_aclrtFree || !orig_halMemCreate || !orig_halMemRelease ||
        !orig_aclrtMallocCached || orig_aclrtMallocAlign32) {
        return -1;
    }

    atexit(exit_handler);

    return 0;
}

drvError_t halMemAlloc(void **pp, unsigned long long size,
                       unsigned long long flag) {
    if (!orig_halMemAlloc)
        init_mem_trace();
    int ret = orig_halMemAlloc(pp, size, flag);
    if (ret == 0 && pp && *pp)
        add_mem_alloc_entry(*pp, size);
    write_trace_to_file();
    return ret;
}

drvError_t halMemFree(void *pp) {
    if (!orig_halMemFree)
        init_mem_trace();
    int ret = orig_halMemFree(pp);
    if (ret == 0 && pp)
        add_mem_free_entry(pp);
    write_trace_to_file();
    return ret;
}