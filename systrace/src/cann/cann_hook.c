#define _GNU_SOURCE
#include "../../include/common/shared_constants.h"
#include "../../protos/systrace.pb-c.h"
#include <dlfcn.h>
#include <errno.h>
#include <google/protobuf-c/protobuf-c.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#if defined(__aarch64__)
#include "../../thirdparty/aarch64/libunwind/libunwind.h"
#elif defined(__x86_64__)
#include "../../thirdparty/x86_64/libunwind/libunwind.h"
#else
#error "Unsupported architecture - only aarch64 and x86_64 are supported"
#endif

// export LD_PRELOAD=/home/MindSpeed-LLM-1.0.RC3/libascend_hal_jack.so
// cd /home/hbdir/mspti_test-megatron
// conda activate mspti10
// python -m torch.distributed.launch --nproc_per_node=8 nqq_train_fsdp.py
// protoc --c_out=. tmp.proto

// drvError_t halMemAlloc(void **pp, unsigned long long size, unsigned long long
// flag); drvError_t halMemFree(void *pp); drvError_t
// halMemCreate(drv_mem_handle_t **handle, size_t size, const struct
// drv_mem_prop *prop, uint64_t flag); drvError_t halMemRelease
// (drv_mem_handle_t *handle);

#define LOG_INTERVAL_SEC 120
#define LOG_ITEMS_MIN 1000

typedef int drvError_t;

typedef enum aclrtMemMallocPolicy
{
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

typedef struct
{
    ProcMem *proc_mem;
    time_t last_log_time;
} ThreadData;

static void *load_symbol(void *lib, const char *symbol_name)
{
    void *sym = dlsym(lib, symbol_name);
    if (!sym)
    {
        fprintf(stderr, "Failed to find symbol %s: %s\n", symbol_name,
                dlerror());
    }
    return sym;
}

static void free_proc_mem(ProcMem *proc_mem)
{
    if (!proc_mem)
        return;

    // 释放分配记录
    for (size_t i = 0; i < proc_mem->n_mem_alloc_stacks; i++)
    {
        MemAllocEntry *entry = proc_mem->mem_alloc_stacks[i];
        for (size_t j = 0; j < entry->n_stack_frames; j++)
        {
            free((void *)entry->stack_frames[j]->so_name);
            free(entry->stack_frames[j]);
        }
        free(entry->stack_frames);
        free(entry);
    }
    free(proc_mem->mem_alloc_stacks);

    // 释放释放记录
    for (size_t i = 0; i < proc_mem->n_mem_free_stacks; i++)
    {
        free(proc_mem->mem_free_stacks[i]);
    }
    free(proc_mem->mem_free_stacks);

    // 重置计数
    proc_mem->n_mem_alloc_stacks = 0;
    proc_mem->mem_alloc_stacks = NULL;
    proc_mem->n_mem_free_stacks = 0;
    proc_mem->mem_free_stacks = NULL;
}

static void free_thread_data(void *data)
{
    ThreadData *td = (ThreadData *)data;
    if (td && td->proc_mem)
    {
        free_proc_mem(td->proc_mem);
        free(td->proc_mem);
    }
    free(td);
}

static inline uint32_t get_current_pid() { return (uint32_t)getpid(); }

static void make_key()
{
    pthread_key_create(&thread_data_key, free_thread_data);
}

static ThreadData *get_thread_data()
{
    ThreadData *td;

    pthread_once(&key_once, make_key);
    td = pthread_getspecific(thread_data_key);

    if (!td)
    {
        td = calloc(1, sizeof(ThreadData));
        td->proc_mem = calloc(1, sizeof(ProcMem));
        proc_mem__init(td->proc_mem);
        td->proc_mem->pid = get_current_pid();
        td->last_log_time = time(NULL);
        pthread_setspecific(thread_data_key, td);
    }

    return td;
}

static const char *get_so_name(uint64_t ip)
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

static void get_log_filename(time_t current, uint32_t pid, char *buf,
                             size_t buf_size)
{
    const char *rank_str = getenv("RANK");
    int rank = rank_str ? atoi(rank_str) : 0;
    struct tm *tm = localtime(&current);

    const char *dir_path = SYS_TRACE_ROOT_DIR "cann";
    if (access(dir_path, F_OK) != 0)
    {
        if (mkdir(dir_path, 0755) != 0 && errno != EEXIST)
        {
            perror("Failed to create directory");
            snprintf(buf, buf_size, "mem_trace_%04d%02d%02d_%02d_%u_rank%d.pb",
                     tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                     tm->tm_hour, pid, rank);
            return;
        }
    }
    snprintf(buf, buf_size, "%s/mem_trace_%04d%02d%02d_%02d_%u_rank%d.pb",
             dir_path, tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
             tm->tm_hour, pid, rank);
}

static char is_ready_to_write(ThreadData *td, time_t *current)
{
    ProcMem *proc_mem = td->proc_mem;
    if (!proc_mem ||
        (proc_mem->n_mem_alloc_stacks + proc_mem->n_mem_free_stacks == 0))
    {
        return 0;
    }

    *current = time(NULL);
    if (proc_mem->n_mem_alloc_stacks + proc_mem->n_mem_free_stacks <
        LOG_ITEMS_MIN)
    {
        if (*current - td->last_log_time < LOG_INTERVAL_SEC)
        {
            return 0;
        }
    }

    return 1;
}

static void write_protobuf_to_file()
{
    time_t current;
    uint8_t *buf;
    ThreadData *td = get_thread_data();
    if (!td)
    {
        return;
    }

    if (!is_ready_to_write(td, &current))
    {
        return;
    }

    if (pthread_mutex_trylock(&file_mutex) == 0)
    { // pthread_mutex_trylock or pthread_mutex_lock
        char filename[256];
        get_log_filename(current, td->proc_mem->pid, filename,
                         sizeof(filename));

        size_t len = proc_mem__get_packed_size(td->proc_mem);
        buf = malloc(len);
        proc_mem__pack(td->proc_mem, buf);

        FILE *fp = fopen(filename, "ab");
        if (fp)
        {
            fwrite(buf, len, 1, fp);
            fclose(fp);
        }

        pthread_mutex_unlock(&file_mutex);
    }
    else
    {
        return;
    }

    if (buf)
    {
        free(buf);
    }

    free_proc_mem(td->proc_mem);
    td->last_log_time = current;
}

static void exit_handler(void) { write_protobuf_to_file(); }

int init_mem_trace()
{
    void *lib =
        dlopen("/usr/local/Ascend/ascend-toolkit/latest/lib64/libascendcl.so",
               RTLD_LAZY);
    if (!lib)
    {
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
        !orig_aclrtMallocCached || orig_aclrtMallocAlign32)
    {
        return -1;
    }

    atexit(exit_handler);

    return 0;
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

static void collect_stack_frames(MemAllocEntry *entry)
{
    unw_cursor_t cursor;
    unw_context_t context;
    unw_word_t ip;
    int frame_count = 0;
    const int max_frames = 32;

    unw_getcontext(&context);
    unw_init_local(&cursor, &context);

    entry->stack_frames = calloc(max_frames, sizeof(StackFrame *));
    while (unw_step(&cursor) > 0 && frame_count < max_frames)
    {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);

        // Get the SO name and base address for this IP
        const char *so_name = get_so_name(ip);
        unw_word_t so_base = get_so_base(ip); // You'll need to implement this

        StackFrame *frame = malloc(sizeof(StackFrame));
        stack_frame__init(frame);
        frame->address =
            ip - so_base; // Store offset within SO instead of virtual address
        frame->so_name = strdup(so_name);

        entry->stack_frames[frame_count] = frame;
        entry->n_stack_frames++;

        frame_count++;
    }
}

static void add_mem_alloc_entry(void *pp, size_t size)
{
    ThreadData *td = get_thread_data();

    MemAllocEntry *entry = malloc(sizeof(MemAllocEntry));
    mem_alloc_entry__init(entry);
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
                td->proc_mem->n_mem_alloc_stacks * sizeof(MemAllocEntry *));
    td->proc_mem->mem_alloc_stacks[td->proc_mem->n_mem_alloc_stacks - 1] =
        entry;
}

static void add_mem_free_entry(void *pp)
{
    ThreadData *td = get_thread_data();

    MemFreeEntry *entry = malloc(sizeof(MemFreeEntry));
    mem_free_entry__init(entry);
    entry->alloc_ptr = (uint64_t)pp;
    entry->stage_id = global_stage_id;
    entry->stage_type = global_stage_type;

    td->proc_mem->n_mem_free_stacks++;
    td->proc_mem->mem_free_stacks =
        realloc(td->proc_mem->mem_free_stacks,
                td->proc_mem->n_mem_free_stacks * sizeof(MemFreeEntry *));
    td->proc_mem->mem_free_stacks[td->proc_mem->n_mem_free_stacks - 1] = entry;
}

drvError_t halMemAlloc(void **pp, unsigned long long size,
                       unsigned long long flag)
{
    if (!orig_halMemAlloc)
    {
        init_mem_trace();
    }
    int ret = orig_halMemAlloc(pp, size, flag);
    if (ret == 0 && pp && *pp)
    {
        add_mem_alloc_entry(*pp, size);
    }

    write_protobuf_to_file();

    return ret;
}

drvError_t halMemFree(void *pp)
{
    if (!orig_halMemFree)
    {
        init_mem_trace();
    }
    int ret = orig_halMemFree(pp);
    if (ret == 0 && pp)
    {
        add_mem_free_entry(pp);
    }

    write_protobuf_to_file();

    return ret;
}

drvError_t aclrtMalloc(void **devPtr, size_t size, aclrtMemMallocPolicy policy)
{
    if (!orig_aclrtMalloc)
    {
        init_mem_trace();
    }
    int ret = orig_aclrtMalloc(devPtr, size, policy);
    if (ret == 0 && devPtr && *devPtr)
    {
        add_mem_alloc_entry(*devPtr, size);
    }

    write_protobuf_to_file();

    return ret;
}

drvError_t aclrtMallocCached(void **devPtr, size_t size,
                             aclrtMemMallocPolicy policy)
{
    if (!orig_aclrtMallocCached)
    {
        init_mem_trace();
    }
    int ret = orig_aclrtMallocCached(devPtr, size, policy);
    if (ret == 0 && devPtr && *devPtr)
    {
        add_mem_alloc_entry(*devPtr, size);
    }

    write_protobuf_to_file();

    return ret;
}

drvError_t aclrtMallocAlign32(void **devPtr, size_t size,
                              aclrtMemMallocPolicy policy)
{
    if (!orig_aclrtMallocAlign32)
    {
        init_mem_trace();
    }
    int ret = orig_aclrtMallocAlign32(devPtr, size, policy);
    if (ret == 0 && devPtr && *devPtr)
    {
        add_mem_alloc_entry(*devPtr, size);
    }

    write_protobuf_to_file();

    return ret;
}

drvError_t aclrtFree(void *devPtr)
{
    if (!orig_aclrtFree)
    {
        init_mem_trace();
    }
    int ret = orig_aclrtFree(devPtr);
    if (ret == 0 && devPtr)
    {
        add_mem_free_entry(devPtr);
    }

    write_protobuf_to_file();

    return ret;
}

drvError_t halMemCreate(void **handle, size_t size, void *prop, uint64_t flag)
{
    if (!orig_halMemCreate)
    {
        init_mem_trace();
    }
    int ret = orig_halMemCreate(handle, size, prop, flag);
    if (ret == 0 && handle && *handle)
    {
        add_mem_alloc_entry(*handle, size);
    }

    write_protobuf_to_file();

    return ret;
}

drvError_t halMemRelease(void *handle)
{
    if (!orig_halMemRelease)
    {
        init_mem_trace();
    }

    int ret = orig_halMemRelease(handle);
    if (ret == 0 && handle)
    {
        add_mem_free_entry(handle);
    }

    write_protobuf_to_file();

    return ret;
}