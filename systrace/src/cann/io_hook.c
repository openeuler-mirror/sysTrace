#define _GNU_SOURCE
#include "../../include/common/constant.h"
#include "common_hook.h"
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef USE_JSON
// JSON 模式：定义原生 C 结构体和枚举
typedef enum {
    IOTYPE__IO_READ = 0,
    IOTYPE__IO_WRITE = 1,
    IOTYPE__IO_FREAD = 2,
    IOTYPE__IO_FWRITE = 3,
    IOTYPE__IO_FOPEN = 4,
    IOTYPE__IO_FCLOSE = 5,
    IOTYPE__IO_FFLUSH = 6,
    IOTYPE__IO_REMOVE = 7,
    IOTYPE__IO_RENAME = 8,
    IOTYPE__IO_CLOSE = 9,
    IOTYPE__IO_FSYNC = 10,
    IOTYPE__IO_MKDIR = 11,
    IOTYPE__IO_RMDIR = 12,
    IOTYPE__IO_UNLINK = 13,
    IOTYPE__IO_OPENDIR = 14,
    IOTYPE__IO_CLOSEDIR = 15
} JSONIOType;

typedef struct {
    uint64_t start_us;
    uint64_t dur;
    int32_t stage_id;
    int32_t stage_type;
    int32_t io_type;
    char *file_name; // 原 Protobuf 中是 ProtobufCBinaryData
    uint32_t rank;
} JSONIOEntry;

typedef struct {
    JSONIOEntry **io_entries;
    size_t n_io_entries;
} JSONIO;

#define IO_STRUCT JSONIO
#define IO_ENTRY_STRUCT JSONIOEntry
#define IO_TYPE_ENUM int32_t
#else
#include "../../protos/systrace.pb-c.h"
#include <google/protobuf-c/protobuf-c.h>
#define IO_STRUCT IO
#define IO_ENTRY_STRUCT IOEntry
#define IO_TYPE_ENUM IOType
#endif

typedef struct {
    IO_STRUCT *io;
    time_t last_log_time;
} ThreadData;

typedef size_t (*halFReadFunc_t)(void *ptr, size_t size, size_t nmemb,
                                 FILE *stream);
typedef size_t (*halFWriteFunc_t)(const void *ptr, size_t size, size_t nmemb,
                                  FILE *stream);
typedef ssize_t (*halReadFunc_t)(int fd, void *buf, size_t count);
typedef ssize_t (*halWriteFunc_t)(int fd, const void *buf, size_t count);
typedef FILE *(*halFOpenFunc_t)(const char *path, const char *mode);
typedef int (*halFCloseFunc_t)(FILE *stream);
typedef int (*halFFlushFunc_t)(FILE *stream);
typedef int (*halRemoveFunc_t)(const char *filename);
typedef int (*halRenameFunc_t)(const char *oldname, const char *newname);
typedef int (*halCloseFunc_t)(int fd);
typedef int (*halFsyncFunc_t)(int fd);
typedef int (*halMkdirFunc_t)(const char *path, mode_t mode);
typedef int (*halRmdirFunc_t)(const char *path);
typedef int (*halUnlinkFunc_t)(const char *path);
typedef DIR *(*halOpendirFunc_t)(const char *name);
typedef int (*halClosedirFunc_t)(DIR *dir);

static halFReadFunc_t orig_fread = NULL;
static halFWriteFunc_t orig_fwrite = NULL;
static halReadFunc_t orig_read = NULL;
static halWriteFunc_t orig_write = NULL;
static halFOpenFunc_t orig_fopen = NULL;
static halFCloseFunc_t orig_fclose = NULL;
static halFFlushFunc_t orig_fflush = NULL;
static halRemoveFunc_t orig_remove = NULL;
static halRenameFunc_t orig_rename = NULL;
static halCloseFunc_t orig_close = NULL;
static halFsyncFunc_t orig_fsync = NULL;
static halMkdirFunc_t orig_mkdir = NULL;
static halRmdirFunc_t orig_rmdir = NULL;
static halUnlinkFunc_t orig_unlink = NULL;
static halOpendirFunc_t orig_opendir = NULL;
static halClosedirFunc_t orig_closedir = NULL;

static pthread_key_t thread_data_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
extern int global_stage_id;
extern int global_stage_type;
static bool g_io_trace_enabled = false;

void io_trace_set_enabled(bool enabled) { g_io_trace_enabled = enabled; }

static void free_io_data(void *data) {
    ThreadData *td = (ThreadData *)data;
    if (td && td->io) {
        for (size_t i = 0; i < td->io->n_io_entries; i++) {
#ifdef USE_JSON
            free(td->io->io_entries[i]->file_name);
#else
            free(td->io->io_entries[i]->file_name.data);
#endif
            free(td->io->io_entries[i]);
        }
        free(td->io->io_entries);
        free(td->io);
    }
    free(td);
}

static void make_key() { pthread_key_create(&thread_data_key, free_io_data); }

static ThreadData *get_thread_data() {
    ThreadData *td;
    pthread_once(&key_once, make_key);
    td = pthread_getspecific(thread_data_key);

    if (!td) {
        td = calloc(1, sizeof(ThreadData));
        td->io = calloc(1, sizeof(IO_STRUCT));
#ifndef USE_JSON
        io__init(td->io);
#endif
        td->last_log_time = time(NULL);
        pthread_setspecific(thread_data_key, td);
    }
    return td;
}

static char *get_filename_from_fd(int fd) {
    if (fd < 0)
        return strdup("<none>");
    char path[256], resolved[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(path, resolved, sizeof(resolved) - 1);
    if (len == -1)
        return strdup("<unknown>");
    resolved[len] = '\0';
    const char *filename = strrchr(resolved, '/');
    return strdup(filename ? filename + 1 : resolved);
}

static int is_ready_to_write(ThreadData *td, time_t *current) {
    *current = time(NULL);
    if (!td->io || td->io->n_io_entries == 0)
        return 0;
    if (*current - td->last_log_time >= LOG_INTERVAL_SEC ||
        td->io->n_io_entries >= LOG_ITEMS_MIN) {
        return 1;
    }
    return 0;
}

static void write_io_trace_to_file() {
    time_t current;
    ThreadData *td = get_thread_data();
    if (!td || !is_ready_to_write(td, &current))
        return;

    if (pthread_mutex_trylock(&file_mutex) == 0) {
        char filename[256];
#ifdef USE_JSON
        get_log_filename(filename, sizeof(filename), "io", JSON);
        FILE *fp = fopen(filename, "ab");
        if (fp) {
            fprintf(fp, "{\"io_entries\":[");
            for (size_t i = 0; i < td->io->n_io_entries; i++) {
                IO_ENTRY_STRUCT *e = td->io->io_entries[i];
                fprintf(fp,
                        "%s{\"start\":%" PRIu64 ",\"dur\":%" PRIu64
                        ",\"sid\":%d,\"st\":%d,\"type\":%d,\"file\":\"%s\","
                        "\"rank\":%u}",
                        (i == 0 ? "" : ","), e->start_us, e->dur, e->stage_id,
                        e->stage_type, e->io_type, e->file_name, e->rank);
            }
            fprintf(fp, "]}\n");
            fclose(fp);
        }
#else
        get_log_filename(filename, sizeof(filename), "io", PB);
        size_t len = io__get_packed_size(td->io);
        uint8_t *buf = malloc(len);
        if (buf) {
            io__pack(td->io, buf);
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

    for (size_t i = 0; i < td->io->n_io_entries; i++) {
#ifdef USE_JSON
        free(td->io->io_entries[i]->file_name);
#else
        free(td->io->io_entries[i]->file_name.data);
#endif
        free(td->io->io_entries[i]);
    }
    td->io->n_io_entries = 0;
    td->last_log_time = current;
}

static void exit_handler(void) { write_io_trace_to_file(); }

static void add_io_entry(int fd, uint64_t start_us, uint64_t duration,
                         IO_TYPE_ENUM operation) {
    if (!g_io_trace_enabled)
        return;
    ThreadData *td = get_thread_data();
    if (!td || !td->io)
        return;

    IO_ENTRY_STRUCT *entry = malloc(sizeof(IO_ENTRY_STRUCT));
#ifndef USE_JSON
    ioentry__init(entry);
#endif
    entry->start_us = start_us;
    entry->dur = duration;
    entry->stage_id = global_stage_id;
    entry->stage_type = global_stage_type;
    entry->io_type = operation;

    char *fname = get_filename_from_fd(fd);
#ifdef USE_JSON
    entry->file_name = fname;
#else
    entry->file_name.data = (uint8_t *)fname;
    entry->file_name.len = strlen(fname);
#endif

    const char *rank_str = getenv("RANK") ? getenv("RANK") : getenv("RANK_ID");
    entry->rank = rank_str ? atoi(rank_str) : 0;

    td->io->n_io_entries++;
    td->io->io_entries = realloc(
        td->io->io_entries, td->io->n_io_entries * sizeof(IO_ENTRY_STRUCT *));
    td->io->io_entries[td->io->n_io_entries - 1] = entry;
}

int init_io_trace() {
    void *lib = dlopen("libc.so.6", RTLD_LAZY);
    if (!lib)
        return -1;

    orig_fread = (halFReadFunc_t)dlsym(lib, "fread");
    orig_fwrite = (halFWriteFunc_t)dlsym(lib, "fwrite");
    orig_read = (halReadFunc_t)dlsym(lib, "read");
    orig_write = (halWriteFunc_t)dlsym(lib, "write");
    orig_fopen = (halFOpenFunc_t)dlsym(lib, "fopen");
    orig_fclose = (halFCloseFunc_t)dlsym(lib, "fclose");
    orig_fflush = (halFFlushFunc_t)dlsym(lib, "fflush");
    orig_remove = (halRemoveFunc_t)dlsym(lib, "remove");
    orig_rename = (halRenameFunc_t)dlsym(lib, "rename");
    orig_close = (halCloseFunc_t)dlsym(lib, "close");
    orig_fsync = (halFsyncFunc_t)dlsym(lib, "fsync");
    orig_mkdir = (halMkdirFunc_t)dlsym(lib, "mkdir");
    orig_rmdir = (halRmdirFunc_t)dlsym(lib, "rmdir");
    orig_unlink = (halUnlinkFunc_t)dlsym(lib, "unlink");
    orig_opendir = (halOpendirFunc_t)dlsym(lib, "opendir");
    orig_closedir = (halClosedirFunc_t)dlsym(lib, "closedir");

    atexit(exit_handler);
    return 0;
}

ssize_t read(int fd, void *buf, size_t count) {
    if (!orig_read) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    ssize_t ret = orig_read(fd, buf, count);
    uint64_t end_us = get_current_utc_us();

    if (ret > 0) {
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_READ);
    }

    write_io_trace_to_file();
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (!orig_write) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    ssize_t ret = orig_write(fd, buf, count);
    uint64_t end_us = get_current_utc_us();

    if (ret > 0) {
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_WRITE);
    }

    write_io_trace_to_file();
    return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!orig_fwrite) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    ssize_t ret = orig_fwrite(ptr, size, nmemb, stream);
    uint64_t end_us = get_current_utc_us();

    if (ret > 0) {
        int fd = fileno(stream);
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_FWRITE);
    }

    write_io_trace_to_file();
    return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (!orig_fread) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    ssize_t ret = orig_fread(ptr, size, nmemb, stream);
    uint64_t end_us = get_current_utc_us();

    if (ret > 0) {
        int fd = fileno(stream);
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_FREAD);
    }

    write_io_trace_to_file();
    return ret;
}

FILE *fopen(const char *path, const char *mode) {
    if (!orig_fopen) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    FILE *ret = orig_fopen(path, mode);
    uint64_t end_us = get_current_utc_us();

    if (ret) {
        int fd = fileno(ret);
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_FOPEN);
    }

    write_io_trace_to_file();
    return ret;
}

int fclose(FILE *stream) {
    if (!orig_fclose) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_fclose(stream);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        int fd = fileno(stream);
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_FCLOSE);
    }

    write_io_trace_to_file();
    return ret;
}

int fflush(FILE *stream) {
    if (!orig_fflush) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_fflush(stream);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0 && stream) {
        int fd = fileno(stream);
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_FFLUSH);
    }

    write_io_trace_to_file();
    return ret;
}

int remove(const char *filename) {
    if (!orig_remove) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_remove(filename);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        add_io_entry(-1, start_us, end_us - start_us, IOTYPE__IO_REMOVE);
    }

    write_io_trace_to_file();
    return ret;
}

int rename(const char *oldname, const char *newname) {
    if (!orig_rename) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_rename(oldname, newname);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        add_io_entry(-1, start_us, end_us - start_us, IOTYPE__IO_RENAME);
    }

    write_io_trace_to_file();
    return ret;
}

int close(int fd) {
    if (!orig_close) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_close(fd);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_CLOSE);
    }

    write_io_trace_to_file();
    return ret;
}

int fsync(int fd) {
    if (!orig_fsync) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_fsync(fd);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        add_io_entry(fd, start_us, end_us - start_us, IOTYPE__IO_FSYNC);
    }

    write_io_trace_to_file();
    return ret;
}

int mkdir(const char *path, mode_t mode) {
    if (!orig_mkdir) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_mkdir(path, mode);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        add_io_entry(-1, start_us, end_us - start_us, IOTYPE__IO_MKDIR);
    }

    write_io_trace_to_file();
    return ret;
}

int rmdir(const char *path) {
    if (!orig_rmdir) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_rmdir(path);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        add_io_entry(-1, start_us, end_us - start_us, IOTYPE__IO_RMDIR);
    }

    write_io_trace_to_file();
    return ret;
}

int unlink(const char *path) {
    if (!orig_unlink) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_unlink(path);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        add_io_entry(-1, start_us, end_us - start_us, IOTYPE__IO_UNLINK);
    }

    write_io_trace_to_file();
    return ret;
}

DIR *opendir(const char *name) {
    if (!orig_opendir) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    DIR *ret = orig_opendir(name);
    uint64_t end_us = get_current_utc_us();

    if (ret) {
        add_io_entry(-1, start_us, end_us - start_us, IOTYPE__IO_OPENDIR);
    }

    write_io_trace_to_file();
    return ret;
}

int closedir(DIR *dir) {
    if (!orig_closedir) {
        init_io_trace();
    }

    uint64_t start_us = get_current_utc_us();
    int ret = orig_closedir(dir);
    uint64_t end_us = get_current_utc_us();

    if (ret == 0) {
        add_io_entry(-1, start_us, end_us - start_us, IOTYPE__IO_CLOSEDIR);
    }

    write_io_trace_to_file();
    return ret;
}