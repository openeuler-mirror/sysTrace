
/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * sysTrace licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 *PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the
 *Mulan PSL v2 for more details. Author: curry Create: 2025-06-20 Description:
 ******************************************************************************/
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef USE_JSON
typedef struct {
    uint64_t key;
    uint64_t start_us;
    uint64_t dur;
    uint64_t rundelay;
    uint32_t os_event_type;
    uint32_t rank;
    char *comm;
    char *nxt_comm;
    uint32_t nxt_pid;
} JSONOSprobeEntry;

typedef struct {
    JSONOSprobeEntry **osprobe_entries;
    size_t n_osprobe_entries;
} JSONOSprobe;

#define OSPROBE_STRUCT JSONOSprobe
#define OSPROBE_ENTRY_STRUCT JSONOSprobeEntry
#else
#include "../../protos/systrace.pb-c.h"
#include <google/protobuf-c/protobuf-c.h>
#define OSPROBE_STRUCT OSprobe
#define OSPROBE_ENTRY_STRUCT OSprobeEntry
#endif

#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif

#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif

#ifndef SYS_TRACE_ROOT_DIR
#define SYS_TRACE_ROOT_DIR "/home/sysTrace/"
#endif

#include "../../include/common/constant.h"
#include "../../include/utils/TimeUtil.hpp"
#include "../cann/common_hook.h"
#include "bpf.h"
#include "os_cpu.skel.h"
#include "os_mem.skel.h"
#include "os_probe.h"

#define MAX_PATH_LEN 512
#define LOG_INTERVAL_SEC_FOR_OS 120
#define RM_MAP_PATH "/usr/bin/rm -rf /sys/fs/bpf/sysTrace*"
#define PROC_FILTER_MAP_PATH "/sys/fs/bpf/sysTrace/__osprobe_proc_filter"
#define KERNEL_FILTER_MAP_PATH "/sys/fs/bpf/sysTrace/__osprobe_kernel_filter"
#define TRACE_CFG_MAP_PATH "/sys/fs/bpf/sysTrace/__osprobe_trace_cfg"
#define LOG_ITEMS_MIN 10

#define MAP_SET_COMMON_PIN_PATHS(probe_name, end, load)                        \
    INIT_OPEN_OPTS(probe_name);                                                \
    OPEN_OPTS(probe_name, end, load);                                          \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_0,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_0", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_1,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_1", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_2,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_2", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_3,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_3", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_4,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_4", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_5,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_5", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_6,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_6", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_7,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_7", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_8,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_8", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_9,                                \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_9", load);            \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_10,                               \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_10", load);           \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_11,                               \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_11", load);           \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_12,                               \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_12", load);           \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_13,                               \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_13", load);           \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_14,                               \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_14", load);           \
    MAP_SET_PIN_PATH(probe_name, osprobe_map_15,                               \
                     "/sys/fs/bpf/sysTrace/__osprobe_map_15", load);           \
    MAP_SET_PIN_PATH(probe_name, proc_filter_map, PROC_FILTER_MAP_PATH, load); \
    MAP_SET_PIN_PATH(probe_name, kernel_filter_map, KERNEL_FILTER_MAP_PATH,    \
                     load);                                                    \
    MAP_SET_PIN_PATH(probe_name, trace_cfg_map, TRACE_CFG_MAP_PATH, load);

#define OPEN_OSPROBE(probe_name, end, load, buffer)                            \
    MAP_SET_COMMON_PIN_PATHS(probe_name, end, load);                           \
    MAP_INIT_BPF_BUFFER_SHARED(probe_name, osprobe_map_0, &buffer, load);

static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_stop = 0;

extern pid_t g_hooked_pid;
static pthread_key_t thread_data_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;
static int rank;
static int local_rank;
static struct bpf_prog_s *prog = NULL;

typedef struct {
    OSPROBE_STRUCT *osprobe;
    time_t last_log_time;
} OSprobe_ThreadData;

void sig_int() { g_stop = 1; };

char *event_name[] = {"mem_fault", "swap_page", "compaction", "vmscan",
                      "offcpu"};

void initialize_osprobe() {
    const char *rank_str = getenv("RANK") ? getenv("RANK") : getenv("RANK_ID");
    const char *local_rank_str =
        getenv("LOCAL_RANK") ? getenv("LOCAL_RANK") : getenv("DEVICE_ID");
    rank = rank_str ? atoi(rank_str) : 0;
    local_rank = local_rank_str ? atoi(local_rank_str) : 0;
}

static void free_osprobe_entries(OSPROBE_STRUCT *osprobe) {
    if (!osprobe || !osprobe->osprobe_entries)
        return;
    for (size_t i = 0; i < osprobe->n_osprobe_entries; i++) {
        OSPROBE_ENTRY_STRUCT *entry = osprobe->osprobe_entries[i];
        if (!entry)
            continue;
#ifdef USE_JSON
        if (entry->comm)
            free(entry->comm);
        if (entry->nxt_comm)
            free(entry->nxt_comm);
#else
        if (entry->comm && entry->comm != protobuf_c_empty_string)
            free((void *)entry->comm);
        if (entry->nxt_comm && entry->nxt_comm != protobuf_c_empty_string)
            free((void *)entry->nxt_comm);
#endif
        free(entry);
    }
    free(osprobe->osprobe_entries);
    osprobe->n_osprobe_entries = 0;
    osprobe->osprobe_entries = NULL;
}

static void free_thread_data(void *data) {
    OSprobe_ThreadData *td = (OSprobe_ThreadData *)data;
    if (td && td->osprobe) {
        free_osprobe_entries(td->osprobe);
        free(td->osprobe);
    }
    free(td);
}

static void make_key() {
    pthread_key_create(&thread_data_key, free_thread_data);
}

static OSprobe_ThreadData *get_thread_data() {
    OSprobe_ThreadData *td;
    pthread_once(&key_once, make_key);
    td = pthread_getspecific(thread_data_key);

    if (!td) {
        td = calloc(1, sizeof(OSprobe_ThreadData));
        td->osprobe = calloc(1, sizeof(OSPROBE_STRUCT));
#ifndef USE_JSON
        osprobe__init(td->osprobe);
#endif
        td->last_log_time = time(NULL);
        pthread_setspecific(thread_data_key, td);
    }
    return td;
}

static void add_osprobe_entry(trace_event_data_t *evt_data) {
    OSprobe_ThreadData *td = get_thread_data();
    if (!td || !evt_data)
        return;

    OSPROBE_ENTRY_STRUCT *entry = malloc(sizeof(OSPROBE_ENTRY_STRUCT));
    if (entry == NULL)
        return;

#ifndef USE_JSON
    osprobe_entry__init(entry);
#else
    memset(entry, 0, sizeof(JSONOSprobeEntry));
#endif

    entry->key = evt_data->key;
    entry->start_us = monotonic_ns_to_utc_us(evt_data->start_time);
    entry->dur = evt_data->duration / NSEC_PER_USEC;
    entry->rundelay = evt_data->delay;
    entry->os_event_type = (uint32_t)evt_data->type;
    entry->rank = rank;

#ifdef USE_JSON
    entry->comm = strdup(evt_data->comm);
    if (!entry->comm) {
        free(entry);
        return;
    }
    entry->nxt_comm = NULL;
    entry->nxt_pid = 0;
    if (entry->os_event_type == EVENT_TYPE_OFFCPU &&
        evt_data->next_comm[0] != '\0') {
        entry->nxt_comm = strdup(evt_data->next_comm);
        if (!entry->nxt_comm) {
            free(entry->comm);
            free(entry);
            return;
        }
        entry->nxt_pid = evt_data->next_pid;
    }
#else
    if (entry->comm && entry->comm != protobuf_c_empty_string) {
        free((void *)entry->comm);
    }
    entry->comm = strdup(evt_data->comm);
    if (!entry->comm) {
        free(entry);
        return;
    }

    if (entry->nxt_comm && entry->nxt_comm != protobuf_c_empty_string) {
        free((void *)entry->nxt_comm);
        entry->nxt_comm = NULL;
    }

    entry->nxt_pid = 0;
    if (entry->os_event_type == EVENT_TYPE_OFFCPU &&
        evt_data->next_comm[0] != '\0') {
        entry->nxt_comm = strdup(evt_data->next_comm);
        if (!entry->nxt_comm) {
            free((void *)entry->comm);
            free(entry);
            return;
        }
        entry->nxt_pid = evt_data->next_pid;
    } else {
        entry->nxt_comm = (char *)protobuf_c_empty_string;
    }
#endif

    td->osprobe->n_osprobe_entries++;
    td->osprobe->osprobe_entries = realloc(td->osprobe->osprobe_entries,
                                           td->osprobe->n_osprobe_entries *
                                               sizeof(OSPROBE_ENTRY_STRUCT *));
    td->osprobe->osprobe_entries[td->osprobe->n_osprobe_entries - 1] = entry;
}

static char is_ready_to_write(OSprobe_ThreadData *td, time_t *current) {
    OSPROBE_STRUCT *osprobe = td->osprobe;
    if (!osprobe || (osprobe->n_osprobe_entries == 0)) {
        return 0;
    }

    *current = time(NULL);
    if (osprobe->n_osprobe_entries < LOG_ITEMS_MIN) {
        if (*current - td->last_log_time < LOG_INTERVAL_SEC_FOR_OS) {
            return 0;
        }
    }
    return 1;
}

static void write_protobuf_to_file() {
    time_t current;
    OSprobe_ThreadData *td = get_thread_data();
    if (!td)
        return;

    if (!is_ready_to_write(td, &current)) {
        return;
    }

    if (pthread_mutex_trylock(&file_mutex) == 0) {
        char filename[256];
#ifdef USE_JSON
        get_log_filename(filename, sizeof(filename), "osprobe", JSON);
#else
        get_log_filename(filename, sizeof(filename), "osprobe", PB);
#endif

#ifdef USE_JSON
        FILE *fp = fopen(filename, "ab");
        if (fp) {
            fprintf(fp, "{\"os_entries\":[");
            for (size_t i = 0; i < td->osprobe->n_osprobe_entries; i++) {
                OSPROBE_ENTRY_STRUCT *e = td->osprobe->osprobe_entries[i];
                fprintf(fp,
                        "%s{\"key\":%" PRIu64 ",\"start\":%" PRIu64
                        ",\"dur\":%" PRIu64 ",\"delay\":%" PRIu64
                        ",\"type\":%u,\"rank\":%d,\"comm\":\"%s\",\"ncomm\":\"%"
                        "s\",\"npid\":%u}",
                        (i == 0 ? "" : ","), e->key, e->start_us, e->dur,
                        e->rundelay, e->os_event_type, (int)e->rank, e->comm,
                        e->nxt_comm ? e->nxt_comm : "", e->nxt_pid);
            }
            fprintf(fp, "]}\n");
            fclose(fp);
        }
#else
        size_t len = osprobe__get_packed_size(td->osprobe);
        uint8_t *buf = malloc(len);
        if (buf) {
            osprobe__pack(td->osprobe, buf);
            FILE *fp = fopen(filename, "ab");
            if (fp) {
                fwrite(buf, len, 1, fp);
                fclose(fp);
            }
            free(buf);
        }
#endif
        pthread_mutex_unlock(&file_mutex);
    } else {
        return;
    }

    free_osprobe_entries(td->osprobe);
    td->last_log_time = current;
}

static int recv_bpf_msg(void *ctx, void *data, __u32 size) {
    char *p = data;
    size_t remain_size = (size_t)size, step_size = sizeof(trace_event_data_t),
           offset = 0;
    trace_event_data_t *evt_data;

    do {
        if (remain_size < step_size) {
            break;
        }
        p = (char *)data + offset;
        evt_data = (trace_event_data_t *)p;
        add_osprobe_entry(evt_data);
        write_protobuf_to_file();
        offset += step_size;
        remain_size -= step_size;
    } while (1);

    return 0;
}

static int load_mem_probe(struct bpf_prog_s *prog, struct bpf_buffer *buffer) {
    INIT_BPF_APP(os_probe, EBPF_RLIM_LIMITED);
    OPEN_OSPROBE(os_mem, err, 1, buffer);
    prog->skels[prog->num].skel = os_mem_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)os_mem_bpf__destroy;
    prog->custom_btf_paths[prog->num] = os_mem_open_opts.btf_custom_path;
    LOAD_ATTACH(os_probe, os_mem, err, 1);

    int ret = bpf_buffer__open(buffer, recv_bpf_msg, NULL, NULL);
    if (ret) {
        bpf_buffer__free(buffer);
        goto err;
    }
    prog->buffers[prog->num++] = buffer;
    return 0;
err:
    UNLOAD(os_mem);
    return -1;
}

static int load_cpu_probe(struct bpf_prog_s *prog, struct bpf_buffer *buffer) {
    INIT_BPF_APP(os_probe, EBPF_RLIM_LIMITED);
    OPEN_OSPROBE(os_cpu, err, 1, buffer);
    prog->skels[prog->num].skel = os_cpu_skel;
    prog->skels[prog->num].fn = (skel_destroy_fn)os_cpu_bpf__destroy;
    prog->custom_btf_paths[prog->num] = os_cpu_open_opts.btf_custom_path;
    LOAD_ATTACH(os_probe, os_cpu, err, 1);

    int ret = bpf_buffer__open(buffer, recv_bpf_msg, NULL, NULL);
    if (ret) {
        bpf_buffer__free(buffer);
        goto err;
    }
    prog->buffers[prog->num++] = buffer;
    return 0;
err:
    UNLOAD(os_cpu);
    return -1;
}

int update_filter_map_by_npu_smi() {
    FILE *fp;
    char line[MAX_PATH_LEN];
    int proc_filter_map_fd;
    int ret = 0;
    proc_filter_map_fd = bpf_obj_get(PROC_FILTER_MAP_PATH);
    if (proc_filter_map_fd < 0) {
        // 打印error num
        fprintf(
            stderr,
            "[OS_PROBE RANK_%d] Failed to get bpf prog proc_filter map: %s.\n",
            rank, strerror(errno));
        return -1;
    }
    // 获取进程号
    fp = popen("npu-smi info", "r");
    if (fp == NULL) {
        perror("Failed to run npu-smi info");
        return -1;
    }
    int start_parsing = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        // 查找 Process id 和 NPU 号
        if (strstr(line, "Process id") != NULL) {
            start_parsing = 1;
            continue;
        }
        if (!start_parsing)
            continue;
        // 空行表示表格结束
        if (strstr(line, "====") || strlen(line) < 10)
            continue;

        unsigned int npu, pid;

        // 匹配含 pid 的行，例如：
        // | 0       0                 | 1228424       | python | 194 |
        if (sscanf(line, "| %u %*d | %u | %*s %*s | %*d", &npu, &pid) == 2) {
            ret = bpf_map_update_elem(proc_filter_map_fd, &pid, &npu, BPF_ANY);
            if (ret != 0) {
                fprintf(stderr,
                        "[OS_PROBE RANK_%d] bpf_map_update_elem failed: %s "
                        "(errno: %d)\n",
                        rank, strerror(errno), errno);
            }
        }
    }
    pclose(fp);
    return ret;
}

int update_filter_map_by_kernel_thread() {
    int kernel_filter_map_fd;
    int ret = 0;
    kernel_filter_map_fd = bpf_obj_get(KERNEL_FILTER_MAP_PATH);
    if (kernel_filter_map_fd < 0) {
        // 打印error num
        fprintf(stderr,
                "[OS_PROBE RANK_%d] Failed to get bpf prog kernel_filter map: "
                "%s.\n",
                rank, strerror(errno));
        return -1;
    }
    for (int dev_id = 0; dev_id < 16; ++dev_id) {
        char send_key[32] = {0};
        char task_key[32] = {0};
        snprintf(send_key, sizeof(send_key), "dev%d_sq_send_wq", dev_id);
        snprintf(task_key, sizeof(task_key), "dev%d_sq_task", dev_id);

        ret = bpf_map_update_elem(kernel_filter_map_fd, send_key, &dev_id,
                                  BPF_ANY);
        if (ret != 0) {
            perror("bpf_map_update_elem failed");
        }
        ret = bpf_map_update_elem(kernel_filter_map_fd, task_key, &dev_id,
                                  BPF_ANY);
        if (ret != 0) {
            perror("bpf_map_update_elem failed");
        }
    }

    return ret;
}

int bpf_buffer_init_from_pin(struct bpf_buffer **buffer_ptr,
                             const char *map_path, bpf_buffer_sample_fn fn,
                             void *ctx) {
    struct bpf_buffer *buffer;
    if (!map_path || !fn) {
        fprintf(stderr, "Invalid arguments to bpf_buffer_init_from_pin\n");
        return -EINVAL;
    }
    buffer = (struct bpf_buffer *)calloc(1, sizeof(*buffer));

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open pinned map at %s: %s\n", map_path,
                strerror(errno));
        return -1;
    }

    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len) < 0) {
        perror("bpf_obj_get_info_by_fd");
        close(map_fd);
        return -1;
    }

    buffer->type = info.type;
    buffer->fn = fn;
    buffer->ctx = ctx;
    switch (info.type) {
    case BPF_MAP_TYPE_RINGBUF:
        buffer->inner =
            ring_buffer__new(map_fd, (ring_buffer_sample_fn)fn, ctx, NULL);
        if (!buffer->inner) {
            fprintf(stderr, "ring_buffer__new failed for map: %s\n", map_path);
            close(map_fd);
            return -1;
        }
        break;

    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        return -1;

    default:
        fprintf(stderr, "Unsupported map type (%d) for map: %s\n", info.type,
                map_path);
        close(map_fd);
        return -1;
    }
    *buffer_ptr = buffer;
    close(map_fd);
    return 0;
}

void cleanup_osprobe() {
    sig_int();

    static int cleaned = 0;
    if (cleaned++)
        return;

    FILE *fp = popen(RM_MAP_PATH, "r");
    if (fp)
        pclose(fp);
}

static void signal_handler(int sig) {
    (void)sig;
    cleanup_osprobe();
    _exit(0);
}

static void exit_handler(void) { cleanup_osprobe(); }

void os_probe_enable_event(os_probe_type_e type) {
    int trace_cfg_map_fd = bpf_obj_get(TRACE_CFG_MAP_PATH);
    int value = 1;
    if (trace_cfg_map_fd < 0) {
        fprintf(
            stderr,
            "[OS_PROBE RANK_%d] Failed to get bpf prog trace_cfg map: %s.\n",
            rank, strerror(errno));
        return;
    }
    bpf_map_update_elem(trace_cfg_map_fd, &type, &value, BPF_ANY);
    close(trace_cfg_map_fd);
}

void os_probe_disable_event(os_probe_type_e type) {
    int value = 0;
    int trace_cfg_map_fd = bpf_obj_get(TRACE_CFG_MAP_PATH);
    if (trace_cfg_map_fd < 0) {
        fprintf(
            stderr,
            "[OS_PROBE RANK_%d] Failed to get bpf prog trace_cfg map: %s.\n",
            rank, strerror(errno));
        return;
    }
    bpf_map_update_elem(trace_cfg_map_fd, &type, &value, BPF_ANY);
    close(trace_cfg_map_fd);
}

void check_npu() {
    int max_retries = 600;
    int interval_ms = 100;
    for (int i = 0; i < max_retries; i++) {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (!fp) {
            break;
        }
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            line[strcspn(line, "\n")] = 0;
            char *ptr = strstr(line, "/dev/davinci");
            if (ptr) {
                fclose(fp);
                usleep(50000);
                return;
            }
        }
        fclose(fp);
        usleep(interval_ms * 1000);
    }
    sleep(60);
}

int run_osprobe() {
    int ret = 0;
    struct bpf_buffer *buffer = NULL;

    initialize_osprobe();

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
    atexit(exit_handler);

    if (local_rank == 0) {
        prog = alloc_bpf_prog();
        if (prog == NULL) {
            goto err;
        }

        ret = load_mem_probe(prog, buffer);
        if (ret) {
            goto err;
        }

        ret = load_cpu_probe(prog, buffer);
        if (ret) {
            goto err;
        }

        (void)update_filter_map_by_kernel_thread();

        check_npu();

        (void)update_filter_map_by_npu_smi();

        while (!g_stop) {
            for (int i = 0; i < prog->num; i++) {
                if (prog->buffers[i]) {
                    ret = bpf_buffer__poll(prog->buffers[i], THOUSAND);
                    if (ret < 0 && ret != -EINTR) {
                        break;
                    }
                }
            }
            usleep(1000);
        }
    } else {
        char osprobe_map_path[MAX_PATH_LEN];
        snprintf(osprobe_map_path, sizeof(osprobe_map_path),
                 "/sys/fs/bpf/sysTrace/__osprobe_map_%d", local_rank);

        while (access(osprobe_map_path, F_OK) != 0) {
            if (g_stop)
                goto err;
            usleep(100000);
        }

        ret = bpf_buffer_init_from_pin(&buffer, osprobe_map_path, recv_bpf_msg,
                                       NULL);
        if (ret < 0) {
            goto err;
        }

        while (!g_stop) {
            ret = bpf_buffer__poll(buffer, THOUSAND);
            if (ret < 0 && ret != -EINTR) {
                break;
            }
        }
    }

err:
    cleanup_osprobe();

    if (local_rank == 0 && prog) {
        unload_bpf_prog(&prog);
        free_bpf_prog(prog);
    }

    return ret;
}
