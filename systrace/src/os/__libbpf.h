/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * sysTrace licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Mr.lu
 * Create: 2021-09-28
 * Description: bpf header
 ******************************************************************************/
#ifndef __GOPHER_LIB_BPF_H__
#define __GOPHER_LIB_BPF_H__

#pragma once

#if !defined( BPF_PROG_KERN ) && !defined( BPF_PROG_USER )

#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include "common.h"
#include "__compat.h"

#define EBPF_RLIM_LIMITED  RLIM_INFINITY
#define EBPF_RLIM_INFINITY (~0UL)
#ifndef EINTR
#define EINTR 4
#endif

static __always_inline int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_WARN)
        return vfprintf(stderr, format, args);

    return 0;
}

static __always_inline int set_memlock_rlimit(unsigned long limit)
{
    struct rlimit rlim_new = {
        .rlim_cur   = limit,
        .rlim_max   = limit,
    };

    if (setrlimit(RLIMIT_MEMLOCK, (const struct rlimit *)&rlim_new) != 0) {
        (void)fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return 0;
    }
    return 1;
}

#define GET_MAP_OBJ(probe_name, map_name) (probe_name##_skel->maps.map_name)
#define GET_MAP_FD(probe_name, map_name) bpf_map__fd(probe_name##_skel->maps.map_name)
#define GET_PROG_FD(probe_name, prog_name) bpf_program__fd(probe_name##_skel->progs.prog_name)
#define GET_PROGRAM_OBJ(probe_name, prog_name) (probe_name##_skel->progs.prog_name)

#define GET_MAP_FD_BY_SKEL(skel, probe_name, map_name) \
    bpf_map__fd(((struct probe_name##_bpf *)(skel))->maps.map_name)
#define GET_PROG_OBJ_BY_SKEL(skel, probe_name) \
    (((struct probe_name##_bpf *)(skel))->obj)

#define BPF_OBJ_GET_MAP_FD(obj, map_name)   \
            ({ \
                int __fd = -1; \
                struct bpf_map *__map = bpf_object__find_map_by_name((obj), (map_name)); \
                if (__map) { \
                    __fd = bpf_map__fd(__map); \
                } \
                __fd; \
            })

#define BPF_OBJ_PIN_MAP_PATH(obj, map_name, path)   \
            ({ \
                int __ret = -1; \
                struct bpf_map *__map = bpf_object__find_map_by_name((obj), (map_name)); \
                if (__map) { \
                    __ret = bpf_map__set_pin_path(__map, path); \
                } \
                __ret; \
            })


#define __MAP_SET_PIN_PATH(probe_name, map_name, map_path) \
    do { \
        int ret; \
        struct bpf_map *__map; \
        \
        __map = GET_MAP_OBJ(probe_name, map_name); \
        ret = bpf_map__set_pin_path(__map, map_path); \
        printf("======>SHARE map(" #map_name ") set pin path \"%s\"(ret=%d).\n", map_path, ret); \
    } while (0)

#define GET_PROC_MAP_PIN_PATH(app_name) ("/sys/fs/bpf/sysTrace/__"#app_name"_proc_map")

#define INIT_BPF_APP(app_name, limit) \
    static char __init = 0; \
    do { \
        if (!__init) { \
            /* Set up libbpf printfs and printf printf callback */ \
            (void)libbpf_set_print(libbpf_print_fn); \
            \
            /* Bump RLIMIT_MEMLOCK  allow BPF sub-system to do anything */ \
            if (set_memlock_rlimit(limit) == 0) { \
                printf("BPF app(" #app_name ") failed to set mem limit.\n"); \
                return -1; \
            } \
            __init = 1; \
        } \
    } while (0)

#define LOAD(app_name, probe_name, end) \
    struct probe_name##_bpf *probe_name##_skel = NULL;           \
    struct bpf_link *probe_name##_link[PATH_NUM] __maybe_unused = {NULL}; \
    int probe_name##_link_current = 0;    \
    do { \
        int err; \
        /* Open load and verify BPF application */ \
        probe_name##_skel = probe_name##_bpf__open(); \
        if (!probe_name##_skel) { \
            printf("Failed to open BPF " #probe_name " skeleton\n"); \
            goto end; \
        } \
        if (probe_name##_bpf__load(probe_name##_skel)) { \
            printf("Failed to load BPF " #probe_name " skeleton\n"); \
            goto end; \
        } \
        /* Attach tracepoint handler */ \
        err = probe_name##_bpf__attach(probe_name##_skel); \
        if (err) { \
            printf("Failed to attach BPF " #probe_name " skeleton\n"); \
            probe_name##_bpf__destroy(probe_name##_skel); \
            probe_name##_skel = NULL; \
            goto end; \
        } \
        printf("Succeed to load and attach BPF " #probe_name " skeleton\n"); \
    } while (0)

#define __OPEN_OPTS(probe_name, end, load, opts) \
    struct probe_name##_bpf *probe_name##_skel = NULL;           \
    struct bpf_link *probe_name##_link[PATH_NUM] __maybe_unused = {NULL}; \
    int probe_name##_link_current = 0;    \
    do { \
        if (load) \
        {\
            /* Open load and verify BPF application */ \
            probe_name##_skel = probe_name##_bpf__open_opts(opts); \
            if (!probe_name##_skel) { \
                printf("Failed to open BPF " #probe_name " skeleton\n"); \
                goto end; \
            } \
        }\
    } while (0)

#define OPEN(probe_name, end, load) __OPEN_OPTS(probe_name, end, load, NULL)

#define OPEN_OPTS(probe_name, end, load) __OPEN_OPTS(probe_name, end, load, &probe_name##_open_opts)

#define MAP_SET_PIN_PATH(probe_name, map_name, map_path, load) \
    do { \
        if (load) \
        { \
            __MAP_SET_PIN_PATH(probe_name, map_name, map_path); \
        } \
    } while (0)

#define MAP_INIT_BPF_BUFFER(probe_name, map_name, buffer, load) \
    do { \
        if (load) { \
            buffer = bpf_buffer__new(probe_name##_skel->maps.map_name, probe_name##_skel->maps.heap); \
            if (buffer == NULL) { \
                printf("Failed to initialize bpf_buffer for " #map_name " in " #probe_name "\n"); \
            } \
        } \
    } while (0)

#define MAP_INIT_BPF_BUFFER_SHARED(probe_name, map_name, buffer_ptr, load) \
    do { \
        if (load) { \
            (void)bpf_buffer__new_shared(probe_name##_skel->maps.map_name, probe_name##_skel->maps.heap, (buffer_ptr)); \
            if (*(buffer_ptr) == NULL) { \
                printf("Failed to initialize bpf_buffer for " #map_name " in " #probe_name "\n"); \
            } \
        } \
    } while (0)

#define LOAD_ATTACH(app_name, probe_name, end, load) \
    do { \
        if (load) \
        { \
            int err; \
            if (probe_name##_bpf__load(probe_name##_skel)) { \
                printf("Failed to load BPF " #probe_name " skeleton\n"); \
                goto end; \
            } \
            /* Attach tracepoint handler */ \
            err = probe_name##_bpf__attach(probe_name##_skel); \
            if (err) { \
                printf("Failed to attach BPF " #probe_name " skeleton\n"); \
                probe_name##_bpf__destroy(probe_name##_skel); \
                probe_name##_skel = NULL; \
                goto end; \
            } \
            printf("Succeed to load and attach BPF " #probe_name " skeleton\n"); \
        } \
    } while (0)

#define UNLOAD(probe_name) \
    do { \
        int err; \
        if (probe_name##_skel != NULL) { \
            probe_name##_bpf__destroy(probe_name##_skel); \
        } \
        for (int i = 0; i < probe_name##_link_current; i++) { \
            err = bpf_link__destroy(probe_name##_link[i]); \
            if (err < 0) { \
                printf("Failed to detach BPF " #probe_name " %d\n", err); \
                break; \
            } \
        } \
    } while (0)

#define INIT_OPEN_OPTS(probe_name) \
    LIBBPF_OPTS(bpf_object_open_opts, probe_name##_open_opts)

static __always_inline __maybe_unused void poll_pb(struct perf_buffer *pb, int timeout_ms)
{
    int ret;

    while ((ret = perf_buffer__poll(pb, timeout_ms)) >= 0 || ret == -EINTR) {
        ;
    }
    return;
}

#define SKEL_MAX_NUM  20
typedef void (*skel_destroy_fn)(void *);

struct __bpf_skel_s {
    skel_destroy_fn fn;
    void *skel;
    void *_link[PATH_NUM];
    size_t _link_num;
};
struct bpf_prog_s {
    struct perf_buffer* pb;
    struct ring_buffer* rb;
    struct bpf_buffer *buffer;
    struct perf_buffer* pbs[SKEL_MAX_NUM];
    struct ring_buffer* rbs[SKEL_MAX_NUM];
    struct bpf_buffer *buffers[SKEL_MAX_NUM];
    struct __bpf_skel_s skels[SKEL_MAX_NUM];
    const char *custom_btf_paths[SKEL_MAX_NUM];
    size_t num;
};

static __always_inline __maybe_unused void free_bpf_prog(struct bpf_prog_s *prog)
{
    (void)free(prog);
}

static __always_inline __maybe_unused struct bpf_prog_s *alloc_bpf_prog(void)
{
    struct bpf_prog_s *prog = malloc(sizeof(struct bpf_prog_s));
    if (prog == NULL) {
        return NULL;
    }

    (void)memset(prog, 0, sizeof(struct bpf_prog_s));
    return prog;
}

static __always_inline __maybe_unused void unload_bpf_prog(struct bpf_prog_s **unload_prog)
{
    struct bpf_prog_s *prog = *unload_prog;

    *unload_prog = NULL;
    if (prog == NULL) {
        return;
    }

    for (int i = 0; i < prog->num; i++) {
        if (prog->skels[i].skel) {
            prog->skels[i].fn(prog->skels[i].skel);

            for (int j = 0; j < prog->skels[i]._link_num; j++) {
                if (prog->skels[i]._link[j]) {
                    (void)bpf_link__destroy(prog->skels[i]._link[j]);
                }
            }
        }

        if (prog->pbs[i]) {
            perf_buffer__free(prog->pbs[i]);
        }

#if (CURRENT_LIBBPF_VERSION  >= LIBBPF_VERSION(0, 8))
        if (prog->rbs[i]) {
            ring_buffer__free(prog->rbs[i]);
        }
#endif

        if (prog->buffers[i]) {
            bpf_buffer__free(prog->buffers[i]);
        }

        free((char *)prog->custom_btf_paths[i]);
    }

    if (prog->pb) {
        perf_buffer__free(prog->pb);
    }

#if (CURRENT_LIBBPF_VERSION  >= LIBBPF_VERSION(0, 8))
    if (prog->rb) {
        ring_buffer__free(prog->rb);
    }
#endif

    if (prog->buffer) {
        bpf_buffer__free(prog->buffer);
    }

    free_bpf_prog(prog);
    return;
}


#endif
#endif
