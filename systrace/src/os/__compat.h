/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * gala-gopher licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: curry
 * Create: 2025-06-20
 * Description: Compatibility APIs for eBPF probes
 ******************************************************************************/

#ifndef __GOPHER_COMPAT_H__
#define __GOPHER_COMPAT_H__

#if defined(BPF_PROG_KERN) || defined(BPF_PROG_USER)
#include <bpf/bpf_helpers.h>

#if defined(BPF_PROG_KERN)
#include "vmlinux.h"
#endif

#include "__feat_probe.h"

#define MAX_DATA_SIZE 10240

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_DATA_SIZE);
} heap SEC(".maps");

#endif

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
#include <bpf/libbpf.h>
#include <malloc.h>
#include <errno.h>

#include "__feat_probe.h"

#define PERF_BUFFER_PAGES 64

typedef int (*bpf_buffer_sample_fn)(void *ctx, void *data, u32 size);
typedef void (*bpf_buffer_lost_fn)(void *ctx, int cpu, u64 cnt);

struct bpf_buffer
{
    struct bpf_map *map;
    void *inner;
    bpf_buffer_sample_fn fn;
    void *ctx;
    int type;
};

static void __perfbuf_sample_fn(void *ctx, int cpu, void *data, __u32 size)
{
    struct bpf_buffer *buffer = (struct bpf_buffer *)ctx;
    bpf_buffer_sample_fn fn;

    fn = buffer->fn;
    if (!fn) {
        return;
    }

    (void)fn(buffer->ctx, data, size);
}

static inline int bpf_buffer__reset(struct bpf_map *map, struct bpf_map *heap)
{
    bool use_ringbuf;
    int type;

    use_ringbuf = probe_ringbuf();
    if (use_ringbuf) {
        bpf_map__set_autocreate(heap, false);
        bpf_map__set_type(map, BPF_MAP_TYPE_RINGBUF);
        type = BPF_MAP_TYPE_RINGBUF;
    } else {
        bpf_map__set_autocreate(heap, true);
        bpf_map__set_type(map, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        bpf_map__set_key_size(map, sizeof(int));
        bpf_map__set_value_size(map, sizeof(int));
        type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    }

    return type;
}

#define MAX_RB_MAP_SZ       32
static inline int bpf_buffer__set_max_entries(struct bpf_map *map, struct bpf_buffer *buffer, unsigned char map_size_mb)
{

    if (buffer == NULL || buffer->type != BPF_MAP_TYPE_RINGBUF) {
        return 0;
    }

    if (map_size_mb == 0 || map_size_mb > MAX_RB_MAP_SZ) {
        return -1;
    }

    u32 max_entries = map_size_mb * 1024 * 1024;
    return bpf_map__set_max_entries(map, max_entries);
}

static inline struct bpf_buffer *bpf_buffer__new(struct bpf_map *map, struct bpf_map *heap)
{
    struct bpf_buffer *buffer;
    int type;

    type = bpf_buffer__reset(map, heap);
    buffer = (struct bpf_buffer *)calloc(1, sizeof(*buffer));
    if (!buffer) {
        errno = ENOMEM;
        return NULL;
    }

    buffer->map = map;
    buffer->type = type;
    return buffer;
}

static inline struct bpf_buffer *bpf_buffer__new_shared(struct bpf_map *map, struct bpf_map *heap, struct bpf_buffer **buffer_ptr)
{
    struct bpf_buffer *buffer;

    if (*buffer_ptr != NULL) {
        (void)bpf_buffer__reset(map, heap);
        return *buffer_ptr;
    }

    buffer = bpf_buffer__new(map, heap);
    *buffer_ptr = buffer;
    return buffer;
}

static inline int bpf_buffer__open(struct bpf_buffer *buffer, bpf_buffer_sample_fn sample_cb, bpf_buffer_lost_fn lost_cb, void *ctx)
{
    int fd, type;
    void *inner;

    if (buffer == NULL) {
        return -1;
    }

    fd = bpf_map__fd(buffer->map);
    type = buffer->type;

    switch (type) {
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        buffer->fn = sample_cb;
        buffer->ctx = ctx;
        inner = perf_buffer__new(fd, PERF_BUFFER_PAGES, __perfbuf_sample_fn, lost_cb, buffer, NULL);
        break;
    case BPF_MAP_TYPE_RINGBUF:
        inner = ring_buffer__new(fd, (ring_buffer_sample_fn) sample_cb, ctx, NULL);
        break;
    default:
        return 0;
    }

    long err = libbpf_get_error(inner);
    if (err) {
        return err;
    }

    buffer->inner = inner;
    return 0;
}

static inline int bpf_buffer__poll(struct bpf_buffer *buffer, int timeout_ms)
{
    switch (buffer->type)
    {
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        return perf_buffer__poll((struct perf_buffer *)buffer->inner, timeout_ms);
    case BPF_MAP_TYPE_RINGBUF:
        return ring_buffer__poll((struct ring_buffer *)buffer->inner, timeout_ms);
    default:
        return -EINVAL;
    }
}

static inline void bpf_buffer__free(struct bpf_buffer *buffer)
{
    if (!buffer) {
        return;
    }

    switch (buffer->type) {
    case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
        perf_buffer__free((struct perf_buffer *)buffer->inner);
        break;
    case BPF_MAP_TYPE_RINGBUF:
        ring_buffer__free((struct ring_buffer *)buffer->inner);
        break;
    }
    free(buffer);
}
#endif

#endif
