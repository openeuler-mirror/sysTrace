/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
 * sysTrace licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: curry
 * Create: 2025-06-20
 * Description: 
 ******************************************************************************/

#ifndef __BPF_COMMON_H__
#define __BPF_COMMON_H__
#include "bpf.h"

#include "os_probe.h"

#define MAX_SIZE_OF_PROC    128
#define MAX_SIZE_OF_THREAD  (128 * MAX_SIZE_OF_PROC)
#define PF_IDLE			0x00000002	/* IDLE thread */
#define PF_KTHREAD		0x00200000	/* kernel thread */

typedef struct {
    u32 pid;
    u32 tgid;
} offcpu_task_key_s;

typedef struct {
    u32 pid;
    int rank;
    __u64 start_time;
    __u64 end_time;
    __u64 delay;
    char next_comm[THREAD_COMM_LEN];
    u32 next_pid;
} task_cpu_s;

typedef struct {
    int key;
    event_type_e event;
} comm_mem_task_key_s;

typedef struct {
    event_type_e event;
    u32 pid;
    u32 tgid;
} fault_task_key_s;

typedef struct {
    event_type_e event;
    __u32 key;
    __u64 start_ts;
    int rank;
} task_mem_s;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_3 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_5 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_7 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_8 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_9 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_10 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_11 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_12 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_13 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_14 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} osprobe_map_15 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, 16);
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} kernel_filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 128);
} proc_filter_map SEC(".maps");

#define MAX_COMM_LEN 16
static __always_inline void emit_event(trace_event_data_t *event, void *ctx)
{
    if (!event) {
        return;
    }
    switch (event->rank) {
    case 0:
        bpf_ringbuf_output(&osprobe_map_0, event, sizeof(*event), 0);
        break;
    case 1:
        bpf_ringbuf_output(&osprobe_map_1, event, sizeof(*event), 0);
        break;
    case 2:
        bpf_ringbuf_output(&osprobe_map_2, event, sizeof(*event), 0);
        break;
    case 3:
        bpf_ringbuf_output(&osprobe_map_3, event, sizeof(*event), 0);
        break;
    case 4:
        bpf_ringbuf_output(&osprobe_map_4, event, sizeof(*event), 0);
        break;
    case 5:
        bpf_ringbuf_output(&osprobe_map_5, event, sizeof(*event), 0);
        break;
    case 6:
        bpf_ringbuf_output(&osprobe_map_6, event, sizeof(*event), 0);
        break;
    case 7:
        bpf_ringbuf_output(&osprobe_map_7, event, sizeof(*event), 0);
        break;
    case 8:
        bpf_ringbuf_output(&osprobe_map_8, event, sizeof(*event), 0);
        break;
    case 9:
        bpf_ringbuf_output(&osprobe_map_9, event, sizeof(*event), 0);
        break;
    case 10:
        bpf_ringbuf_output(&osprobe_map_10, event, sizeof(*event), 0);
        break;
    case 11:
        bpf_ringbuf_output(&osprobe_map_11, event, sizeof(*event), 0);
        break;
    case 12:
        bpf_ringbuf_output(&osprobe_map_12, event, sizeof(*event), 0);
        break;
    case 13:
        bpf_ringbuf_output(&osprobe_map_13, event, sizeof(*event), 0);
        break;
    case 14:
        bpf_ringbuf_output(&osprobe_map_14, event, sizeof(*event), 0);
        break;
    case 15:
        bpf_ringbuf_output(&osprobe_map_15, event, sizeof(*event), 0);
        break;
    default:
        break;
    }
}

static __always_inline void create_cur_event(trace_event_data_t *cur_event, int key,
    u64 start_time, u64 end_time, int rank, event_type_e type)
{
    if (cur_event == NULL) {
        return;
    }
    __builtin_memset(cur_event, 0, sizeof(*cur_event));
    cur_event->key = key;
    cur_event->start_time = start_time;
    cur_event->end_time = end_time;
    cur_event->duration = end_time - start_time;
    cur_event->type = type;
    cur_event->rank = rank;
}

static int strcase_match(const char *s1, const char *s2, int n)
{
    unsigned char c1, c2;
#pragma unroll
    while (n--) {
        c1 = *s1++;
        c2 = *s2++;

        if (!c1 || !c2)
            break;

        // 转换为小写进行比较
        if (c1 == c2)
            continue;

        if ((c1 >= 'A' && c1 <= 'Z') && (c2 >= 'a' && c2 <= 'z') && (c1 + 32 == c2))
            continue;

        if ((c2 >= 'A' && c2 <= 'Z') && (c1 >= 'a' && c1 <= 'z') && (c2 + 32 == c1))
            continue;

        // 不相等
        return (int)c1 - (int)c2;
    }

    if (n == (size_t)-1) { /* 如果循环是因为n用完而不是遇到\0 */
        // 检查最后一个字符是否都为 '\0'
        if (!c1 && !c2)
            return 0;
    }

    return (int)c1 - (int)c2;
}

static __always_inline int get_npu_id(struct task_struct *task)
{
    u32 pid = BPF_CORE_READ(task, pid);

    // 匹配python主线程
    int *rank;
    rank = bpf_map_lookup_elem(&proc_filter_map, &pid);
    if (rank) {
        return *rank;
    }

    // 匹配内核dev线程
    char comm[16] = {};
    bpf_core_read_str(comm, sizeof(comm), &task->comm);
    // bpf_get_current_comm(&comm, sizeof(comm));
    rank = bpf_map_lookup_elem(&kernel_filter_map, comm);
    if (rank) {
        bpf_printk("is kernel thread:%s, pid is %lu", comm, pid);
        return *rank;
    }

    // 匹配ACL线程
    const char target[] = "acl_thread";
    if (strcase_match(comm, target, MAX_COMM_LEN)) {
        u32 tgid = BPF_CORE_READ(task, tgid);
        rank = bpf_map_lookup_elem(&proc_filter_map, &tgid);
        if (rank) {
            return *rank;
        }
    }

    // 全都不匹配返回-1
    return -1;

}

#endif
