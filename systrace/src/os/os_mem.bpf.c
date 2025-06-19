/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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
#ifdef BPF_PROG_USER
#undef BPF_PROG_USER
#endif
#define BPF_PROG_KERN
#include "bpf.h"
#include "bpf_comm.h"
#include "os_probe.h"

char g_license[] SEC("license") = "GPL";

#define BPF_F_INDEX_MASK    0xffffffffULL
#define BPF_F_ALL_CPU   BPF_F_INDEX_MASK

#ifndef __PERF_OUT_MAX
#define __PERF_OUT_MAX (64)
#endif

#define PAGE_SIZE 4096
#define DEFAULT_RANK 0

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(fault_task_key_s *));
    __uint(value_size, sizeof(task_mem_s));
    __uint(max_entries, 1000);
} fault_task_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(comm_mem_task_key_s *));
    __uint(value_size, sizeof(task_mem_s));
    __uint(max_entries, 1000);
} comm_mem_task_map SEC(".maps");

static __always_inline int fault_event_start(struct task_struct *task, event_type_e event)
{
    u32 pid = BPF_CORE_READ(task, pid);  // 获取 TGID
    u32 tgid = BPF_CORE_READ(task, tgid);  // 获取 PID
    int rank = 0;
    rank = get_npu_id(task);
    if (rank < 0) {
        return 0;
    }

    pid = BPF_CORE_READ(task, pid);
    fault_task_key_s fault_task_key = {0};
    fault_task_key.event = event;
    fault_task_key.pid = pid;
    fault_task_key.tgid = tgid;

    task_mem_s task_mem_event = {0};
    task_mem_event.start_ts = bpf_ktime_get_ns();
    task_mem_event.event = event;
    task_mem_event.key = pid;
    task_mem_event.rank = rank;
    bpf_map_update_elem(&fault_task_map, &fault_task_key, &task_mem_event, BPF_ANY);
    
    return 0;
}

static __always_inline int fault_event_end(struct task_struct *task, void *ctx, event_type_e event)
{
    u32 pid = BPF_CORE_READ(task, pid);  // 获取 TGID
    u32 tgid = BPF_CORE_READ(task, tgid);  // 获取 PID
    fault_task_key_s fault_task_key = {0};
    fault_task_key.event = event;
    fault_task_key.pid = pid;
    fault_task_key.tgid = tgid;

    task_mem_s* task_mem_event = bpf_map_lookup_elem(&fault_task_map, &fault_task_key);
    if (task_mem_event) {
        u64 now = bpf_ktime_get_ns();
        if (now > task_mem_event->start_ts) {
            trace_event_data_t cur_event;
            create_cur_event(&cur_event, task_mem_event->key, task_mem_event->start_ts, now, task_mem_event->rank, event);
            // bpf_get_current_comm(&cur_event.comm, sizeof(cur_event.comm));
            bpf_core_read_str(cur_event.comm, sizeof(cur_event.comm), &task->comm);
            emit_event(&cur_event, ctx);
        }
        bpf_map_delete_elem(&fault_task_map, &fault_task_key);
    }

    return 0;
}

static __always_inline int common_event_start(struct task_struct *task, event_type_e event)
{
    int cpu = bpf_get_smp_processor_id();
    comm_mem_task_key_s comm_mem_task_key = {0};
     comm_mem_task_key.event = event;
     comm_mem_task_key.key = cpu;

    task_mem_s task_mem_event = {0};
    task_mem_event.start_ts = bpf_ktime_get_ns();
    task_mem_event.event = event;
    task_mem_event.key = cpu;

    bpf_map_update_elem(&comm_mem_task_map, &comm_mem_task_key, &task_mem_event, BPF_ANY);
    
    return 0;
}

static __always_inline int common_event_end(struct task_struct *task, void *ctx, event_type_e event)
{
    int cpu = bpf_get_smp_processor_id();
    comm_mem_task_key_s comm_mem_task_key = {0};
    comm_mem_task_key.event = event;
    comm_mem_task_key.key = cpu;

    task_mem_s* task_mem_event = bpf_map_lookup_elem(&comm_mem_task_map, & comm_mem_task_key);
    if (task_mem_event) {
        u64 now = bpf_ktime_get_ns();
        if (now > task_mem_event->start_ts) {
            trace_event_data_t cur_event;
            create_cur_event(&cur_event, task_mem_event->key, task_mem_event->start_ts, now, DEFAULT_RANK, event);
            emit_event(&cur_event, ctx);
        }
        bpf_map_delete_elem(&fault_task_map, &comm_mem_task_key);
    }

    return 0;
}

KPROBE(handle_mm_fault, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_filter_task(task)) {
        return 0;
    }
    fault_event_start(task, EVENT_TYPE_MM_FAULT);

    return 0;
}

KRETPROBE(handle_mm_fault, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_filter_task(task)) {
        return 0;
    }
    fault_event_end(task, ctx, EVENT_TYPE_MM_FAULT);

    return 0;
}

KPROBE(do_swap_page, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_filter_task(task)) {
        return 0;
    }
    common_event_start(task, EVENT_TYPE_SWAP_PAGE);
    return 0;
}

KRETPROBE(do_swap_page, pt_regs)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_filter_task(task)) {
        return 0;
    }
    common_event_end(task, ctx, EVENT_TYPE_SWAP_PAGE);
    return 0;
}

KRAWTRACE(mm_compaction_begin, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_filter_task(task)) {
        return 0;
    }
    common_event_start(task, EVENT_TYPE_COMPACTION);
    return 0;
}

KRAWTRACE(mm_compaction_end, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_filter_task(task)) {
        return 0;
    }
    common_event_end(task, ctx, EVENT_TYPE_COMPACTION);
    return 0;
}

KRAWTRACE(mm_vmscan_direct_reclaim_begin, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_filter_task(task)) {
        return 0;
    }
    common_event_start(task, EVENT_TYPE_VMSCAN);
    return 0;
}

KRAWTRACE(mm_vmscan_direct_reclaim_end, bpf_raw_tracepoint_args)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (is_filter_task(task)) {
        return 0;
    }
    common_event_end(task, ctx, EVENT_TYPE_VMSCAN);
    return 0;
}
