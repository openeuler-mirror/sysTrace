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
#ifdef BPF_PROG_KERN
#undef BPF_PROG_KERN
#endif
#define BPF_PROG_KERN
#include "vmlinux.h"
#include "bpf.h"
#include "bpf_comm.h"
#include "os_probe.h"

char g_license[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(offcpu_task_key_s));
    __uint(value_size, sizeof(task_cpu_s));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} task_cpu_map SEC(".maps");

static __always_inline task_cpu_s *get_offcpu_enter(struct task_struct *task)
{
    int rank = 0;
    u32 pid = BPF_CORE_READ(task, pid);  // 获取 TGID
    u32 tgid = BPF_CORE_READ(task, tgid);  // 获取 PID
    offcpu_task_key_s task_offcpu_key = {0};
    task_offcpu_key.pid = pid;
    task_offcpu_key.tgid = tgid;
    task_cpu_s *offcpu_enter;
    offcpu_enter = (task_cpu_s *)bpf_map_lookup_elem(&task_cpu_map, &task_offcpu_key);
    if (offcpu_enter == (void *)0) {
        task_cpu_s oncpu_enter_tmp;
        __builtin_memset(&oncpu_enter_tmp, 0, sizeof(oncpu_enter_tmp));
        rank = get_npu_id(task);
        if (rank < 0) {
            return 0;
        }
        oncpu_enter_tmp.pid = pid;
        oncpu_enter_tmp.rank = rank;
        (void)bpf_map_update_elem(&task_cpu_map, &task_offcpu_key, &oncpu_enter_tmp, BPF_ANY);
        offcpu_enter = (task_cpu_s *)bpf_map_lookup_elem(&task_cpu_map, &task_offcpu_key);
    }

    return offcpu_enter;
}

static __inline int str_eq(const char *s1, const char *s2, int len) {
    for (int i = 0; i < len; i++) {
        if (s1[i] != s2[i])
            return 1;
        if (s1[i] == '\0')
            return 0;
    }
    return 0;
}

static __always_inline void process_oncpu(struct task_struct *task, void *ctx)
{
    u32 pid = BPF_CORE_READ(task, pid);  // 获取 TGID
    u32 tgid = BPF_CORE_READ(task, tgid);  // 获取 PID
    offcpu_task_key_s task_offcpu_key = {0};
    task_offcpu_key.pid = pid;
    task_offcpu_key.tgid = tgid;
    task_cpu_s *offcpu_enter = (task_cpu_s *)bpf_map_lookup_elem(&task_cpu_map, &task_offcpu_key);
    if (offcpu_enter == (void *)0) {
        return;
    }
    
    offcpu_enter->end_time = bpf_ktime_get_ns(); // i.e. offcpu's start_time
    if (offcpu_enter->start_time == 0) {
        bpf_map_delete_elem(&task_cpu_map, &task_offcpu_key);
        return;
    }
    trace_event_data_t cur_event;
    create_cur_event(&cur_event, pid, offcpu_enter->start_time, offcpu_enter->end_time, offcpu_enter->rank, EVENT_TYPE_OFFCPU);
    cur_event.delay = offcpu_enter->delay;
    cur_event.next_pid = offcpu_enter->next_pid;
    bpf_probe_read_kernel(cur_event.next_comm, sizeof(cur_event.next_comm), &offcpu_enter->next_comm);
    bpf_core_read_str(cur_event.comm, sizeof(cur_event.comm), &task->comm);
    emit_event(&cur_event, ctx);
    bpf_map_delete_elem(&task_cpu_map, &task_offcpu_key);
}

static __always_inline void process_offcpu(struct task_struct *prev, struct task_struct *current, void *ctx)
{
    task_cpu_s *offcpu_enter;
    offcpu_enter = get_offcpu_enter(prev);
    if (offcpu_enter == (void *)0) {
        return;
    }
    offcpu_enter->start_time = bpf_ktime_get_ns();
    offcpu_enter->delay = BPF_CORE_READ((prev), sched_info.run_delay);
    bpf_probe_read_kernel(offcpu_enter->next_comm, sizeof(offcpu_enter->next_comm), &current->comm);
    offcpu_enter->next_pid = BPF_CORE_READ(current, pid);
}

KRAWTRACE(sched_switch, bpf_raw_tracepoint_args)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *current = (struct task_struct *)ctx->args[2];
    if (current == NULL || prev == NULL) {
        return 0;
    }
    process_offcpu(prev, current, (void *)ctx);
    process_oncpu(current, (void *)ctx);

    return 0;
}
