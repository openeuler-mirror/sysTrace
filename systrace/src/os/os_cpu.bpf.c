#define BPF_PROG_KERN
#include "vmlinux.h"
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
    u32 pid = BPF_CORE_READ(task, pid);
    u32 tgid = BPF_CORE_READ(task, tgid);
    offcpu_task_key_s key = {.pid = pid, .tgid = tgid};
    
    task_cpu_s *entry = bpf_map_lookup_elem(&task_cpu_map, &key);
    if (!entry) {
        rank = get_npu_id(task);
        if (rank < 0) return 0;
        task_cpu_s new_val = {.pid = pid, .rank = rank};
        bpf_map_update_elem(&task_cpu_map, &key, &new_val, BPF_ANY);
        entry = bpf_map_lookup_elem(&task_cpu_map, &key);
    }
    return entry;
}

static __always_inline void process_oncpu(struct task_struct *task, void *ctx) {
    u32 pid = BPF_CORE_READ(task, pid);
    u32 tgid = BPF_CORE_READ(task, tgid);
    offcpu_task_key_s key = {.pid = pid, .tgid = tgid};
    task_cpu_s *entry = bpf_map_lookup_elem(&task_cpu_map, &key);
    if (!entry || entry->start_time == 0) {
        bpf_map_delete_elem(&task_cpu_map, &key);
        return;
    }
    entry->end_time = bpf_ktime_get_ns();
    trace_event_data_t ev = {0};
    create_cur_event(&ev, pid, entry->start_time, entry->end_time, entry->rank, EVENT_TYPE_OFFCPU);
    ev.delay = entry->delay;
    ev.next_pid = entry->next_pid;
    bpf_probe_read_kernel(ev.next_comm, sizeof(ev.next_comm), entry->next_comm);
    bpf_core_read_str(ev.comm, sizeof(ev.comm), &task->comm);
    emit_event(&ev, ctx);
    bpf_map_delete_elem(&task_cpu_map, &key);
}

static __always_inline void process_offcpu(struct task_struct *prev, struct task_struct *current, void *ctx) {
    task_cpu_s *entry = get_offcpu_enter(prev);
    if (!entry) return;
    entry->start_time = bpf_ktime_get_ns();
    entry->delay = BPF_CORE_READ(prev, sched_info.run_delay);
    bpf_probe_read_kernel(entry->next_comm, sizeof(entry->next_comm), current->comm);
    entry->next_pid = BPF_CORE_READ(current, pid);
}

KRAWTRACE(sched_switch, bpf_raw_tracepoint_args)
{
    if (!trace_cfg_enabled(OS_PROBE_CPU)) {
        return 0;
    }
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *current = (struct task_struct *)ctx->args[2];
    if (current == NULL || prev == NULL) {
        return 0;
    }
    process_offcpu(prev, current, (void *)ctx);
    process_oncpu(current, (void *)ctx);

    return 0;
}
