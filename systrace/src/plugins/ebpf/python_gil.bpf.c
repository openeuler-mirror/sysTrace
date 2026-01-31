#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

typedef struct {
    __u64 ts;
    __u32 pid;
    __u32 tid;
    char name[16];
    char ph;
    char pad[7];
} gil_event;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rank_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

static __always_inline void submit_event(struct pt_regs *ctx, const char *name,
                                         char ph) {
    gil_event ev = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev.ts = bpf_ktime_get_ns();
    ev.pid = pid_tgid >> 32;
    ev.tid = (__u32)pid_tgid;
    ev.ph = ph;
    __builtin_memcpy(ev.name, name, sizeof(ev.name));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
}

SEC("uprobe") int handle_take_gil_enter(struct pt_regs *ctx) {
    submit_event(ctx, "take_gil", 'B');
    return 0;
}
SEC("uprobe") int handle_take_gil_exit(struct pt_regs *ctx) {
    submit_event(ctx, "take_gil", 'E');
    return 0;
}
SEC("uprobe") int handle_drop_gil_enter(struct pt_regs *ctx) {
    submit_event(ctx, "drop_gil", 'B');
    return 0;
}
SEC("uprobe") int handle_drop_gil_exit(struct pt_regs *ctx) {
    submit_event(ctx, "drop_gil", 'E');
    return 0;
}

char LICENSE[] SEC("license") = "GPL";