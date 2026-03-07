#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>

#define MAX_SIZE_OF_THREAD  (128 * 128)
#define THREAD_COMM_LEN     16
#define bpf_section(NAME) __attribute__((section(NAME), used))

enum {
    GIL_UNKNOWN_ID = 0,
    GIL_TAKE_ID,
    GIL_DROP_ID,
    GIL_MAX_ID
};

typedef struct {
    int pid;
    int id;
} gil_m_key_t;

typedef struct {
    gil_m_key_t key;
    __u64 start_time;
    __u64 end_time;
} gil_m_enter_t;

typedef enum {
    EVT_TYPE_GIL = 1,
} trace_event_type_t;

typedef struct {
    __u64 start_time;
    __u64 end_time;
    __u64 duration;
    int id;
    char name[16];
} gil_data_t;

typedef struct {
    int pid;
    int tid;
    char comm[THREAD_COMM_LEN];
    trace_event_type_t type;
    union {
        gil_data_t gil_d;
    };
} gil_trace_event_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);  // 1MB ringbuf
} event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(gil_trace_event_data_t));
    __uint(max_entries, 1);
} event_stash_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(gil_m_key_t));
    __uint(value_size, sizeof(gil_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} gil_enter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 128);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rank_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));   // 开关ID
    __uint(value_size, sizeof(__u32)); // 0: disable, 1: enable
    __uint(max_entries, 128);
} gil_trace_cfg_map SEC(".maps");

static __always_inline int trace_cfg_enabled(__u32 key) {
    __u32 *enable = bpf_map_lookup_elem(&gil_trace_cfg_map, &key);
    if (!enable || *enable == 0) {
        return 0;
    }
    return 1;
}

static __always_inline gil_trace_event_data_t *new_trace_event() {
    __u32 zero = 0;
    gil_trace_event_data_t *evt;

    evt = (gil_trace_event_data_t *)bpf_map_lookup_elem(&event_stash_heap, &zero);
    if (evt) {
        __builtin_memset(evt, 0, sizeof(*evt));
    }
    return evt;
}

static __always_inline void init_gil_data(gil_data_t *gil_d, gil_m_enter_t *gil_enter, const char *name) {
    gil_d->start_time = gil_enter->start_time;
    gil_d->end_time = gil_enter->end_time;
    gil_d->duration = gil_enter->end_time - gil_enter->start_time;
    gil_d->id = gil_enter->key.id;
    __builtin_memcpy(gil_d->name, name, sizeof(gil_d->name));
}

static __always_inline void init_trace_event_common(gil_trace_event_data_t *evt_data, trace_event_type_t type) {
    __u64 ptid = bpf_get_current_pid_tgid();

    evt_data->type = type;
    evt_data->tid = (__u32)ptid;
    evt_data->pid = (__u32)(ptid >> 32);
    (void)bpf_get_current_comm(evt_data->comm, sizeof(evt_data->comm));
}

static __always_inline gil_trace_event_data_t *create_gil_event(gil_m_enter_t *gil_enter, const char *name) {
    gil_trace_event_data_t *evt_data;

    evt_data = new_trace_event();
    if (!evt_data) {
        return NULL;
    }
    init_trace_event_common(evt_data, EVT_TYPE_GIL);
    init_gil_data(&evt_data->gil_d, gil_enter, name);

    return evt_data;
}

static inline long bpfbuf_output(void *ctx, void *map, void *buf, __u64 size) {
    return bpf_ringbuf_output(map, buf, size, 0);
}

static __always_inline void emit_gil_event(gil_m_enter_t *gil_enter, const char *name, void *ctx) {
    gil_trace_event_data_t *evt_data = create_gil_event(gil_enter, name);

    if (!evt_data) {
        return;
    }
    
    bpfbuf_output(ctx, &event_map, evt_data, sizeof(gil_trace_event_data_t));
}

static __always_inline void enter_gil_event(int id) {
    __u32 switch_key = 1;
    if (!trace_cfg_enabled(switch_key)) {
        return;
    }
    
    gil_m_enter_t enter;
    __u64 ptid = bpf_get_current_pid_tgid();

    __builtin_memset(&enter, 0, sizeof(enter));
    enter.key.pid = (int)ptid;
    enter.key.id = id;
    enter.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&gil_enter_map, &enter.key, &enter, BPF_ANY);
}

static __always_inline void exit_gil_event(int id, const char *name, void *ctx) {
    __u32 switch_key = 1;
    if (!trace_cfg_enabled(switch_key)) {
        gil_m_key_t gil_key = {0};
        __u32 pid = bpf_get_current_pid_tgid();
        gil_key.pid = pid;
        gil_key.id = id;
        bpf_map_delete_elem(&gil_enter_map, &gil_key);
        return;
    }
    
    gil_m_enter_t *enter;
    gil_m_key_t key = {0};
    __u32 pid = bpf_get_current_pid_tgid();

    key.pid = pid;
    key.id = id;
    enter = (gil_m_enter_t *)bpf_map_lookup_elem(&gil_enter_map, &key);
    if (!enter) {
        return;
    }
    
    enter->end_time = bpf_ktime_get_ns();
    emit_gil_event(enter, name, ctx);
    
    (void)bpf_map_delete_elem(&gil_enter_map, &key);
}

bpf_section("uprobe") int handle_take_gil_enter(struct pt_regs *ctx) {
    enter_gil_event(GIL_TAKE_ID);
    return 0;
}

bpf_section("uretprobe") int handle_take_gil_exit(struct pt_regs *ctx) {
    exit_gil_event(GIL_TAKE_ID, "take_gil", ctx);
    return 0;
}

bpf_section("uprobe") int handle_drop_gil_enter(struct pt_regs *ctx) {
    enter_gil_event(GIL_DROP_ID);
    return 0;
}

bpf_section("uretprobe") int handle_drop_gil_exit(struct pt_regs *ctx) {
    exit_gil_event(GIL_DROP_ID, "drop_gil", ctx);
    return 0;
}

char LICENSE[] bpf_section("license") = "GPL";