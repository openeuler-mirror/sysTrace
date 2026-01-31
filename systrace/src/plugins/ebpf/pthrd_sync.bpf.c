#include "../../os/common.h"
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
enum {
    PTHREAD_UNKNOWN_ID = 0,
    PTHREAD_MUTEX_LOCK_ID,
    PTHREAD_MUTEX_TIMEDLOCK_ID,
    PTHREAD_MUTEX_TRYLOCK_ID,
    PTHREAD_RWLOCK_RDLOCK_ID,
    PTHREAD_RWLOCK_WRLOCK_ID,
    PTHREAD_RWLOCK_TIMEDRDLOCK_ID,
    PTHREAD_RWLOCK_TIMEDWRLOCK_ID,
    PTHREAD_RWLOCK_TRYRDLOCK_ID,
    PTHREAD_RWLOCK_TRYWRLOCK_ID,
    PTHREAD_SPIN_LOCK_ID,
    PTHREAD_SPIN_TRYLOCK_ID,
    PTHREAD_TIMEDJOIN_NP_ID,
    PTHREAD_TRYJOIN_NP_ID,
    PTHREAD_YIELD_ID,
    SEM_TIMEDWAIT_ID,
    SEM_TRYWAIT_ID,
    SEM_WAIT_ID,
    PTHREAD_MAX_ID
};

#define PTHREAD_MUTEX_LOCK_NAME         "pthread_mutex_lock"
#define PTHREAD_MUTEX_TIMEDLOCK_NAME    "pthread_mutex_timedlock"
#define PTHREAD_MUTEX_TRYLOCK_NAME      "pthread_mutex_trylock"
#define PTHREAD_RWLOCK_RDLOCK_NAME      "pthread_rwlock_rdlock"
#define PTHREAD_RWLOCK_WRLOCK_NAME      "pthread_rwlock_wrlock"
#define PTHREAD_RWLOCK_TIMEDRDLOCK_NAME "pthread_rwlock_timedrdlock"
#define PTHREAD_RWLOCK_TIMEDWRLOCK_NAME "pthread_rwlock_timedwrlock"
#define PTHREAD_RWLOCK_TRYRDLOCK_NAME   "pthread_rwlock_tryrdlock"
#define PTHREAD_RWLOCK_TRYWRLOCK_NAME   "pthread_rwlock_trywrlock"
#define PTHREAD_SPIN_LOCK_NAME          "pthread_spin_lock"
#define PTHREAD_SPIN_TRYLOCK_NAME       "pthread_spin_trylock"
#define PTHREAD_TIMEDJOIN_NP_NAME       "pthread_timedjoin_np"
#define PTHREAD_TRYJOIN_NP_NAME         "pthread_tryjoin_np"
#define PTHREAD_YIELD_NAME              "pthread_yield"
#define SEM_TIMEDWAIT_NAME              "sem_timedwait"
#define SEM_TRYWAIT_NAME                "sem_trywait"
#define SEM_WAIT_NAME                   "sem_wait"

#define INT_LEN                 32
#define MAX_SIZE_OF_PROC    128
#define MAX_SIZE_OF_THREAD  (128 * MAX_SIZE_OF_PROC)
#define THREAD_COMM_LEN     16
#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH    127
#endif
#define bpf_section(NAME) __attribute__((section(NAME), used))

struct proc_s {
    unsigned int proc_id;
};

typedef struct {
    __u64 min_exec_dur;
} trace_setting_t;

typedef struct {
    int pid;
    int id;
} pthrd_m_key_t;

typedef struct {
    pthrd_m_key_t key;
    __u64 start_time;
    __u64 end_time;
} pthrd_m_enter_t;

typedef enum {
    EVT_TYPE_PTHREAD = 1,
} trace_event_type_t;

typedef struct {
    __u64 start_time;
    __u64 end_time;
    __u64 duration;
    int id;
} pthrd_data_t;

typedef struct {
    int pid;
    int tid;
    char comm[THREAD_COMM_LEN];
    trace_event_type_t type;
    union {
        pthrd_data_t pthrd_d;
    };
} pthread_trace_event_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(trace_setting_t));
    __uint(max_entries, 1);
} setting_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64);
} event_map_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(pthread_trace_event_data_t));
    __uint(max_entries, 1);
} event_stash_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(pthrd_m_key_t));
    __uint(value_size, sizeof(pthrd_m_enter_t));
    __uint(max_entries, MAX_SIZE_OF_THREAD);
} pthrd_enter_map SEC(".maps");


static __always_inline trace_setting_t *get_trace_setting()
{
    trace_setting_t *setting;
    __u32 zero = 0;

    setting = (trace_setting_t *)bpf_map_lookup_elem(&setting_map, &zero);
    return setting;
}

static __always_inline pthread_trace_event_data_t *new_trace_event()
{
    __u32 zero = 0;
    pthread_trace_event_data_t *evt;

    evt = (pthread_trace_event_data_t *)bpf_map_lookup_elem(&event_stash_heap, &zero);
    if (evt) {
        __builtin_memset(evt, 0, sizeof(*evt));
    }
    return evt;
}

static __always_inline void init_pthrd_data(pthrd_data_t *pthrd_d, pthrd_m_enter_t *pthrd_enter, void *ctx)
{
    pthrd_d->start_time = pthrd_enter->start_time;
    pthrd_d->end_time = pthrd_enter->end_time;
    pthrd_d->duration = pthrd_enter->end_time - pthrd_enter->start_time;
    pthrd_d->id = pthrd_enter->key.id;
}
static __always_inline __maybe_unused void init_trace_event_common(pthread_trace_event_data_t *evt_data, trace_event_type_t type)
{
    __u64 ptid = bpf_get_current_pid_tgid();

    evt_data->type = type;
    evt_data->tid = (__u32)ptid;
    evt_data->pid = (__u32)(ptid >> INT_LEN);
    (void)bpf_get_current_comm(evt_data->comm, sizeof(evt_data->comm));
}

static __always_inline pthread_trace_event_data_t *create_pthrd_event(pthrd_m_enter_t *pthrd_enter, void *ctx)
{
    pthread_trace_event_data_t *evt_data;

    evt_data = new_trace_event();
    if (!evt_data) {
    return NULL;
    }
    init_trace_event_common(evt_data, EVT_TYPE_PTHREAD);
    init_pthrd_data(&evt_data->pthrd_d, pthrd_enter, ctx);

    return evt_data;
}
static inline long bpfbuf_output(void *ctx, void *map, void *buf, __u64 size)
{
    return bpf_ringbuf_output(map, buf, size, 0);
}

static __always_inline void emit_incomming_pthrd_event(pthrd_m_enter_t *pthrd_enter, void *ctx)
{
    pthread_trace_event_data_t *evt_data = create_pthrd_event(pthrd_enter, ctx);
    void *cur_event_map;

    if (!evt_data) {
        return;
    }
    cur_event_map = (void *)&event_map_a;
    if (cur_event_map) {
        bpfbuf_output(ctx, cur_event_map, evt_data, sizeof(pthread_trace_event_data_t));
    }
}

static __always_inline void enter_pthrd_event(int id)
{
    pthrd_m_enter_t enter;
    __u64 ptid = bpf_get_current_pid_tgid();

    __builtin_memset(&enter, 0, sizeof(enter));
    enter.key.pid = (int)ptid;
    enter.key.id = id;
    enter.start_time = bpf_ktime_get_ns();
    (void)bpf_map_update_elem(&pthrd_enter_map, &enter.key, &enter, BPF_ANY);
    return;
}

static __always_inline void exit_pthrd_event(int id, void *ctx)
{
    pthrd_m_enter_t *enter;
    pthrd_m_key_t key = {0};
    __u32 pid = bpf_get_current_pid_tgid();
    trace_setting_t *setting;

    key.pid = pid;
    key.id = id;
    enter = (pthrd_m_enter_t *)bpf_map_lookup_elem(&pthrd_enter_map, &key);
    if (!enter) {
        return;
    }
    setting = get_trace_setting();
    if (!setting) {
        goto out;
    }
    enter->end_time = bpf_ktime_get_ns();
    if (enter->end_time < enter->start_time + setting->min_exec_dur) {
        goto out;
    }
    emit_incomming_pthrd_event(enter, ctx);
    out:
    (void)bpf_map_delete_elem(&pthrd_enter_map, &key);
    return;
}

#define UPROBE(func, type) \
    bpf_section("uprobe") \
    int ubpf_##func(struct type *ctx)

#define URETPROBE(func, type) \
    bpf_section("uretprobe") \
    int ubpf_ret_##func(struct type *ctx)

#define UP_PTHREAD_ENTER(name, id) \
    UPROBE(name, pt_regs) \
    { \
        enter_pthrd_event(id); \
        return 0; \
    } \

#define UP_PTHREAD_EXIT(name, id) \
    URETPROBE(name, pt_regs) \
    { \
        exit_pthrd_event(id, ctx); \
        return 0; \
    } \

#define UP_PTHREAD(name, id) \
    UP_PTHREAD_ENTER(name, id); \
    UP_PTHREAD_EXIT(name, id)

/* start bpf prog definition */

UP_PTHREAD(pthread_mutex_lock, PTHREAD_MUTEX_LOCK_ID);
UP_PTHREAD(pthread_mutex_timedlock, PTHREAD_MUTEX_TIMEDLOCK_ID);
UP_PTHREAD(pthread_mutex_trylock, PTHREAD_MUTEX_TRYLOCK_ID);
UP_PTHREAD(pthread_rwlock_rdlock, PTHREAD_RWLOCK_RDLOCK_ID);
UP_PTHREAD(pthread_rwlock_wrlock, PTHREAD_RWLOCK_WRLOCK_ID);
UP_PTHREAD(pthread_rwlock_timedrdlock, PTHREAD_RWLOCK_TIMEDRDLOCK_ID);
UP_PTHREAD(pthread_rwlock_timedwrlock, PTHREAD_RWLOCK_TIMEDWRLOCK_ID);
UP_PTHREAD(pthread_rwlock_tryrdlock, PTHREAD_RWLOCK_TRYRDLOCK_ID);
UP_PTHREAD(pthread_rwlock_trywrlock, PTHREAD_RWLOCK_TRYWRLOCK_ID);
UP_PTHREAD(pthread_spin_lock, PTHREAD_SPIN_LOCK_ID);
UP_PTHREAD(pthread_spin_trylock, PTHREAD_SPIN_TRYLOCK_ID);
UP_PTHREAD(pthread_timedjoin_np, PTHREAD_TIMEDJOIN_NP_ID);
UP_PTHREAD(pthread_tryjoin_np, PTHREAD_TRYJOIN_NP_ID);
UP_PTHREAD(pthread_yield, PTHREAD_YIELD_ID);
UP_PTHREAD(sem_timedwait, SEM_TIMEDWAIT_ID);
UP_PTHREAD(sem_trywait, SEM_TRYWAIT_ID);
UP_PTHREAD(sem_wait, SEM_WAIT_ID);

/* end bpf prog definition */

char g_license[] SEC("license") = "GPL";