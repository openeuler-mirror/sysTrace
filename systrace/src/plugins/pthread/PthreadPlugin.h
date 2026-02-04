#ifndef PTHREAD_SYNC_PLUGIN_H
#define PTHREAD_SYNC_PLUGIN_H

#include "../../../include/common/ICollector.hpp"
#include "../../../include/common/constant.h"
#include "../../../include/utils/ElfUtils.hpp"
#include "../../../include/utils/FileWriterUtil.hpp"
#include "../../../include/utils/PluginUtils.hpp"
#include "../../../include/utils/TimeUtil.hpp"
#include "../../../include/utils/TimerManager.hpp"
#include "../../../include/utils/util.h"
#include "../ebpfPluginBase/EbpfCollectorBase.h"
#include <atomic>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <elfutils/libdwfl.h>
#include <fcntl.h>
#include <gelf.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#define PTHREAD_MUTEX_LOCK_ID 1
#define PTHREAD_MUTEX_TIMEDLOCK_ID 2
#define PTHREAD_MUTEX_TRYLOCK_ID 3
#define PTHREAD_RWLOCK_RDLOCK_ID 4
#define PTHREAD_RWLOCK_WRLOCK_ID 5
#define PTHREAD_RWLOCK_TIMEDRDLOCK_ID 6
#define PTHREAD_RWLOCK_TIMEDWRLOCK_ID 7
#define PTHREAD_RWLOCK_TRYRDLOCK_ID 8
#define PTHREAD_RWLOCK_TRYWRLOCK_ID 9
#define PTHREAD_SPIN_LOCK_ID 10
#define PTHREAD_SPIN_TRYLOCK_ID 11
#define SEM_WAIT_ID 12
#define SEM_TIMEDWAIT_ID 13
#define SEM_TRYWAIT_ID 14
#define MAP_HOOK_PID_PATH "/sys/fs/bpf/sysTrace/__osprobe_rank_pid"
#define PROC_FILTER_RANK_MAP_PATH "/sys/fs/bpf/sysTrace/__osprobe_proc_filter"
#ifndef PTHREAD_SYNC_COMMON_TYPES
#define PTHREAD_SYNC_COMMON_TYPES

typedef uint32_t u32;
typedef uint64_t u64;

typedef struct {
    int pid;
    int id;
} pthrd_m_key_t;

struct trace_setting_t {
    u64 min_exec_dur;
};

struct proc_s {
    u32 proc_id;
};

struct obj_ref_s {
    u32 count;
};

typedef enum {
    EVT_TYPE_PTHREAD = 1,
} trace_event_type_t;

typedef struct {
    u64 start_time;
    u64 end_time;
    u64 duration;
    int id;
} __attribute__((aligned(8))) pthrd_data_t;

typedef struct {
    int pid;
    int tid;
    char comm[16];
    trace_event_type_t type;
    union {
        pthrd_data_t pthrd_d;
    };
} pthread_trace_event_data_t;

#endif

using PluginNameType = systrace::constant::Plugin;

namespace {
struct PthreadHook {
    int id;
    const char *func_name;
    struct bpf_program *enter_prog;
    struct bpf_program *exit_prog;
};
} // namespace

class PthreadPlugin : public EbpfCollectorBase, public ICollector {
  public:
    PthreadPlugin();

    ~PthreadPlugin();

    bool start(const json &params, int duration) override;

    void stop() override;

  private:
    struct pthrd_sync_bpf *bpf_skeleton_ = nullptr;
    std::thread poll_thread_;
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
    FILE *trace_output_stream_ = nullptr;
    bool first_event_ = true;
    std::unordered_map<int, int> host_pid_to_rank_mapping_;
    std::string output_;
    std::vector<struct bpf_link *> links_;
    systrace::fileWriterUtil::strbuf_t json_buf_;
    struct ring_buffer *rb_;
    std::mutex rb_mutex_;

    std::vector<PthreadHook> get_hook_list();
    void attach_all_probes(std::vector<int> pids, const char *path);
    static const char *get_pthread_func_name(int id);
    void poll_loop();
    void init_trace_setting_t(const json &params);
    void cleanup_skel();
    static int handle_event(void *ctx, void *data, size_t data_sz);
    void process_raw_event(pthread_trace_event_data_t *ev);
    void clear_pthrd_maps();
    void clean_ringbuffer();
};

#endif