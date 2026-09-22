#include "GilPlugin.h"
#include "../../../include/common/constant.h"
#include "../ebpf/python_gil.skel.h"

#define MAP_HOOK_PID_PATH "/sys/fs/bpf/sysTrace/__osprobe_rank_pid"
#define PROC_FILTER_RANK_MAP_PATH "/sys/fs/bpf/sysTrace/__osprobe_proc_filter"
#define GIL_TRACE_CFG_MAP_PATH "/sys/fs/bpf/sysTrace/__osprobe_gil_trace_cfg"
#define GET_HOOK_PID_COUNT 20
#define TRACE_CFG_GIL 1

const int MAP_READY_TIMEOUT_S = 30;
const int MAP_INIT_TIMEOUT_S = 5;

extern "C" char g_python_lib_path[512];
extern "C" pid_t g_hooked_pid;

typedef enum {
    EVT_TYPE_GIL = 1,
} trace_event_type_t;

typedef struct {
    int pid;
    int id;
} gil_m_key_t;

typedef struct {
    unsigned long long start_time;
    unsigned long long end_time;
    unsigned long long duration;
    int id;
    char name[16];
} gil_data_t;

typedef struct {
    int pid;
    int tid;
    char comm[16];
    trace_event_type_t type;
    union {
        gil_data_t gil_d;
    };
} gil_trace_event_data_t;

GILPlugin::GILPlugin() {
    pluginName_ = PluginNameType::PYTHON_GIL_PLUGIN.data();
    if (is_main_process()) {
        set_memlock_rlimit(EBPF_RLIM_LIMITED);
        bpf_skeleton_ = python_gil_bpf__open_and_load();
        if (!bpf_skeleton_) {
            LOG_MODULE(ERROR, pluginName_) << "skel load error";
            return;
        }

        std::string dir = std::string(get_sys_trace_root_dir()) + pluginName_;
        systrace::util::fs_utils::CreateDirectoryIfNotExists(dir);
        output_ = dir + "/" + get_id() + "_" + std::to_string(g_hooked_pid) +
                  "_rank_" + std::to_string(get_local_rank()) + ".json";

        int ret =
            bpf_map__pin(bpf_skeleton_->maps.rank_pid_map, MAP_HOOK_PID_PATH);
        if (ret) {
            LOG_MODULE(ERROR, pluginName_) << "init hook map error";
        }

        // Pin gil_trace_cfg_map for controlling GIL trace
        struct bpf_map *trace_cfg_map = bpf_skeleton_->maps.gil_trace_cfg_map;
        if (trace_cfg_map) {
            ret = bpf_map__pin(trace_cfg_map, GIL_TRACE_CFG_MAP_PATH);
            if (ret) {
                LOG_MODULE(ERROR, pluginName_)
                    << "Failed to pin gil_trace_cfg_map";
            } else {
                LOG_MODULE(DEBUG, pluginName_)
                    << "Pinned gil_trace_cfg_map to " << GIL_TRACE_CFG_MAP_PATH;
            }
        }
    }
    register_target_process_to_bpf();
}

GILPlugin::~GILPlugin() {
    if (is_main_process()) {
        if (bpf_skeleton_) {
            python_gil_bpf__destroy(bpf_skeleton_);
            bpf_skeleton_ = nullptr;
        }
        if (access(MAP_HOOK_PID_PATH, F_OK) == 0) {
            int ret = unlink(MAP_HOOK_PID_PATH);
            if (ret) {
                LOG_MODULE(ERROR, pluginName_)
                    << "unlink pin file error, path=" << MAP_HOOK_PID_PATH;
            }
        }

        // Clean up gil_trace_cfg_map pin file
        if (access(GIL_TRACE_CFG_MAP_PATH, F_OK) == 0) {
            int ret = unlink(GIL_TRACE_CFG_MAP_PATH);
            if (ret) {
                LOG_MODULE(ERROR, pluginName_)
                    << "unlink pin file error, path=" << GIL_TRACE_CFG_MAP_PATH;
            } else {
                LOG_MODULE(DEBUG, pluginName_)
                    << "Unlinked gil_trace_cfg_map pin file";
            }
        }
    }
}

bool GILPlugin::start(const json &params, int duration) {
    if (!is_main_process()) {
        return true;
    }
    bool expected = false;
    if (!active_.compare_exchange_strong(expected, true))
        return true;

    // Get the mapping relationship between AI process IDs (host pid) and ranks.
    // If the pid-to-rank map is empty, initialize it by setting rank-pid
    // mapping.
    if (host_pid_to_rank_mapping_.empty()) {
        host_pid_to_rank_mapping_ = init_pid_to_rank_map();
    }

    if (!bpf_skeleton_) {
        LOG_MODULE(ERROR, pluginName_) << "Skeleton is null, stop";
        stop();
        return false;
    } else {
        clean_ringbuffer();
        clear_gil_maps();
    }
    std::vector<int> pids = get_trace_pids(params);

    if (pids.empty()) {
        LOG_MODULE(ERROR, pluginName_) << "No valid PID found (params + map)";
        active_.store(false);
        return false;
    }

    std::string libpython_path = auto_find_libpython();
    if (libpython_path.empty()) {
        LOG_MODULE(ERROR, pluginName_) << "libpython not found";
        active_.store(false);
        return false;
    }
    first_event_ = true;

    trace_output_stream_ = fopen(output_.c_str(), "w");
    if (!trace_output_stream_) {
        LOG_MODULE(ERROR, pluginName_)
            << "Failed to open output file: " << output_
            << " error: " << strerror(errno);
        active_.store(false);
        return false;
    }

    systrace::fileWriterUtil::strbuf_init(&json_buf_, BUF_CHUNK_SIZE,
                                          trace_output_stream_);
    if (!json_buf_.buf) {
        LOG_MODULE(ERROR, pluginName_) << "Init buffer failed";
        fclose(trace_output_stream_);
        trace_output_stream_ = nullptr;
        active_.store(false);
        return false;
    }

    fprintf(trace_output_stream_, "[\n");

    attach_all_probes(pids, libpython_path);

    poll_thread_ = std::thread(&GILPlugin::consume_perf_events, this);

    // 启用GIL事件采集开关
    set_gil_trace_enabled(true);

    if (duration > 0) {
        systrace::utils::TimerManager::getInstance().startTimer(
            get_id(), duration, [this]() { this->stop(); });
    }
    LOG_MODULE(INFO, pluginName_) << "Output file: " << output_;
    return true;
}

void GILPlugin::stop() {
    if (!is_main_process())
        return;

    if (stop_latched_.test_and_set(std::memory_order_acquire)) {
        return;
    }

    // 禁用GIL事件采集开关
    set_gil_trace_enabled(false);
    if (active_.load()) {
        LOG_MODULE(INFO, pluginName_) << "trace stop.";
        active_.store(false);
        if (poll_thread_.joinable())
            poll_thread_.join();
        cleanup_skel();
        clear_gil_maps();
        {
            std::lock_guard<std::mutex> lock(rb_mutex_);
            if (rb_) {
                while (ring_buffer__poll(rb_, 0) > 0)
                    ;
                ring_buffer__free(rb_);
                rb_ = nullptr;
            }
        }

        if (trace_output_stream_) {
            LOG_MODULE(DEBUG, pluginName_) << "Finalizing output file...";
            systrace::fileWriterUtil::strbuf_flush(&json_buf_);
            systrace::fileWriterUtil::strbuf_destroy(&json_buf_);
            fprintf(trace_output_stream_, "\n]\n");
            if (fclose(trace_output_stream_) != 0) {
                LOG_MODULE(DEBUG, pluginName_)
                    << "Failed to close JSON file: " << strerror(errno);
            } else {
                LOG_MODULE(DEBUG, pluginName_) << "JSON file synced and closed";
            }
            trace_output_stream_ = nullptr;
        }

        systrace::utils::TimerManager::getInstance().stopTimer(get_id());
    }
    stop_latched_.clear(std::memory_order_release);
}
void GILPlugin::cleanup_skel() {
    for (auto link : links_) {
        if (link) {
            bpf_link__destroy(link);
        }
    }
    links_.clear();

    if (bpf_skeleton_) {
        python_gil_bpf__detach(bpf_skeleton_);
    }
}
void GILPlugin::register_target_process_to_bpf() {
    int hook_pid_fd = -1;
    int count = GET_HOOK_PID_COUNT;
    while (count--) {
        hook_pid_fd = bpf_obj_get(MAP_HOOK_PID_PATH);
        if (hook_pid_fd > 0)
            break;
        usleep(50000);
    }
    if (hook_pid_fd < 0) {
        LOG_MODULE(ERROR, pluginName_)
            << " Failed to get bpf prog hook pid map: " << strerror(errno);
        return;
    }

    int update_ret =
        bpf_map_update_elem(hook_pid_fd, &g_hooked_pid, &g_hooked_pid, BPF_ANY);
    if (update_ret < 0) {
        LOG_MODULE(ERROR, pluginName_)
            << " Failed to update map: " << strerror(errno);
        close(hook_pid_fd);
        return;
    }

    LOG_MODULE(INFO, pluginName_)
        << "Write pid " << g_hooked_pid << " to map success";

    close(hook_pid_fd);
}

void GILPlugin::clean_ringbuffer() {
    struct ring_buffer *temp_rb = ring_buffer__new(
        bpf_map__fd(bpf_skeleton_->maps.event_map),
        [](void *, void *, size_t) { return 0; }, nullptr, nullptr);
    if (temp_rb) {
        while (ring_buffer__poll(temp_rb, 0) > 0)
            ;
        ring_buffer__free(temp_rb);
    }
}

void GILPlugin::clear_gil_maps() {
    if (!bpf_skeleton_) {
        return;
    }

    struct bpf_map *enter_map = bpf_skeleton_->maps.gil_enter_map;
    if (!enter_map) {
        return;
    }

    int fd = bpf_map__fd(enter_map);
    if (fd <= 0) {
        return;
    }

    gil_m_key_t key = {0};
    gil_m_key_t next_key;
    int delete_count = 0;

    bool has_key = (bpf_map_get_next_key(fd, NULL, &next_key) == 0);
    while (has_key) {
        key = next_key;
        has_key = (bpf_map_get_next_key(fd, &key, &next_key) == 0);

        if (bpf_map_delete_elem(fd, &key) == 0) {
            delete_count++;
        }
    }

    if (delete_count > 0) {
        LOG_MODULE(DEBUG, pluginName_)
            << "Cleared " << delete_count
            << " residual entries from gil_enter_map";
    }
}

void GILPlugin::set_gil_trace_enabled(bool enabled) {
    struct bpf_map *gil_trace_cfg_map = bpf_skeleton_->maps.gil_trace_cfg_map;
    if (gil_trace_cfg_map) {
        int trace_cfg_fd = bpf_map__fd(gil_trace_cfg_map);
        if (trace_cfg_fd >= 0) {
            u32 key = TRACE_CFG_GIL;
            u32 value = enabled ? 1 : 0;
            bpf_map_update_elem(trace_cfg_fd, &key, &value, BPF_ANY);
            LOG_MODULE(DEBUG, pluginName_)
                << "GIL trace " << (enabled ? "enabled" : "disabled");
        } else {
            LOG_MODULE(WARN, pluginName_)
                << "Failed to get gil_trace_cfg_map fd: " << strerror(errno);
        }
    } else {
        LOG_MODULE(WARN, pluginName_)
            << "gil_trace_cfg_map not found in skeleton";
    }
}
void GILPlugin::consume_perf_events() {
    struct ring_buffer *local_rb = nullptr;

    if (!bpf_skeleton_) {
        LOG_MODULE(ERROR, pluginName_) << "Skeleton is null, poll loop exit";
        return;
    }

    local_rb = ring_buffer__new(
        bpf_map__fd(bpf_skeleton_->maps.event_map),
        [](void *ctx, void *data, size_t size) {
            auto *plugin = static_cast<GILPlugin *>(ctx);
            if (plugin->active_.load()) {
                plugin->process_raw_event(data);
            }
            return 0;
        },
        this, nullptr);

    if (!local_rb) {
        LOG_MODULE(ERROR, pluginName_)
            << "Create ringbuf failed: " << strerror(errno);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(rb_mutex_);
        rb_ = local_rb;
    }

    while (active_.load()) {
        ring_buffer__poll(local_rb, 50);
    }

    // 清理资源
    {
        std::lock_guard<std::mutex> lock(rb_mutex_);
        rb_ = nullptr;
    }
    ring_buffer__free(local_rb);

    LOG_MODULE(DEBUG, pluginName_) << "Poll loop exited normally";
}

void GILPlugin::process_raw_event(void *data) {

    gil_trace_event_data_t *e = (gil_trace_event_data_t *)data;

    if (!trace_output_stream_ || !json_buf_.buf) {
        return;
    }
    // 优化缓冲区管理，确保有足够空间写入事件
    size_t remaining = json_buf_.total_size - json_buf_.used_size;
    // 当剩余空间小于事件估计大小时，先flush确保有足够空间
    if (remaining < 512) {
        systrace::fileWriterUtil::strbuf_flush(&json_buf_);
        remaining = json_buf_.total_size - json_buf_.used_size;
    }

    char *write_ptr = json_buf_.buf + json_buf_.used_size;
    int ret = 0;

    if (!first_event_) {
        ret = snprintf(write_ptr, remaining, ",\n");
        if (ret < 0 || ret >= static_cast<int>(remaining)) {
            LOG_MODULE(ERROR, pluginName_) << "Buffer overflow (separator)";
            return;
        }
        systrace::fileWriterUtil::strbuf_update_offset(&json_buf_, ret);
        write_ptr += ret;
        remaining -= ret;
    }

    std::string rank_str = "";
    if (host_pid_to_rank_mapping_.find(e->pid) !=
        host_pid_to_rank_mapping_.end()) {
        rank_str = std::to_string(host_pid_to_rank_mapping_[e->pid]);
    } else {
        rank_str = std::to_string(e->pid);
    }

    std::string tid_str =
        std::string(pluginName_) + "_" + std::to_string(e->tid);

    uint64_t start_time_us =
        systrace::util::time::MonotonicNsToUtcUs(e->gil_d.start_time);
    double duration_us = (double)e->gil_d.duration / 1000.0;

    ret = snprintf(write_ptr, remaining,
                   "  {\"name\": \"%s\", \"ph\": \"X\", \"ts\": %lu, "
                   "\"dur\": %.3f, \"pid\": \"%s\", \"tid\": \"%s\"}",
                   e->gil_d.name, start_time_us, duration_us, rank_str.c_str(),
                   tid_str.c_str());

    if (ret < 0 || ret >= static_cast<int>(remaining)) {
        LOG_MODULE(ERROR, pluginName_) << "Buffer overflow (event data)";
        return;
    }

    systrace::fileWriterUtil::strbuf_update_offset(&json_buf_, ret);
    first_event_ = false;

    if (json_buf_.used_size >= json_buf_.chunk_size) {
        systrace::fileWriterUtil::strbuf_flush(&json_buf_);
    }
}

std::string GILPlugin::auto_find_libpython() { return g_python_lib_path; }

bool GILPlugin::try_bind_uprobe(struct bpf_program *prog, int pid,
                                const std::string &path,
                                const std::vector<std::string> &funcs,
                                bool is_ret) {

    for (const auto &func : funcs) {
        unsigned long off = systrace::elfutils::ElfUtils::find_function_offset(
            path.c_str(), func.c_str());
        if (off > 0) {
            struct bpf_link *link = bpf_program__attach_uprobe(
                prog, is_ret, pid, path.c_str(), off);
            if (link) {
                std::lock_guard<std::mutex> lock(link_mutex_);
                links_.push_back(link);
                LOG_MODULE(DEBUG, pluginName_)
                    << "Attached uprobe: PID=" << pid << ", func=" << func
                    << ", is_ret=" << is_ret << ", offset=0x" << std::hex << off
                    << std::dec;
                return true;
            } else {
                LOG_MODULE(WARN, pluginName_)
                    << "Failed to attach uprobe: PID=" << pid
                    << ", func=" << func << ", is_ret=" << is_ret
                    << ", error=" << strerror(errno);
            }
        }
    }
    return false;
}

void GILPlugin::attach_all_probes(std::vector<int> pids,
                                  const std::string &path) {
    if (!bpf_skeleton_) {
        LOG_MODULE(ERROR, pluginName_)
            << "Invalid skeleton, skip attach probes";
        return;
    }

    for (int i = 0; i < pids.size(); i++) {
        if (!try_bind_uprobe(bpf_skeleton_->progs.handle_take_gil_enter,
                             pids[i], path, gil_acquire_symbols, false)) {
            LOG_MODULE(ERROR, pluginName_)
                << "Process(pid=" << pids[i]
                << ") Failed to attach Take GIL Enter probes";
        }
        if (!try_bind_uprobe(bpf_skeleton_->progs.handle_take_gil_exit, pids[i],
                             path, gil_acquire_symbols, true)) {
            LOG_MODULE(ERROR, pluginName_)
                << "Process(pid=" << pids[i]
                << ") Failed to attach Take GIL Exit probes";
        }
        if (!try_bind_uprobe(bpf_skeleton_->progs.handle_drop_gil_enter,
                             pids[i], path, gil_release_symbols, false)) {
            LOG_MODULE(ERROR, pluginName_)
                << "Process(pid=" << pids[i]
                << ") Failed to attach Drop GIL Enter probes";
        }
        if (!try_bind_uprobe(bpf_skeleton_->progs.handle_drop_gil_exit, pids[i],
                             path, gil_release_symbols, true)) {
            LOG_MODULE(ERROR, pluginName_)
                << "Process(pid=" << pids[i]
                << ") Failed to attach Drop GIL Exit probes";
        }
    }
}