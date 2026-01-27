#include "PthreadPlugin.h"
#include "../../../include/utils/TimeUtil.hpp"

static const char *names[] = {"UNKNOWN",
                              "pthread_mutex_lock",
                              "pthread_mutex_timedlock",
                              "pthread_mutex_trylock",
                              "pthread_rwlock_rdlock",
                              "pthread_rwlock_wrlock",
                              "pthread_rwlock_timedrdlock",
                              "pthread_rwlock_timedwrlock",
                              "pthread_rwlock_tryrdlock",
                              "pthread_rwlock_trywrlock",
                              "pthread_spin_lock",
                              "pthread_spin_trylock",
                              "pthread_timedjoin_np",
                              "pthread_tryjoin_np",
                              "pthread_yield",
                              "sem_timedwait",
                              "sem_trywait",
                              "sem_wait"};
const size_t BUF_CHUNK_SIZE = 64 * 1024;
extern "C" char g_libc_path[512];
extern "C" pid_t g_hooked_pid;

PthreadPlugin::PthreadPlugin() {
    pluginName_ = PluginNameType::PTHREAD_LOCK_PLUGIN.data();
    if (is_main_process()) {

        bpf_skeleton_ = pthrd_sync_bpf__open_and_load();
        if (!bpf_skeleton_) {
            LOG_MODULE(ERROR, pluginName_) << "skel load error";
            return;
        }
        std::string dir = std::string(SYS_TRACE_ROOT_DIR) + pluginName_;
        mkdir(dir.c_str(), 0755);
        output_ = dir + "/" + get_id() + "_" + std::to_string(g_hooked_pid) +
                  "_rank_" + std::to_string(get_local_rank()) + ".json";
    }
}

PthreadPlugin::~PthreadPlugin() {
    if (is_main_process()) {
        if (bpf_skeleton_) {
            pthrd_sync_bpf__destroy(bpf_skeleton_);
            bpf_skeleton_ = nullptr;
        }
    }
}

bool PthreadPlugin::start(const json &params, int duration) {
    if (get_local_rank() != 0) {
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
    }

    std::vector<int> pids = get_trace_pids(params);

    if (pids.empty()) {
        LOG_MODULE(ERROR, pluginName_) << "No valid PID found (params + map)";
        active_.store(false);
        return false;
    }

    first_event_ = true;

    trace_output_stream_ = fopen(output_.c_str(), "w");

    systrace::fileWriterUtil::strbuf_init(&json_buf_, BUF_CHUNK_SIZE,
                                          trace_output_stream_);
    if (!json_buf_.buf) {
        LOG_MODULE(ERROR, pluginName_) << "Init buffer failed";
        fclose(trace_output_stream_);
        trace_output_stream_ = nullptr;
        active_.store(false);
        return false;
    }
    fprintf(trace_output_stream_, "{\"traceEvents\": [\n");

    init_trace_setting_t(params);

    LOG_MODULE(DEBUG, pluginName_) << "libc_path = " << g_libc_path;

    clear_pthrd_maps();

    attach_all_probes(pids, g_libc_path);

    poll_thread_ = std::thread(&PthreadPlugin::poll_loop, this);

    if (duration > 0) {
        systrace::utils::TimerManager::getInstance().startTimer(
            get_id(), duration, [this]() { this->stop(); });
    }
    LOG_MODULE(INFO, pluginName_) << "Output file: " << output_;
    return true;
}

void PthreadPlugin::stop() {
    if (get_local_rank() != 0) {
        return;
    }
    if (stop_latched_.test_and_set(std::memory_order_acquire))
        return;

    if (active_.load()) {
        LOG_MODULE(INFO, pluginName_) << "trace stop.";
        active_.store(false);
        if (poll_thread_.joinable())
            poll_thread_.join();
        cleanup_skel();
        clear_pthrd_maps();
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
            fprintf(trace_output_stream_, "\n]}\n");
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

void PthreadPlugin::clean_ringbuffer() {
    struct ring_buffer *temp_rb = ring_buffer__new(
        bpf_map__fd(bpf_skeleton_->maps.event_map_a),
        [](void *, void *, size_t) { return 0; }, nullptr, nullptr);
    if (temp_rb) {
        while (ring_buffer__poll(temp_rb, 0) > 0)
            ;
        ring_buffer__free(temp_rb);
    }
}

void PthreadPlugin::cleanup_skel() {
    for (auto link : links_) {
        if (link) {
            bpf_link__destroy(link);
        }
    }
    links_.clear();

    if (bpf_skeleton_) {
        pthrd_sync_bpf__detach(bpf_skeleton_);
    }
}

void PthreadPlugin::init_trace_setting_t(const json &params) {
    struct trace_setting_t setting = {};
    u64 final_min_dur = 100 * 1000;
    if (params.contains("min_dur_ns")) {
        auto &v = params["min_dur_ns"];
        if (v.is_string()) {
            try {
                final_min_dur = std::stoull(v.get<std::string>());
            } catch (...) {
                LOG_MODULE(WARNING, pluginName_)
                    << "Invalid min_dur_ns string: " << v;
            }
        } else if (v.is_number()) {
            final_min_dur = v.get<u64>();
        }
    }

    setting.min_exec_dur = final_min_dur;
    u32 zero = 0;
    bpf_map__update_elem(bpf_skeleton_->maps.setting_map, &zero, sizeof(zero),
                         &setting, sizeof(setting), BPF_ANY);
}

std::vector<PthreadHook> PthreadPlugin::get_hook_list() {
    return {{PTHREAD_MUTEX_LOCK_ID, "pthread_mutex_lock",
             bpf_skeleton_->progs.ubpf_pthread_mutex_lock,
             bpf_skeleton_->progs.ubpf_ret_pthread_mutex_lock},
            {PTHREAD_MUTEX_TIMEDLOCK_ID, "pthread_mutex_timedlock",
             bpf_skeleton_->progs.ubpf_pthread_mutex_timedlock,
             bpf_skeleton_->progs.ubpf_ret_pthread_mutex_timedlock},
            {PTHREAD_MUTEX_TRYLOCK_ID, "pthread_mutex_trylock",
             bpf_skeleton_->progs.ubpf_pthread_mutex_trylock,
             bpf_skeleton_->progs.ubpf_ret_pthread_mutex_trylock},
            {PTHREAD_RWLOCK_RDLOCK_ID, "pthread_rwlock_rdlock",
             bpf_skeleton_->progs.ubpf_pthread_rwlock_rdlock,
             bpf_skeleton_->progs.ubpf_ret_pthread_rwlock_rdlock},
            {PTHREAD_RWLOCK_WRLOCK_ID, "pthread_rwlock_wrlock",
             bpf_skeleton_->progs.ubpf_pthread_rwlock_wrlock,
             bpf_skeleton_->progs.ubpf_ret_pthread_rwlock_wrlock},
            {PTHREAD_RWLOCK_TIMEDRDLOCK_ID, "pthread_rwlock_timedrdlock",
             bpf_skeleton_->progs.ubpf_pthread_rwlock_timedrdlock,
             bpf_skeleton_->progs.ubpf_ret_pthread_rwlock_timedrdlock},
            {PTHREAD_RWLOCK_TIMEDWRLOCK_ID, "pthread_rwlock_timedwrlock",
             bpf_skeleton_->progs.ubpf_pthread_rwlock_timedwrlock,
             bpf_skeleton_->progs.ubpf_ret_pthread_rwlock_timedwrlock},
            {PTHREAD_RWLOCK_TRYRDLOCK_ID, "pthread_rwlock_tryrdlock",
             bpf_skeleton_->progs.ubpf_pthread_rwlock_tryrdlock,
             bpf_skeleton_->progs.ubpf_ret_pthread_rwlock_tryrdlock},
            {PTHREAD_RWLOCK_TRYWRLOCK_ID, "pthread_rwlock_trywrlock",
             bpf_skeleton_->progs.ubpf_pthread_rwlock_trywrlock,
             bpf_skeleton_->progs.ubpf_ret_pthread_rwlock_trywrlock},
            {PTHREAD_SPIN_LOCK_ID, "pthread_spin_lock",
             bpf_skeleton_->progs.ubpf_pthread_spin_lock,
             bpf_skeleton_->progs.ubpf_ret_pthread_spin_lock},
            {PTHREAD_SPIN_TRYLOCK_ID, "pthread_spin_trylock",
             bpf_skeleton_->progs.ubpf_pthread_spin_trylock,
             bpf_skeleton_->progs.ubpf_ret_pthread_spin_trylock},
            {SEM_WAIT_ID, "sem_wait", bpf_skeleton_->progs.ubpf_sem_wait,
             bpf_skeleton_->progs.ubpf_ret_sem_wait},
            {SEM_TIMEDWAIT_ID, "sem_timedwait",
             bpf_skeleton_->progs.ubpf_sem_timedwait,
             bpf_skeleton_->progs.ubpf_ret_sem_timedwait},
            {SEM_TRYWAIT_ID, "sem_trywait",
             bpf_skeleton_->progs.ubpf_sem_trywait,
             bpf_skeleton_->progs.ubpf_ret_sem_trywait}};
}

void PthreadPlugin::attach_all_probes(std::vector<int> pids, const char *path) {
    if (!bpf_skeleton_) {
        LOG_MODULE(ERROR, pluginName_)
            << "Invalid skeleton, skip attach probes";
        return;
    }

    auto hooks = get_hook_list();
    for (const auto &h : hooks) {
        unsigned long off = systrace::elfutils::ElfUtils::find_function_offset(
            path, h.func_name);
        for (int i = 0; i < pids.size(); i++) {
            if (off > 0) {
                struct bpf_link *l_enter = bpf_program__attach_uprobe(
                    h.enter_prog, false, pids[i], path, off);
                if (l_enter)
                    links_.push_back(l_enter);

                struct bpf_link *l_exit = bpf_program__attach_uprobe(
                    h.exit_prog, true, pids[i], path, off);
                if (l_exit)
                    links_.push_back(l_exit);
            }
        }
    }
}

const char *PthreadPlugin::get_pthread_func_name(int id) {
    if (id >= 0 && id < (int)(sizeof(names) / sizeof(char *))) {
        return names[id];
    }
    return "UNKNOWN";
}

int PthreadPlugin::handle_event(void *ctx, void *data, size_t data_sz) {
    auto *self = static_cast<PthreadPlugin *>(ctx);
    auto *ev = static_cast<pthread_trace_event_data_t *>(data);

    if (self && self->active_.load() && ev) {
        self->process_raw_event(ev);
    }
    return 0;
}

void PthreadPlugin::process_raw_event(pthread_trace_event_data_t *e) {
    if (e->type != EVT_TYPE_PTHREAD || !trace_output_stream_ ||
        !json_buf_.buf) {
        return;
    }
    pthrd_data_t &d = e->pthrd_d;
    double dur_us = (double)d.duration / 1000.0;
    if (dur_us < 10.0) {
        return;
    };

    if (json_buf_.total_size - json_buf_.used_size < 512) {
        systrace::fileWriterUtil::strbuf_flush(&json_buf_);
    }
    size_t remaining = json_buf_.total_size - json_buf_.used_size;
    if (remaining < 256) {
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

    uint64_t current_time =
        systrace::util::time::MonotonicNsToUtcUs(d.start_time);

    ret = snprintf(write_ptr, remaining,
                   "{"
                   "\"cat\": \"pthread_sync\", "
                   "\"name\": \"%s\", "
                   "\"ph\": \"X\", "
                   "\"ts\": %lu, "
                   "\"dur\": %.3f, "
                   "\"pid\": \"%s\", "
                   "\"tid\": \"%s\", "
                   "\"args\": {"
                   "\"comm\": \"%s\""
                   "}}",
                   get_pthread_func_name(d.id), current_time, dur_us,
                   rank_str.c_str(), tid_str.c_str(), e->comm);

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

void PthreadPlugin::poll_loop() {
    if (!bpf_skeleton_)
        return;
    struct ring_buffer *local_pb =
        ring_buffer__new(bpf_map__fd(bpf_skeleton_->maps.event_map_a),
                         PthreadPlugin::handle_event, this, nullptr);

    if (!local_pb) {
        LOG_MODULE(ERROR, pluginName_) << "Failed to create ring buffer";
        return;
    }
    {
        std::lock_guard<std::mutex> lock(rb_mutex_);
        rb_ = local_pb;
    }
    while (active_.load()) {
        ring_buffer__poll(local_pb, 100);
    }
}

void PthreadPlugin::clear_pthrd_maps() {
    if (!bpf_skeleton_)
        return;
    struct bpf_map *map = bpf_skeleton_->maps.pthrd_enter_map;
    if (!map)
        return;
    int fd = bpf_map__fd(map);
    pthrd_m_key_t key = {};
    pthrd_m_key_t next_key;
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
            << " residual entries from pthrd_enter_map";
    }
}