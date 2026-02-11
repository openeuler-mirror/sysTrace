#include "GilPlugin.h"
#include "../ebpf/python_gil.skel.h"
#include "../../../include/common/constant.h"

#define MAP_HOOK_PID_PATH "/sys/fs/bpf/sysTrace/__osprobe_rank_pid"
#define PROC_FILTER_RANK_MAP_PATH "/sys/fs/bpf/sysTrace/__osprobe_proc_filter"
#define GET_HOOK_PID_COUNT 20

const int MAP_READY_TIMEOUT_S = 30;
const int MAP_INIT_TIMEOUT_S = 5;

extern "C" char g_python_lib_path[512];
extern "C" pid_t g_hooked_pid;

struct event {
    unsigned long long ts;
    unsigned int pid;
    unsigned int tid;
    char name[16];
    char ph;
    char pad[7];
} __attribute__((aligned(8)));

UprobeLink::UprobeLink(int p, const std::string &fn, bool ir,
                       struct bpf_link *l)
    : pid(p), func_name(fn), is_ret(ir), link(l) {}

UprobeLink::~UprobeLink() {
    if (link) {
        bpf_link__destroy(link);
        link = nullptr;
    }
}

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

    LOG_MODULE(DEBUG, pluginName_)
        << "Stop request received, initiating cleanup";

    if (active_.load()) {
        active_.store(false, std::memory_order_release);
    }

    if (poll_thread_.joinable()) {
        LOG_MODULE(DEBUG, pluginName_) << "Joining poll thread...";
        poll_thread_.join();
        LOG_MODULE(DEBUG, pluginName_) << "Poll thread joined successfully";
    }

    {
        std::lock_guard<std::mutex> lock(pb_mutex_);
        if (pb_) {
            perf_buffer__free(pb_);
            pb_ = nullptr;
            LOG_MODULE(DEBUG, pluginName_) << "Perf buffer resource released";
        }
    }

    cleanup_all_uprobe_links();

    if (bpf_skeleton_) {
        python_gil_bpf__detach(bpf_skeleton_);
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
    LOG_MODULE(INFO, pluginName_) << " trace stop.";

    stop_latched_.clear(std::memory_order_release);
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

void GILPlugin::cleanup_all_uprobe_links() {
    std::lock_guard<std::mutex> lock(link_mutex_);

    if (uprobe_links_.empty()) {
        LOG_MODULE(DEBUG, pluginName_) << "No active uprobe links to clean";
        return;
    }

    size_t total = uprobe_links_.size();
    LOG_MODULE(DEBUG, pluginName_)
        << "Cleaning up " << total << " uprobe links";

    for (auto &link_ptr : uprobe_links_) {
        if (!link_ptr)
            continue;

        if (link_ptr->link) {
            int ret = bpf_link__destroy(link_ptr->link);
            if (ret == 0) {
                LOG_MODULE(DEBUG, pluginName_)
                    << "Destroyed link: func=" << link_ptr->func_name
                    << ", pid=" << link_ptr->pid;
            } else {
                LOG_MODULE(INFO, pluginName_)
                    << "Failed to destroy link: func=" << link_ptr->func_name
                    << ", pid=" << link_ptr->pid << ", err=" << strerror(-ret);
            }
            link_ptr->link = nullptr;
        }
    }
    uprobe_links_.clear();
}

void GILPlugin::consume_perf_events() {
    struct perf_buffer *local_pb = nullptr;

    if (!bpf_skeleton_) {
        LOG_MODULE(ERROR, pluginName_) << "Skeleton is null, poll loop exit";
        return;
    }

    local_pb = perf_buffer__new(
        bpf_map__fd(bpf_skeleton_->maps.events), 64,
        [](void *ctx, int cpu, void *data, __u32 size) {
            auto *plugin = static_cast<GILPlugin *>(ctx);
            if (plugin->active_.load()) {
                plugin->process_raw_event(data);
            }
        },
        nullptr, this, nullptr);

    if (!local_pb) {
        LOG_MODULE(ERROR, pluginName_)
            << "Create perf buffer failed: " << strerror(errno);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(pb_mutex_);
        pb_ = local_pb;
    }

    while (active_.load()) {
        perf_buffer__poll(local_pb, 50);
    }

    perf_buffer__free(local_pb);

    {
        std::lock_guard<std::mutex> lock(pb_mutex_);
        pb_ = nullptr;
    }

    LOG_MODULE(DEBUG, pluginName_) << "Poll loop exited normally";
}

void GILPlugin::process_raw_event(void *data) {

    struct event *e = (struct event *)data;

    if (!trace_output_stream_ || !json_buf_.buf) {
        return;
    }
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
    uint64_t current_time = systrace::util::time::MonotonicNsToUtcUs(e->ts);
    ret = snprintf(write_ptr, remaining,
                   "  {\"name\": \"%s\", \"ph\": \"%c\", \"ts\": %lu, "
                   "\"pid\": \"%s\", \"tid\": \"%s\"}",
                   e->name, e->ph, current_time, rank_str.c_str(),
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
                uprobe_links_.emplace_back(
                    std::make_unique<UprobeLink>(pid, func, is_ret, link));
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