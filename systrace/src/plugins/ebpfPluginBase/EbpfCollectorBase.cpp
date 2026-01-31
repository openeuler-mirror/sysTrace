#include "EbpfCollectorBase.h"
#include "../../../include/log/logging.h"
#include "../../../include/utils/PluginUtils.hpp"
#include "../../../include/utils/TimerManager.hpp"
#include "../../../include/utils/util.h"
#include <algorithm>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#define PROC_FILTER_RANK_MAP_PATH "/sys/fs/bpf/sysTrace/__osprobe_proc_filter"
#define MAP_HOOK_PID_PATH "/sys/fs/bpf/sysTrace/__osprobe_rank_pid"

int EbpfCollectorBase::get_local_rank() {
    return systrace::util::config::GlobalConfig::Instance().local_rank;
}

bool EbpfCollectorBase::is_main_process() { return get_local_rank() == 0; }

std::unordered_map<int, int> EbpfCollectorBase::init_pid_to_rank_map() {
    std::unordered_map<int, int> pid_to_rank;
    int map_fd = bpf_obj_get(PROC_FILTER_RANK_MAP_PATH);
    if (map_fd < 0) {
        LOG_MODULE(WARN, ebpfPluginName_)
            << "Failed to get eBPF map FD: " << strerror(errno)
            << " (path: " << PROC_FILTER_RANK_MAP_PATH << ")";
        return pid_to_rank;
    }

    __u32 iter_key = 0;
    __u32 next_key = 0;
    int rank_value = 0;

    while (true) {
        int next_ret = bpf_map_get_next_key(map_fd, &iter_key, &next_key);
        if (next_ret != 0) {
            if (errno == ENOENT) {
                LOG_MODULE(DEBUG, ebpfPluginName_)
                    << "eBPF map traverse done, total entries: "
                    << pid_to_rank.size();
                break;
            } else {
                LOG_MODULE(ERROR, ebpfPluginName_)
                    << "Failed to get next key: " << strerror(errno);
                break;
            }
        }

        int read_ret = bpf_map_lookup_elem(map_fd, &next_key, &rank_value);
        if (read_ret != 0) {
            LOG_MODULE(WARN, ebpfPluginName_)
                << "Failed to read rank for PID " << next_key << ": "
                << strerror(errno);
            iter_key = next_key;
            continue;
        }

        pid_to_rank[next_key] = rank_value;

        LOG_MODULE(DEBUG, ebpfPluginName_)
            << "Insert to map: PID=" << next_key << ", Rank=" << rank_value;

        iter_key = next_key;
    }

    close(map_fd);
    return pid_to_rank;
}

std::vector<int> EbpfCollectorBase::read_all_pids_from_map() {
    std::vector<int> trace_pids;
    int hook_pid_fd = bpf_obj_get(MAP_HOOK_PID_PATH);

    if (hook_pid_fd < 0) {
        LOG_MODULE(ERROR, ebpfPluginName_)
            << " Failed to get bpf prog rank_pid map: " << strerror(errno);
        return trace_pids;
    }

    __u32 current_key = 0;
    __u32 next_key;
    __u32 pid;

    while (true) {
        int next_ret =
            bpf_map_get_next_key(hook_pid_fd, &current_key, &next_key);
        if (next_ret != 0) {
            if (errno == ENOENT) {
                LOG_MODULE(DEBUG, ebpfPluginName_)
                    << " Read " << trace_pids.size() << " PIDs from map";
                break;
            } else {
                LOG_MODULE(ERROR, ebpfPluginName_)
                    << " Failed to get next key from map: " << strerror(errno);
                break;
            }
        }

        int read_ret = bpf_map_lookup_elem(hook_pid_fd, &next_key, &pid);
        if (read_ret == 0 && pid > 0) {
            trace_pids.push_back(static_cast<int>(pid));
        } else if (read_ret != 0) {
            LOG_MODULE(WARN, ebpfPluginName_)
                << " Failed to read PID for key " << next_key << ": "
                << strerror(errno);
        }

        current_key = next_key;
    }

    close(hook_pid_fd);
    return trace_pids;
}

std::vector<int> EbpfCollectorBase::get_trace_pids(const json &params) {
    std::vector<int> result_pids;

    if (params.contains("pid")) {
        auto &v = params["pid"];
        if (v.is_string()) {
            std::string pid_str = v.get<std::string>();
            std::vector<int> parsed_pids =
                systrace::pluginutils::PluginUtils::split_pid_string(pid_str);
            if (!parsed_pids.empty()) {
                result_pids.insert(result_pids.end(), parsed_pids.begin(),
                                   parsed_pids.end());
            }
        }
    }
    std::vector<int> trace_pids = read_all_pids_from_map();
    result_pids.insert(result_pids.end(), trace_pids.begin(), trace_pids.end());

    std::sort(result_pids.begin(), result_pids.end());
    auto last = std::unique(result_pids.begin(), result_pids.end());
    result_pids.erase(last, result_pids.end());
    return result_pids;
}
