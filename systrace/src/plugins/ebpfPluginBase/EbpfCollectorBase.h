#ifndef EBPF_COLLECTOR_BASE_H
#define EBPF_COLLECTOR_BASE_H

#include <atomic>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/resource.h>
#include <thread>
#include <unordered_map>
#include <vector>

#define EBPF_RLIM_LIMITED RLIM_INFINITY

using json = nlohmann::json;

class EbpfCollectorBase {
  public:
    virtual ~EbpfCollectorBase() = default;

  protected:
    bool is_main_process();
    int get_local_rank();
    std::unordered_map<int, int> init_pid_to_rank_map();
    std::vector<int> get_trace_pids(const json &params);
    std::vector<int> read_all_pids_from_map();
    int set_memlock_rlimit(unsigned long limit);

    const char *ebpfPluginName_ = "EbpfCollectorBase";
};

#endif