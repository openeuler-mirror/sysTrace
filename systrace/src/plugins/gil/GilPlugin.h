#pragma once

#include "../../../include/common/ICollector.hpp"
#include "../../../include/common/constant.h"
#include "../../../include/utils/FileWriterUtil.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

struct python_gil_bpf;
struct perf_buffer;
struct bpf_link;

using PluginNameType = systrace::constant::Plugin;

struct UprobeLink {
    int pid;
    std::string func_name;
    bool is_ret;
    struct bpf_link *link;

    UprobeLink(int p, const std::string &fn, bool ir, struct bpf_link *l);
    ~UprobeLink();
};

class GILPlugin : public ICollector {
  public:
    GILPlugin();
    ~GILPlugin();

    bool start(const json &params, int duration) override;
    void stop() override;

  private:
    void consume_perf_events();
    void process_raw_event(void *data);
    void attach_all_probes(std::vector<int> pids, const std::string &path);
    bool try_bind_uprobe(struct bpf_program *prog, int pid,
                             const std::string &path,
                             const std::vector<std::string> &funcs,
                             bool is_ret);
    void cleanup_all_uprobe_links();
    std::vector<int> get_trace_pids(const json &params);

    std::vector<int> read_all_pids_from_map();
    void initPidToRankMap();
    int get_local_rank();
    bool is_main_process();
    void register_target_process_to_bpf();
    std::string auto_find_libpython();

    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
    struct python_gil_bpf *bpf_skeleton_ = nullptr;
    std::thread poll_thread_;
    FILE *trace_output_stream_ = nullptr;
    bool first_event_ = true;
    systrace::fileWriterUtil::strbuf_t json_buf_;
    std::unordered_map<int, int> host_pid_to_rank_mapping_;
    struct perf_buffer *pb_ = nullptr;
    std::mutex pb_mutex_;
    std::vector<std::unique_ptr<UprobeLink>> uprobe_links_;
    std::mutex link_mutex_;
    std::string output_;
    const std::vector<std::string> gil_acquire_symbols = {"take_gil",
                                                 "PyEval_RestoreThread"};
    const std::vector<std::string> gil_release_symbols = {"drop_gil",
                                                 "PyEval_SaveThread"};
};