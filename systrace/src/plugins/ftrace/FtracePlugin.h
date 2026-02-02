#ifndef FTRACE_PLUGIN_HPP
#define FTRACE_PLUGIN_HPP

#include "../../../include/common/ICollector.hpp"
#include "../../../include/common/constant.h"
#include "../../../include/log/logging.h"
#include "../../../include/utils/PluginUtils.hpp"
#include "../../../include/utils/TimerManager.hpp"
#include "../../../include/utils/util.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <thread>
#include <unistd.h>
#include <vector>

using json = nlohmann::json;
using PluginNameType = systrace::constant::Plugin;
using PluginUtils = systrace::pluginutils::PluginUtils;

struct TraceCoreConfig {
    std::vector<std::string> enable_events;
    std::string trace_functions;
    std::string buffer_size_kb = "32768";
    bool stack_trace = false;
    bool func_stack_trace = false;
    std::string function_tracer = "function";
    std::string ftrace_pid;
    std::string event_pid;
};

struct TraceTaskConfig {
    std::string cpu_list;
    int duration = 10;
    TraceCoreConfig core_config;
};

class FtracePlugin : public ICollector {
  public:
    FtracePlugin();
    virtual ~FtracePlugin();

    bool start(const json &params, int duration) override;
    void stop() override;

  private:
    struct CpuReader {
        int cpu_id;
        int raw_fd = -1;
        int out_fd = -1;
        int pipe_fds[2] = {-1, -1};
        std::thread worker;
    };

    void per_cpu_splice_loop(CpuReader &reader);
    bool init_ftrace();
    int get_local_rank();
    void reset_ftrace();
    void cleanup_resources();
    void reset_plugin_state();
    void process_raw_data();
    TraceTaskConfig parse_config_from_json(const nlohmann::json &params);

    static constexpr size_t K_SPLICE_SIZE = 5 * 1024 * 1024;
    std::vector<CpuReader> cpu_readers_; // 多 CPU 读取器
    int collect_duration_ = -1;
    std::string output_dir_;
    std::string output_;
    std::string ftrace_path_;
    std::atomic<bool> stop_flag_;
    TraceTaskConfig task_config_;
};

#endif // FTRACE_PLUGIN_HPP