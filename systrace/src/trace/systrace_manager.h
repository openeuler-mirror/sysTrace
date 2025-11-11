#pragma once
#include <atomic>
#include <mutex>
#include <pthread.h>
#include <thread>
#include <vector>
#include <queue>
#include <condition_variable>
#include <nlohmann/json.hpp>

#include "../../include/common/logging.h"
#include "../../include/common/util.h"
#include "../../include/common/shared_constants.h"
#include "../../server/monitor_server.hpp"
#include "library_loader.h"
#include "python/pytorch_tracing_loader.h"

namespace systrace
{
using namespace util;
using json = nlohmann::json;

class PyTorchTrace
{
public:
    static PyTorchTrace &getInstance();

    void dumpPyTorchTracing();
    void dumpPyTorchTracing(bool incremental, bool async);
    bool triggerTrace();

    PyTorchTrace(const PyTorchTrace &) = delete;
    PyTorchTrace &operator=(const PyTorchTrace &) = delete;

private:
    PyTorchTrace();
    ~PyTorchTrace();

    void initialize();
    void registerTracingFunctions();
    void processFunctionTracingData(size_t function_index);
    void enqueueTraceEntry(json &&entry);
    void writerLoop();
    void writeTraceEntryToFile(const json &entry);

    inline static PyTorchTrace *instance_ = nullptr;
    inline static std::once_flag init_flag_;

    std::atomic<bool> has_trigger_trace_{false};

    std::vector<std::string> pytorch_tracing_functions_;
    std::string PyFuncListPath_ = "/etc/systrace/config/PyFuncList";
    pytorch_tracing::PyTorchTracingLibrary *pytorch_tracing_library_;

    std::queue<json> trace_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::thread writer_thread_;
    std::atomic<bool> stop_writer_{false};
};

class SysTrace
{
public:
    static SysTrace &getInstance();

    SysTrace(const SysTrace &) = delete;
    SysTrace &operator=(const SysTrace &) = delete;
    static void cleanup() {
      if (!instance_) {
        return;
      }
        instance_->stopEventPoller();
      // delete instance_;
      instance_ = nullptr;
    }

private:
    SysTrace() = default;
    ~SysTrace();

    void initializeSystem();
    void startEventPoller();
    void stopEventPoller();
    void eventPollerMain();

    inline static SysTrace *instance_ = nullptr;
    inline static std::once_flag init_flag_;

    std::atomic<bool> should_run_{true};
    std::atomic<uint64_t> loop_count_{0};
    std::thread event_poller_;

#ifdef HAS_BTF_SUPPORT
    void stopOsProbePoller();
    std::thread os_probe_;
#endif
};

} // namespace systrace