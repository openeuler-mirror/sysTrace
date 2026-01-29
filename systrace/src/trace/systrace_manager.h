#pragma once
#include "../../include/common/constant.h"
#include "../../include/log/logging.h"
#include "../../include/utils/util.h"
#include "../plugins/CacheMissPlugin.hpp"
#include "../plugins/EbpfPlugin.hpp"
#include "../plugins/HbmPlugin.hpp"
#include "../plugins/IOPlugin.hpp"
#include "../plugins/MsptiTrackerPlugin.hpp"
#include "../plugins/TracePlugin.hpp"
#include "../plugins/ftrace/FtracePlugin.h"
#include "../plugins/gil/GilPlugin.h"
#include "../plugins/manager/ControlManager.hpp"
#include "../plugins/pthread/PthreadPlugin.h"
#include "library_loader.h"
#include "python/pytorch_tracing_loader.h"
#include <atomic>
#include <condition_variable>
#include <fstream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#ifdef USE_JSON
#include <nlohmann/json.hpp>
using json = nlohmann::json;
#else
#include "../../protos/systrace.pb.h"
#endif

namespace systrace {

class PyTorchTrace {
  public:
    static PyTorchTrace &getInstance();
    void dumpPyTorchTracing();
    bool triggerTrace();

    PyTorchTrace(const PyTorchTrace &) = delete;
    PyTorchTrace &operator=(const PyTorchTrace &) = delete;

  private:
    PyTorchTrace();
    ~PyTorchTrace();

    void initialize();
    void registerTracingFunctions();
    void processFunctionTracingData(size_t function_index);

#ifdef USE_JSON
    void writerLoop();
    void enqueueTraceEntry(json &&entry);

    std::thread writer_thread_;
    std::queue<json> trace_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::atomic<bool> stop_writer_{false};
#else
    void writeTraceToFile();
    Pytorch pytorch_trace_;
#endif

    inline static PyTorchTrace *instance_ = nullptr;
    inline static std::once_flag init_flag_;

    std::atomic<bool> has_trigger_trace_{false};
    std::mutex trace_mutex_;

    std::vector<std::string> pytorch_tracing_functions_;
    std::string PyFuncListPath_ = "/etc/systrace/config/PyFuncList";
    pytorch_tracing::PyTorchTracingLibrary *pytorch_tracing_library_ = nullptr;
};

class SysTrace {
  public:
    static SysTrace &getInstance();
    ~SysTrace();

    SysTrace(const SysTrace &) = delete;
    SysTrace &operator=(const SysTrace &) = delete;

  private:
    SysTrace() = default;
    void initializeSystem();
    void registerPlugins();
    void startEventPoller();
    void stopEventPoller();
    void eventPollerMain();
    static void cleanup();

#ifdef HAS_BTF_SUPPORT
    void stopOsProbePoller();
    std::thread os_probe_;
#endif

    inline static SysTrace *instance_ = nullptr;
    inline static std::once_flag init_flag_;

    std::atomic<bool> should_run_{true};
    std::atomic<uint64_t> loop_count_{0};
    std::thread event_poller_;
};

} // namespace systrace