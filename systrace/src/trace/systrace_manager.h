#pragma once
#include <atomic>
#include <mutex>
#include <pthread.h>
#include <thread>
#include <vector>

#include "../../include/common/logging.h"
#include "../../include/common/util.h"
#include "../../protos/systrace.pb.h"
#include "../mspti/mspti_tracker.hpp"
#include "library_loader.h"
#include "python/pytorch_tracing_loader.h"

namespace systrace
{
using namespace util;

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
    PyTorchTrace() = default;
    ~PyTorchTrace() = default;

    void initialize();
    void registerTracingFunctions();
    void processFunctionTracingData(size_t function_index);
    void writeTraceToFile();

    inline static PyTorchTrace *instance_ = nullptr;
    inline static std::once_flag init_flag_;

    Pytorch pytorch_trace_;
    std::atomic<bool> has_trigger_trace_{false};
    std::mutex trace_mutex_;

    std::vector<std::string> pytorch_tracing_functions_;
    pytorch_tracing::PyTorchTracingLibrary *pytorch_tracing_library_;
};

class SysTrace
{
  public:
    static SysTrace &getInstance();

    SysTrace(const SysTrace &) = delete;
    SysTrace &operator=(const SysTrace &) = delete;

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
};

} // namespace systrace