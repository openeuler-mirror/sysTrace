#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "../../include/common/constant.h"
#include "../../include/log/logging.h"
#include "systrace_manager.h"

int global_stage_id = 0;
int global_stage_type = 0;

#ifdef HAS_BTF_SUPPORT
extern "C" {
int run_osprobe();
void cleanup_osprobe();
}
#endif

namespace systrace {

namespace {
constexpr uint64_t TRACE_INTERVAL = 100;
constexpr std::chrono::milliseconds POLL_INTERVAL(10);
} // namespace

PyTorchTrace &PyTorchTrace::getInstance() {
    std::call_once(init_flag_, []() {
        instance_ = new PyTorchTrace();
        instance_->initialize();
    });
    return *instance_;
}

void PyTorchTrace::initialize() {
    pytorch_trace_.set_rank(config::GlobalConfig::Instance().rank);
    LOG_MODULE(INFO, "PyTorchTrace")
        << "Rank set to: " << config::GlobalConfig::Instance().rank;

    pytorch_tracing_library_ =
        new pytorch_tracing::PyTorchTracingLibrary("libsysTrace.so");
    LOG_MODULE(INFO, "PyTorchTrace") << "Tracing library loaded";

    registerTracingFunctions();
}

void PyTorchTrace::registerTracingFunctions() {
    std::ifstream funcListFile(PyFuncListPath_);
    std::string line;
    if (!funcListFile.is_open()) {
        LOG_MODULE(ERROR, "PyTorchTrace") << "Failed to open PyFuncList file";
        return;
    }
    while (std::getline(funcListFile, line)) {
        if (!line.empty() && line[0] != '#') {
            pytorch_tracing_functions_.push_back(line);
        }
    }

    funcListFile.close();

    auto errors =
        pytorch_tracing_library_->Register(pytorch_tracing_functions_);
    for (size_t i = 0; i < pytorch_tracing_functions_.size(); ++i) {
        LOG_MODULE(INFO, "PyTorchTrace")
            << "Registered function: " << pytorch_tracing_functions_[i]
            << ", status: " << errors[i];
    }
}

bool PyTorchTrace::triggerTrace() { return has_trigger_trace_.exchange(true); }

void PyTorchTrace::dumpPyTorchTracing() {
    const std::string &dump_path =
        std::string(constant::TorchTraceConstant::DEFAULT_TRACE_DUMP_PATH);

    if (util::fs_utils::CreateDirectoryIfNotExists(dump_path)) {
        LOG_MODULE(ERROR, "PyTorchTrace")
            << "[PyTorchTrace] Failed to create dump directory";
        return;
    }

    std::lock_guard<std::mutex> lock(trace_mutex_);

    pytorch_trace_.set_rank(config::GlobalConfig::Instance().rank);
    pytorch_trace_.set_comm(config::GlobalConfig::Instance().job_name);

    for (size_t i = 0; i < pytorch_tracing_functions_.size(); ++i) {
        processFunctionTracingData(i);
    }

    writeTraceToFile();
}

void PyTorchTrace::processFunctionTracingData(size_t function_index) {
    std::vector<PyTorchTracingDataArray *> data_holders;

    if (auto data = pytorch_tracing_library_->RetrievePartialTracingData(
            function_index)) {
        data_holders.push_back(data);
    }

    while (auto data = pytorch_tracing_library_->RetrieveAllTracingData(
               function_index)) {
        data_holders.push_back(data);
    }

    for (auto data : data_holders) {
        for (uint32_t i = 0; i < data->cur; ++i) {
            if (data->data[i].start == 0)
                continue;

            auto trace = pytorch_trace_.add_pytorch_stages();
            trace->set_start_us(data->data[i].start);
            trace->set_end_us(data->data[i].end);
            trace->set_stage_id(data->data[i].count);
            trace->set_stage_type(pytorch_tracing_functions_[function_index]);

            if (data->data[i].stack_depth > 0) {
                trace->mutable_stack_frames()->Reserve(
                    data->data[i].stack_depth);
                for (int j = 0; j < data->data[i].stack_depth; ++j) {
                    if (data->data[i].stack_info[j][0] != '\0') {
                        trace->add_stack_frames(data->data[i].stack_info[j]);
                    }
                }
            }

            if (data->data[i].type == PAYLOAD_GC) {
                auto gc_debug = trace->mutable_gc_debug();
                gc_debug->set_collected(data->data[i].payload.gc_debug[0]);
                gc_debug->set_uncollectable(data->data[i].payload.gc_debug[1]);
            }
        }
    }

    for (auto data : data_holders) {
        pytorch_tracing_library_->ReleaseTracingData(
            data, PY_TRACING_EMPTY_POOL, function_index);
    }
}

void PyTorchTrace::writeTraceToFile() {
    const std::string &dump_path =
        std::string(constant::TorchTraceConstant::DEFAULT_TRACE_DUMP_PATH);
    std::string file_path =
        dump_path + "/" +
        util::fs_utils::GenerateClusterUniqueFilename(".timeline");

    std::ofstream file(file_path, std::ios::binary | std::ios::out);
    if (!file) {
        LOG_MODULE(ERROR, "PyTorchTrace")
            << "Failed to open file: " << file_path;
        return;
    }

    std::string binary_data;
    if (!pytorch_trace_.SerializeToString(&binary_data)) {
        LOG_MODULE(ERROR, "PyTorchTrace") << "Failed to serialize trace data";
        return;
    }

    file << binary_data;
}

SysTrace &SysTrace::getInstance() {
    std::call_once(init_flag_, []() {
        instance_ = new SysTrace();
        instance_->initializeSystem();
        std::atexit(cleanup);
    });
    return *instance_;
}

SysTrace::~SysTrace() {
    ControlManager::getInstance().stop();
#ifdef HAS_BTF_SUPPORT
    stopOsProbePoller();
#endif
    stopEventPoller();
}

void SysTrace::initializeSystem() {
    if (!config::GlobalConfig::Instance().enable)
        return;
    systrace::util::InitializeSystemUtilities();
    registerPlugins();
    ControlManager::getInstance().start();

    MSPTITracker::getInstance();
    PyTorchTrace::getInstance();
#ifdef HAS_BTF_SUPPORT
    os_probe_ = std::thread(&run_osprobe);
#endif

    startEventPoller();
}

void SysTrace::startEventPoller() {
#ifdef _GNU_SOURCE
    should_run_ = true;
    event_poller_ = std::thread(&SysTrace::eventPollerMain, this);
    pthread_setname_np(event_poller_.native_handle(), "systrace_poller");
#endif
    LOG_MODULE(INFO, "SysTrace") << "Event poller started";
}

#ifdef HAS_BTF_SUPPORT
void SysTrace::stopOsProbePoller() {
    cleanup_osprobe();
    if (os_probe_.joinable()) {
        os_probe_.join();
    }
}
#endif

void SysTrace::registerPlugins() {
    auto &cm = ControlManager::getInstance();
    cm.register_plugin(std::make_shared<HbmPlugin>());
    cm.register_plugin(std::make_shared<MsptiPlugin>());
    cm.register_plugin(std::make_shared<IOPlugin>());
    cm.register_plugin(std::make_shared<MemoryPlugin>());
    cm.register_plugin(std::make_shared<CpuPlugin>());
    cm.register_plugin(std::make_shared<CacheMissPlugin>());
    cm.register_plugin(std::make_shared<GILPlugin>());
    cm.register_plugin(std::make_shared<PthreadPlugin>());
}

void SysTrace::stopEventPoller() {
    should_run_ = false;
    if (event_poller_.joinable()) {
        event_poller_.join();
    }
}

void SysTrace::eventPollerMain() {
    while (should_run_) {
        if (loop_count_++ % TRACE_INTERVAL == 0) {
            if (PyTorchTrace::getInstance().triggerTrace()) {
                PyTorchTrace::getInstance().dumpPyTorchTracing();
            }
        }
        std::this_thread::sleep_for(POLL_INTERVAL);
    }

    if (PyTorchTrace::getInstance().triggerTrace()) {
        PyTorchTrace::getInstance().dumpPyTorchTracing();
    }
}

} // namespace systrace
