#include "systrace_manager.h"
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

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

PyTorchTrace::PyTorchTrace() {
#ifdef USE_JSON
    writer_thread_ = std::thread(&PyTorchTrace::writerLoop, this);
#endif
}

PyTorchTrace::~PyTorchTrace() {
#ifdef USE_JSON
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        stop_writer_ = true;
    }
    queue_cv_.notify_one();
    if (writer_thread_.joinable())
        writer_thread_.join();
#else
    std::lock_guard<std::mutex> lock(trace_mutex_);
    writeTraceToFile();
#endif
    if (pytorch_tracing_library_) {
        delete pytorch_tracing_library_;
        pytorch_tracing_library_ = nullptr;
    }
}

void PyTorchTrace::initialize() {
#ifndef USE_JSON
    pytorch_trace_.set_rank(
        systrace::util::config::GlobalConfig::Instance().rank);
    LOG_MODULE(INFO, "PyTorchTrace")
        << "Rank set to: "
        << systrace::util::config::GlobalConfig::Instance().rank;
#endif

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

    if (pytorch_tracing_library_) {
        auto errors =
            pytorch_tracing_library_->Register(pytorch_tracing_functions_);
        for (size_t i = 0; i < pytorch_tracing_functions_.size(); ++i) {
            LOG_MODULE(INFO, "PyTorchTrace")
                << "Registered function: " << pytorch_tracing_functions_[i]
                << ", status: " << errors[i];
        }
    }
}

bool PyTorchTrace::triggerTrace() { return has_trigger_trace_.exchange(true); }

void PyTorchTrace::dumpPyTorchTracing() {
    const std::string dump_path =
        constant::TorchTraceConstant::DEFAULT_TRACE_DUMP_PATH();

    if (util::fs_utils::CreateDirectoryIfNotExists(dump_path)) {
        LOG_MODULE(ERROR, "PyTorchTrace")
            << "[PyTorchTrace] Failed to create dump directory";
        return;
    }

    std::lock_guard<std::mutex> lock(trace_mutex_);

#ifndef USE_JSON
    pytorch_trace_.set_rank(
        systrace::util::config::GlobalConfig::Instance().rank);
    pytorch_trace_.set_comm(
        systrace::util::config::GlobalConfig::Instance().job_name);
#endif

    for (size_t i = 0; i < pytorch_tracing_functions_.size(); ++i) {
        processFunctionTracingData(i);
    }

#ifndef USE_JSON
    writeTraceToFile();
#endif
}

void PyTorchTrace::processFunctionTracingData(size_t function_index) {
    if (!pytorch_tracing_library_)
        return;

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

#ifdef USE_JSON
            json item;
            item["start_us"] = data->data[i].start;
            item["end_us"] = data->data[i].end;
            item["stage_id"] = data->data[i].count;
            item["rank"] =
                systrace::util::config::GlobalConfig::Instance().rank;

            if (data->data[i].type == PAYLOAD_GC) {
                item["stage_type"] = "GC";
                item["gc_debug"] = {
                    {"collected", data->data[i].payload.gc_debug[0]},
                    {"uncollectable", data->data[i].payload.gc_debug[1]}};
            } else {
                item["stage_type"] = pytorch_tracing_functions_[function_index];
            }

            if (data->data[i].stack_depth > 0) {
                item["stack_frames"] = json::array();
                for (int j = 0; j < data->data[i].stack_depth; ++j) {
                    if (data->data[i].stack_info[j][0] != '\0') {
                        item["stack_frames"].push_back(
                            data->data[i].stack_info[j]);
                    }
                }
            }
            enqueueTraceEntry(std::move(item));
#else
            auto trace = pytorch_trace_.add_pytorch_stages();
            trace->set_start_us(data->data[i].start);
            trace->set_end_us(data->data[i].end);
            trace->set_stage_id(data->data[i].count);

            if (data->data[i].type == PAYLOAD_GC) {
                trace->set_stage_type("GC");
            } else {
                trace->set_stage_type(
                    pytorch_tracing_functions_[function_index]);
            }

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
#endif
        }
    }
    for (auto data : data_holders) {
        pytorch_tracing_library_->ReleaseTracingData(
            data, PY_TRACING_EMPTY_POOL, function_index);
    }
}

#ifdef USE_JSON
void PyTorchTrace::enqueueTraceEntry(json &&entry) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        trace_queue_.push(std::move(entry));
    }
    queue_cv_.notify_one();
}

void PyTorchTrace::writerLoop() {
    while (true) {
        std::vector<json> batch;
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(
                lock, [this] { return !trace_queue_.empty() || stop_writer_; });
            if (stop_writer_ && trace_queue_.empty())
                break;
            while (!trace_queue_.empty()) {
                batch.push_back(std::move(trace_queue_.front()));
                trace_queue_.pop();
            }
        }
        if (!batch.empty()) {
            const std::string dump_path =
                constant::TorchTraceConstant::DEFAULT_TRACE_DUMP_PATH();
            std::string file_path =
                dump_path + "/" +
                util::fs_utils::GenerateClusterUniqueFilename(".json");
            std::ofstream file(file_path, std::ios::app);
            if (file.is_open()) {
                for (const auto &entry : batch)
                    file << entry.dump() << "\n";
                file.flush();
            }
        }
    }
}
#else
void PyTorchTrace::writeTraceToFile() {
    const std::string dump_path =
        constant::TorchTraceConstant::DEFAULT_TRACE_DUMP_PATH();
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
#endif

SysTrace &SysTrace::getInstance() {
    std::call_once(init_flag_, []() {
        instance_ = new SysTrace();
        instance_->initializeSystem();
        std::atexit(cleanup);
    });
    return *instance_;
}

SysTrace::~SysTrace() {
    stopEventPoller();
#ifdef HAS_BTF_SUPPORT
    stopOsProbePoller();
#endif
}

bool SysTrace::isMsptiLibraryLoaded() {
    const char *ld_preload = std::getenv("LD_PRELOAD");
    if (!ld_preload) {
        return false;
    }
    std::string preload_str(ld_preload);
    return preload_str.find("libmspti.so") != std::string::npos;
}

void SysTrace::registerPlugins() {
    auto &cm = ControlManager::getInstance();
    cm.register_plugin(std::make_shared<HbmPlugin>());

    if (isMsptiLibraryLoaded()) {
        cm.register_plugin(std::make_shared<MsptiPlugin>());
    } else {
        LOG_MODULE(INFO, "SysTrace")
            << "libmspti.so not found in LD_PRELOAD, skipping MsptiPlugin "
               "registration";
    }

    cm.register_plugin(std::make_shared<IOPlugin>());
    cm.register_plugin(std::make_shared<MemoryPlugin>());
    cm.register_plugin(std::make_shared<CpuPlugin>());
    cm.register_plugin(std::make_shared<CacheMissPlugin>());
    cm.register_plugin(std::make_shared<GILPlugin>());
    cm.register_plugin(std::make_shared<PthreadPlugin>());
    cm.register_plugin(std::make_shared<FtracePlugin>());
    cm.register_plugin(std::make_shared<TracePlugin>());
}

void SysTrace::initializeSystem() {
    if (!systrace::util::config::GlobalConfig::Instance().enable)
        return;

    init_sys_trace_root_dir();

    systrace::util::InitializeSystemUtilities();
    registerPlugins();
    ControlManager::getInstance().start();

    PyTorchTrace::getInstance();
#ifdef HAS_BTF_SUPPORT
    os_probe_ = std::thread(&run_osprobe);
#endif
    startEventPoller();
}

void SysTrace::startEventPoller() {
    should_run_ = true;
    event_poller_ = std::thread(&SysTrace::eventPollerMain, this);
    pthread_setname_np(event_poller_.native_handle(), "systrace_poller");
}

void SysTrace::stopEventPoller() {
    should_run_ = false;
    if (event_poller_.joinable())
        event_poller_.join();
    ControlManager::getInstance().stop();
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
    PyTorchTrace::getInstance().dumpPyTorchTracing();
}

#ifdef HAS_BTF_SUPPORT
void SysTrace::stopOsProbePoller() {
    cleanup_osprobe();
    if (os_probe_.joinable())
        os_probe_.join();
}
#endif

void SysTrace::cleanup() {
    if (instance_) {
        PyTorchTrace::getInstance().dumpPyTorchTracing();
    }
#ifdef HAS_BTF_SUPPORT
    instance_->stopOsProbePoller();
#endif
}

} // namespace systrace