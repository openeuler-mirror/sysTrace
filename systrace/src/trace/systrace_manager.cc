#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "../../include/common/constant.h"
#include "../../include/common/shared_constants.h"
#include "systrace_manager.h"
// #include "../../src/os/os_probe.h"

int global_stage_id = 0;
int global_stage_type = 0;

#ifdef HAS_BTF_SUPPORT
extern "C" {
    int run_osprobe();
    void cleanup_osprobe();
}
#endif

namespace systrace
{

namespace
{
constexpr uint64_t TRACE_INTERVAL = 100;
constexpr std::chrono::milliseconds POLL_INTERVAL(10);
} // namespace

PyTorchTrace &PyTorchTrace::getInstance()
{
    std::call_once(init_flag_,
                   []()
                   {
                       instance_ = new PyTorchTrace();
                       instance_->initialize();
                   });
    return *instance_;
}

PyTorchTrace::PyTorchTrace()
{
    writer_thread_ = std::thread(&PyTorchTrace::writerLoop, this);
}

PyTorchTrace::~PyTorchTrace()
{
    stop_writer_ = true;
    queue_cv_.notify_one();
    if (writer_thread_.joinable())
        writer_thread_.join();

    if (pytorch_tracing_library_)
    {
        delete pytorch_tracing_library_;
        pytorch_tracing_library_ = nullptr;
    }
}

void PyTorchTrace::initialize()
{
    STLOG(INFO) << "[PyTorchTrace] Initializing PyTorchTrace";

    pytorch_tracing_library_ =
        new pytorch_tracing::PyTorchTracingLibrary("libsysTrace.so");
    STLOG(INFO) << "[PyTorchTrace] Tracing library loaded";

    registerTracingFunctions();
}

void PyTorchTrace::registerTracingFunctions()
{
    std::ifstream funcListFile(PyFuncListPath_);
    std::string line;
    if (!funcListFile.is_open())
    {
        STLOG(ERROR) << "Failed to open PyFuncList file";
        return;
    }
    while (std::getline(funcListFile, line))
    {
        if (!line.empty() && line[0] != '#')
        {
            pytorch_tracing_functions_.emplace_back(line);
        }
    }

    funcListFile.close();

    auto errors =
        pytorch_tracing_library_->Register(pytorch_tracing_functions_);
    for (size_t i = 0; i < pytorch_tracing_functions_.size(); ++i)
    {
        STLOG(INFO) << "Registered function: " << pytorch_tracing_functions_[i]
                    << ", status: " << errors[i];
    }
}

bool PyTorchTrace::triggerTrace()
{
    SharedData *shared_data = get_shared_data();
    if (!shared_data)
        return false;

    return has_trigger_trace_.exchange(true) && shared_data->g_dump_L0;
}

void PyTorchTrace::dumpPyTorchTracing()
{
    for (size_t i = 0; i < pytorch_tracing_functions_.size(); ++i)
    {
        processFunctionTracingData(i);
    }
}

void PyTorchTrace::processFunctionTracingData(size_t function_index)
{
    std::vector<PyTorchTracingDataArray *> data_holders;

    if (auto data = pytorch_tracing_library_->RetrievePartialTracingData(function_index))
    {
        data_holders.emplace_back(data);
    }

    while (auto data = pytorch_tracing_library_->RetrieveAllTracingData(function_index))
    {
        data_holders.emplace_back(data);
    }
    for (auto data : data_holders)
    {
        for (uint32_t i = 0; i < data->cur; ++i)
        {
            if (data->data[i].start == 0)
                continue;

            json trace_entry = json::object();
            trace_entry["start_us"] = data->data[i].start;
            trace_entry["end_us"] = data->data[i].end;
            trace_entry["stage_id"] = data->data[i].count;

            if (data->data[i].type == PAYLOAD_GC)
            {
                trace_entry["stage_type"] = "GC";
                json gc_debug = json::object();
                gc_debug["collected"] = data->data[i].payload.gc_debug[0];
                gc_debug["uncollectable"] = data->data[i].payload.gc_debug[1];
                trace_entry["gc_debug"] = gc_debug;
            }
            else
            {
                trace_entry["stage_type"] = pytorch_tracing_functions_[function_index];
            }

            if (data->data[i].stack_depth > 0)
            {
                trace_entry["stack_frames"] = json::array();
                for (int j = 0; j < data->data[i].stack_depth; ++j)
                {
                    if (data->data[i].stack_info[j][0] != '\0')
                        trace_entry["stack_frames"].emplace_back(data->data[i].stack_info[j]);
                }
            }

            enqueueTraceEntry(std::move(trace_entry));
        }
    }

    for (auto data : data_holders)
    {
        pytorch_tracing_library_->ReleaseTracingData(data, PY_TRACING_EMPTY_POOL, function_index);
    }
}

void PyTorchTrace::enqueueTraceEntry(json &&entry)
{
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        trace_queue_.push(std::move(entry));
    }
    queue_cv_.notify_one();
}

void PyTorchTrace::writerLoop()
{
    while (true)
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        queue_cv_.wait(lock, [this] { return !trace_queue_.empty() || stop_writer_; });

        if (stop_writer_ && trace_queue_.empty())
            break;

        while (!trace_queue_.empty())
        {
            auto entry = std::move(trace_queue_.front());
            trace_queue_.pop();
            lock.unlock();

            writeTraceEntryToFile(entry);

            lock.lock();
        }
    }
}

void PyTorchTrace::writeTraceEntryToFile(const json &entry)
{
    const std::string &dump_path = std::string(constant::TorchTraceConstant::DEFAULT_TRACE_DUMP_PATH);
    util::fs_utils::CreateDirectoryIfNotExists(dump_path);

    std::string file_path = dump_path + "/" + util::fs_utils::GenerateClusterUniqueFilename(".json");
    std::ofstream file(file_path, std::ios::app);
    if (file.is_open())
    {
        file << entry.dump() << "\n";
    }
    else
    {
        STLOG(ERROR) << "[PyTorchTrace] Failed to open file: " << file_path;
    }
}

// ======================== SysTrace ========================

SysTrace &SysTrace::getInstance()
{
    std::call_once(init_flag_,
                   []()
                   {
                       instance_ = new SysTrace();
                       instance_->initializeSystem();
                       std::atexit(cleanup);
                   });
    return *instance_;
}

SysTrace::~SysTrace()
{
#ifdef HAS_BTF_SUPPORT
    stopOsProbePoller();
#endif
    stopEventPoller();
}

void SysTrace::initializeSystem()
{
    if (!config::GlobalConfig::Instance().enable)
        return;

    systrace::util::InitializeSystemUtilities();
    MonitorServer::getInstance();
    PyTorchTrace::getInstance();
#ifdef HAS_BTF_SUPPORT
    os_probe_ = std::thread(&run_osprobe);
#endif

    startEventPoller();
}

void SysTrace::startEventPoller()
{
#ifdef _GNU_SOURCE
    should_run_ = true;
    event_poller_ = std::thread(&SysTrace::eventPollerMain, this);
    pthread_setname_np(event_poller_.native_handle(), "systrace_poller");
#endif
    STLOG(INFO) << "[SysTrace] Event poller started";
}

#ifdef HAS_BTF_SUPPORT
void SysTrace::stopOsProbePoller()
{
    cleanup_osprobe();
    if (os_probe_.joinable())
        os_probe_.join();
}
#endif

void SysTrace::stopEventPoller()
{
    should_run_ = false;
    if (event_poller_.joinable())
        event_poller_.join();
}

void SysTrace::eventPollerMain()
{
    while (should_run_)
    {
        if (loop_count_++ % TRACE_INTERVAL == 0)
        {
            if (PyTorchTrace::getInstance().triggerTrace())
            {
                PyTorchTrace::getInstance().dumpPyTorchTracing();
            }
        }
        std::this_thread::sleep_for(POLL_INTERVAL);
    }

    if (PyTorchTrace::getInstance().triggerTrace())
    {
        PyTorchTrace::getInstance().dumpPyTorchTracing();
    }
}

} // namespace systrace