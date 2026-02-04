#include "FtracePlugin.h"
#include "../../../include/common/constant.h"

extern "C" pid_t g_hooked_pid;

FtracePlugin::FtracePlugin() {
    pluginName_ = PluginNameType::FTRACE_PLUGIN.data();
    active_.store(false);
    stop_flag_.store(true);
    std::string dir = std::string(get_sys_trace_root_dir()) + pluginName_;
    systrace::util::fs_utils::CreateDirectoryIfNotExists(dir);
    output_ = dir + "/" + get_id() + "_" + std::to_string(g_hooked_pid) +
              "_rank_" + std::to_string(get_local_rank()) + ".log";
}

FtracePlugin::~FtracePlugin() { stop(); }

bool FtracePlugin::start(const json &params, int duration) {
    if (systrace::util::config::GlobalConfig::Instance().local_rank != 0)
        return true;
    bool expected = false;
    if (!active_.compare_exchange_strong(expected, true)) {
        LOG_MODULE(INFO, pluginName_) << "already starting";
        return true;
    }

    try {
        task_config_ = parse_config_from_json(params);
        ftrace_path_ = PluginUtils::ensure_ftrace_path();

        std::vector<int> target_cpus;
        PluginUtils::parse_cpu_list(task_config_.cpu_list, target_cpus);

        if (!init_ftrace())
            throw std::runtime_error("Ftrace init fail");

        output_dir_ =
            std::string(get_sys_trace_root_dir()) + pluginName_ + "/tmp";
        mkdir(output_dir_.c_str(), 0755);

        stop_flag_.store(false);
        collect_duration_ = duration;

        for (int cpu_id : target_cpus) {
            CpuReader reader;
            reader.cpu_id = cpu_id;

            std::string raw_path = ftrace_path_ + "per_cpu/cpu" +
                                   std::to_string(cpu_id) + "/trace_pipe";
            reader.raw_fd = open(raw_path.c_str(), O_RDONLY | O_NONBLOCK);

            std::string out_path =
                output_dir_ + "/cpu" + std::to_string(cpu_id) + ".raw";
            reader.out_fd =
                open(out_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);

            if (pipe(reader.pipe_fds) == -1)
                throw std::runtime_error("Pipe fail");
            fcntl(reader.pipe_fds[0], F_SETPIPE_SZ, K_SPLICE_SIZE);
            fcntl(reader.pipe_fds[1], F_SETPIPE_SZ, K_SPLICE_SIZE);

            if (reader.raw_fd < 0 || reader.out_fd < 0)
                throw std::runtime_error("Open per-cpu FD fail");
            cpu_readers_.push_back(std::move(reader));
        }
        for (auto &reader : cpu_readers_) {
            reader.worker = std::thread(&FtracePlugin::per_cpu_splice_loop,
                                        this, std::ref(reader));
        }
        if (duration > 0) {
            systrace::utils::TimerManager::getInstance().startTimer(
                get_id(), duration, [this]() { this->stop(); });
        }

        LOG_MODULE(INFO, pluginName_)
            << "Parallel Ftrace started. Output file: " << output_;
        return true;
    } catch (const std::exception &e) {
        LOG_MODULE(ERROR, pluginName_) << "Start failed: " << e.what();
        reset_plugin_state();
        return false;
    }
}

void FtracePlugin::stop() {
    if (get_local_rank() != 0)
        return;
    if (stop_flag_.exchange(true))
        return;

    if (active_.load()) {
        try {
            PluginUtils::write_file(ftrace_path_ + "tracing_on", "0");
            systrace::utils::TimerManager::getInstance().stopTimer(get_id());

            for (auto &reader : cpu_readers_) {
                if (reader.worker.joinable())
                    reader.worker.join();
            }

            cleanup_resources();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            LOG_MODULE(DEBUG, pluginName_)
                << "Parallel ftrace stop. All CPU buffers flushed.";
            reset_ftrace();

            active_.store(false);
            LOG_MODULE(DEBUG, pluginName_)
                << "All collection threads joined. Starting data aggregation "
                   "and processing...";
            process_raw_data();

            output_dir_.clear();
            cpu_readers_.clear();
            LOG_MODULE(INFO, pluginName_) << "Parallel ftrace stop.";
        } catch (const std::exception &e) {
            LOG_MODULE(ERROR, pluginName_) << "stop failed: " << e.what();
            return;
        }
    }
}

void FtracePlugin::per_cpu_splice_loop(CpuReader &reader) {
    const auto start_time = std::chrono::steady_clock::now();

    while (true) {
        bool should_exit = stop_flag_.load();
        if (collect_duration_ > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::steady_clock::now() - start_time)
                               .count();
            if (elapsed >= collect_duration_)
                should_exit = true;
        }

        // 零拷贝：Raw FD -> Pipe In -> Pipe Out -> File FD
        ssize_t moved =
            splice(reader.raw_fd, nullptr, reader.pipe_fds[1], nullptr,
                   K_SPLICE_SIZE, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);

        if (moved > 0) {
            splice(reader.pipe_fds[0], nullptr, reader.out_fd, nullptr, moved,
                   SPLICE_F_MOVE);
        } else if (moved < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (should_exit)
                    break;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }
            break;
        } else
            break;

        if (should_exit && moved <= 0)
            break;
    }
    fsync(reader.out_fd);
}

void FtracePlugin::process_raw_data() {
    std::remove(output_.c_str());
    std::ofstream outfile(output_,
                          std::ios::out | std::ios::trunc | std::ios::binary);

    for (const auto &reader : cpu_readers_) {
        std::string part_path =
            output_dir_ + "/cpu" + std::to_string(reader.cpu_id) + ".raw";
        std::ifstream infile(part_path);
        if (infile.is_open()) {
            outfile << infile.rdbuf();
            infile.close();
            std::remove(part_path.c_str());
        }
    }
    outfile.close();
}

int FtracePlugin::get_local_rank() {
    return systrace::util::config::GlobalConfig::Instance().local_rank;
}

bool FtracePlugin::init_ftrace() {
    reset_ftrace();
    std::vector<int> cpus;
    PluginUtils::parse_cpu_list(task_config_.cpu_list, cpus);
    PluginUtils::write_file(ftrace_path_ + "tracing_cpumask",
                            PluginUtils::generate_cpu_mask(cpus));
    PluginUtils::write_file(ftrace_path_ + "buffer_size_kb",
                            task_config_.core_config.buffer_size_kb);

    for (const auto &ev : task_config_.core_config.enable_events) {
        PluginUtils::write_file(ftrace_path_ + "events/" + ev + "/enable", "1");
    }
    if (!task_config_.core_config.trace_functions.empty()) {
        PluginUtils::write_file(ftrace_path_ + "current_tracer",
                                task_config_.core_config.function_tracer);
        PluginUtils::write_file(ftrace_path_ + "set_ftrace_filter",
                                task_config_.core_config.trace_functions);
    }
    if (!task_config_.core_config.ftrace_pid.empty()) {
        PluginUtils::write_file(ftrace_path_ + "set_ftrace_pid",
                                task_config_.core_config.ftrace_pid);
    }
    if (!task_config_.core_config.event_pid.empty()) {
        PluginUtils::write_file(ftrace_path_ + "set_event_pid",
                                task_config_.core_config.event_pid);
    }
    PluginUtils::write_file(ftrace_path_ + "options/stacktrace",
                            task_config_.core_config.stack_trace ? "1" : "0");
    PluginUtils::write_file(ftrace_path_ + "tracing_on", "1");
    return true;
}

void FtracePlugin::reset_ftrace() {
    if (ftrace_path_.empty())
        return;

    try {
        PluginUtils::write_file(ftrace_path_ + "tracing_on", "0");
    } catch (...) {}

    try {
        PluginUtils::write_file(ftrace_path_ + "events/enable", "0");
    } catch (...) {}

    try {
        PluginUtils::write_file(ftrace_path_ + "set_ftrace_filter", "");
    } catch (...) {}
    try {
        PluginUtils::write_file(ftrace_path_ + "set_graph_function", "");
    } catch (...) {}

    try {
        PluginUtils::write_file(ftrace_path_ + "set_ftrace_pid", "");
    } catch (...) {}

    try {
        PluginUtils::write_file(ftrace_path_ + "current_tracer", "nop");
    } catch (const std::exception &e) {
        LOG_MODULE(WARN, pluginName_) << "Final Tracer reset still busy. This "
                                         "usually means an unclosed FD exists. "
                                      << e.what();
    }
}

TraceTaskConfig
FtracePlugin::parse_config_from_json(const nlohmann::json &params) {
    TraceTaskConfig config;
    try {
        if (params.contains("cpu_list")) {
            config.cpu_list = params.at("cpu_list").get<std::string>();
        } else {
            throw std::invalid_argument("miss cpu_list");
        }

        auto &core = config.core_config;

        if (params.contains("events")) {
            auto &events = params.at("events");
            if (events.is_array()) {
                core.enable_events = events.get<std::vector<std::string>>();
            } else if (events.is_string()) {
                core.enable_events =
                    PluginUtils::split_string(events.get<std::string>());
            } else {
                throw std::invalid_argument("events type error");
            }
            core.enable_events.erase(
                std::remove_if(core.enable_events.begin(),
                               core.enable_events.end(),
                               [](const std::string &s) { return s.empty(); }),
                core.enable_events.end());
        }

        if (params.contains("func")) {
            auto &func = params.at("func");
            if (!func.is_string()) {
                throw std::invalid_argument("func type error");
            }
            std::string func_str = func.get<std::string>();
            std::replace(func_str.begin(), func_str.end(), ',', ' ');
            core.trace_functions = func_str;
        }

        if (params.contains("set_ftrace_pid")) {
            auto &sfp = params.at("set_ftrace_pid");
            if (!sfp.is_string()) {
                throw std::invalid_argument("trace_pid type error");
            }
            core.ftrace_pid = sfp.get<std::string>();
        }

        if (params.contains("set_event_pid")) {
            auto &sep = params.at("set_event_pid");
            if (!sep.is_string()) {
                throw std::invalid_argument("event_pid type error");
            }
            core.event_pid = sep.get<std::string>();
        }

        if (params.contains("buffer_size_kb")) {
            auto &bsk = params.at("buffer_size_kb");
            if (!bsk.is_string()) {
                throw std::invalid_argument("buffer_size_kb type error");
            }
            core.buffer_size_kb = bsk.get<std::string>();
        }

        if (params.contains("event_stack_trace")) {
            core.stack_trace =
                PluginUtils::safe_parse_boolean(params.at("event_stack_trace"));
        }

        if (params.contains("func_stack_trace")) {
            core.func_stack_trace =
                PluginUtils::safe_parse_boolean(params.at("func_stack_trace"));
        }

        if (params.contains("function_tracer")) {
            auto &ft = params.at("function_tracer");
            if (!ft.is_string()) {
                throw std::invalid_argument("function_tracer type error");
            }
            core.function_tracer = ft.get<std::string>();
        }

    } catch (...) { throw std::runtime_error("parse_config_from_json error"); }

    return config;
}

void FtracePlugin::cleanup_resources() {
    for (auto &reader : cpu_readers_) {
        if (reader.raw_fd >= 0) {
            close(reader.raw_fd);
            reader.raw_fd = -1;
        }
        if (reader.out_fd >= 0) {
            close(reader.out_fd);
            reader.out_fd = -1;
        }
        if (reader.pipe_fds[0] >= 0) {
            close(reader.pipe_fds[0]);
            close(reader.pipe_fds[1]);
            reader.pipe_fds[0] = reader.pipe_fds[1] = -1;
        }
    }
}

void FtracePlugin::reset_plugin_state() {
    active_.store(false);
    stop_flag_.store(true);
    cleanup_resources();
}