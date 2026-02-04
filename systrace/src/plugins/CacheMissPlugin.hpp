#include "../../include/common/ICollector.hpp"
#include "../../include/common/constant.h"
#include "../../include/log/logging.h"
#include "../../include/utils/TimerManager.hpp"
#include "../../include/utils/util.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <signal.h>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

using json = nlohmann::json;
using PluginNameType = systrace::constant::Plugin;
extern "C" pid_t g_hooked_pid;

class CacheMissPlugin : public ICollector {

  public:
    CacheMissPlugin() {
        pluginName_ = PluginNameType::CACHE_MISS_PLUGIN.data();
        std::string dir = std::string(get_sys_trace_root_dir()) + pluginName_;
        systrace::util::fs_utils::CreateDirectoryIfNotExists(dir);
        output_ =
            dir + "/" + get_id() + "_" + std::to_string(g_hooked_pid) +
            "_rank_" +
            std::to_string(
                systrace::util::config::GlobalConfig::Instance().local_rank) +
            ".txt";
    }
    bool start(const json &params, int duration) override {
        if (systrace::util::config::GlobalConfig::Instance().local_rank != 0) {
            return true;
        }

        if (active_.load() && !is_actually_running()) {
            LOG_MODULE(INFO, pluginName_)
                << " Detected zombie state, auto-resetting...";
            reset_plugin_state();
        }

        bool expected = false;
        if (!active_.compare_exchange_strong(expected, true)) {
            return false;
        }

        std::string args = params.value("args", "");
        if (args.empty()) {
            LOG_MODULE(ERROR, pluginName_)
                << "Failed to start: 'args' (target command) is empty.";
            active_.store(false);
            return false;
        }
        std::string full_cmd = "perf stat " + args + " -o " + output_ + " 2>&1";
        LOG_MODULE(INFO, pluginName_) << " Output file: " << output_;

        perf_pid_ = fork();
        if (perf_pid_ == 0) {
            setpgid(0, 0);
            execl("/bin/sh", "sh", "-c", full_cmd.c_str(), nullptr);
            _exit(127);
        } else if (perf_pid_ > 0) {
            std::thread([this, pid = perf_pid_]() {
                int status;
                waitpid(pid, &status, 0);
                this->handle_child_exit(status);
            }).detach();

            if (duration > 0) {
                systrace::utils::TimerManager::getInstance().startTimer(
                    get_id(), duration, [this]() { this->stop(); });
            }
            return true;
        }
        return false;
    }

    void stop() override {
        if (systrace::util::config::GlobalConfig::Instance().local_rank != 0) {
            return;
        }
        if (stop_latched_.test_and_set(std::memory_order_acquire))
            return;

        if (active_.load() && perf_pid_ > 0) {
            if (is_actually_running()) {
                kill(-perf_pid_, SIGINT);
            }

            systrace::utils::TimerManager::getInstance().stopTimer(get_id());
        }
        stop_latched_.clear(std::memory_order_release);
    }

    void reset_plugin_state() {
        active_.store(false);
        perf_pid_ = -1;
    }

    bool is_actually_running() {
        if (perf_pid_ <= 0)
            return false;
        int status;
        pid_t res = waitpid(perf_pid_, &status, WNOHANG);
        return (res == 0);
    }

  private:
    void handle_child_exit(int status) {
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            LOG_MODULE(ERROR, pluginName_)
                << " Subprocess exited with error code: "
                << WEXITSTATUS(status);
        }

        perf_pid_ = -1;
        active_.store(false);
        LOG_MODULE(INFO, pluginName_) << " stop.";
    }

    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
    pid_t perf_pid_ = -1;
    std::string output_;
};