#include "../../include/common/ICollector.hpp"
#include "../../include/log/logging.h"
#include "../../include/utils/TimerManager.hpp"
#include "../os/os_probe.h"
#include <atomic>

extern "C" {
void os_probe_enable_event(os_probe_type_e type);
void os_probe_disable_event(os_probe_type_e type);
}

class MemoryPlugin : public ICollector {

  public:
    MemoryPlugin() {
        pluginName_ = PluginNameType::MEMORY_PLUGIN.data();
    }
    bool start(const json &params, int duration) override {
        bool expected = false;
        if (!active_.compare_exchange_strong(expected, true)) {
            return true;
        }

        os_probe_enable_event(OS_PROBE_MEM);
        LOG_MODULE(INFO, pluginName_) << "Memory trace started.";

        if (duration > 0) {
            systrace::utils::TimerManager::getInstance().startTimer(
                get_id(), duration, [this]() { this->stop(); });
        }
        return true;
    }

    void stop() override {
        if (stop_latched_.test_and_set(std::memory_order_acquire)) {
            return;
        }

        if (active_.load()) {
            os_probe_disable_event(OS_PROBE_MEM);
            active_.store(false);

            systrace::utils::TimerManager::getInstance().stopTimer(get_id());

            LOG_MODULE(INFO, pluginName_) << "Memory trace stopped.";
        }

        stop_latched_.clear(std::memory_order_release);
    }

  private:
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
};

class CpuPlugin : public ICollector {

  public:
    CpuPlugin() {
        pluginName_ = PluginNameType::CPU_PLUGIN.data();
    }
    bool start(const json &params, int duration) override {
        bool expected = false;
        if (!active_.compare_exchange_strong(expected, true)) {
            return true;
        }

        os_probe_enable_event(OS_PROBE_CPU);
        LOG_MODULE(INFO, pluginName_) << "CPU trace started.";

        if (duration > 0) {
            systrace::utils::TimerManager::getInstance().startTimer(
                get_id(), duration, [this]() { this->stop(); });
        }
        return true;
    }

    void stop() override {
        if (stop_latched_.test_and_set(std::memory_order_acquire)) {
            return;
        }

        if (active_.load()) {
            os_probe_disable_event(OS_PROBE_CPU);
            active_.store(false);

            systrace::utils::TimerManager::getInstance().stopTimer(get_id());

            LOG_MODULE(INFO, pluginName_) << "CPU trace stopped.";
        }

        stop_latched_.clear(std::memory_order_release);
    }

  private:
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
};