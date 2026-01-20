#include "../../include/common/ICollector.hpp"
#include "../../include/log/logging.h"
#include "../../include/utils/TimerManager.hpp"
#include <atomic>

extern "C" {
void io_trace_set_enabled(bool enabled);
}

class IOPlugin : public ICollector {

  public:
    IOPlugin() { pluginName_ = PluginNameType::IO_PLUGIN.data(); }
    bool start(const json &params, int duration) override {
        bool expected = false;
        if (!active_.compare_exchange_strong(expected, true)) {
            return true;
        }

        io_trace_set_enabled(true);
        LOG_MODULE(INFO, pluginName_) << "IO trace started.";

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
            io_trace_set_enabled(false);
            active_.store(false);

            systrace::utils::TimerManager::getInstance().stopTimer(get_id());

            LOG_MODULE(INFO, pluginName_) << "IO trace stopped.";
        }

        stop_latched_.clear(std::memory_order_release);
    }

  private:
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
};