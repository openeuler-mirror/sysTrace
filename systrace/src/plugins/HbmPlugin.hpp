#include "../../include/common/ICollector.hpp"
#include "../../include/log/logging.h"
#include "../../include/utils/TimerManager.hpp"
#include <atomic>

extern "C" {
void hbm_trace_set_enabled(bool enabled);
}

class HbmPlugin : public ICollector {

  public:
    HbmPlugin() {
        pluginName_ = PluginNameType::HBM_PLUGIN.data();
    }
    bool start(const json &params, int duration) override {
        bool expected = false;
        if (!active_.compare_exchange_strong(expected, true)) {
            return true;
        }

        hbm_trace_set_enabled(true);
        LOG_MODULE(INFO, pluginName_) << "HBM trace started.";

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
            hbm_trace_set_enabled(false);
            active_.store(false);

            systrace::utils::TimerManager::getInstance().stopTimer(get_id());

            LOG_MODULE(INFO, pluginName_) << "HBM trace stopped.";
        }

        stop_latched_.clear(std::memory_order_release);
    }

  private:
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
};