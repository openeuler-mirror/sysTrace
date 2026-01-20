#include "../../include/common/ICollector.hpp"
#include "../../include/log/logging.h"
#include "../../include/utils/TimerManager.hpp"
#include <atomic>

extern "C" {
void hbm_trace_set_enabled(bool enabled);
}

class HbmPlugin : public ICollector {
  public:
    std::string get_id() const override { return "HBM"; }

    bool start(const json &params) override {
        bool expected = false;
        if (!active_.compare_exchange_strong(expected, true)) {
            return true;
        }

        int duration = 0;
        if (params.contains("duration")) {
            auto &v = params["duration"];
            if (v.is_number())
                duration = v.get<int>();
            else if (v.is_string())
                duration = std::stoi(v.get<std::string>());
        }

        hbm_trace_set_enabled(true);
        LOG_MODULE(INFO, "HbmPlugin") << "HBM trace started.";

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

            LOG_MODULE(INFO, "HbmPlugin") << "HBM trace stopped.";
        }

        stop_latched_.clear(std::memory_order_release);
    }

  private:
    std::atomic<bool> active_{false};
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
};