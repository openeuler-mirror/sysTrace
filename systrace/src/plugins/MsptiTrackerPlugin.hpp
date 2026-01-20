#pragma once
#include "../../include/common/ICollector.hpp"
#include "../../include/utils/TimerManager.hpp"
#include "../mspti/mspti_tracker.hpp"
#include <atomic>
#include <iostream>

class MsptiPlugin : public ICollector {
  public:
    std::string get_id() const override { return "MSPTI"; }

    bool start(const json &params) override {
        if (active_.exchange(true))
            return true;

        MSPTITracker::getInstance().setExternalEnable(true);

        int duration = 0;
        if (params.contains("duration")) {
            auto &v = params["duration"];
            duration =
                v.is_number() ? v.get<int>() : std::stoi(v.get<std::string>());
        }

        if (duration > 0) {
            systrace::utils::TimerManager::getInstance().startTimer(
                get_id(), duration, [this]() { this->stop(); });
        }
        return true;
    }

    void stop() override {
        if (stop_latched_.test_and_set(std::memory_order_acquire))
            return;

        if (active_.load()) {
            MSPTITracker::getInstance().setExternalEnable(false);

            active_.store(false);

            systrace::utils::TimerManager::getInstance().stopTimer(get_id());
        }

        stop_latched_.clear(std::memory_order_release);
    }

  private:
    std::atomic<bool> active_{false};
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
};