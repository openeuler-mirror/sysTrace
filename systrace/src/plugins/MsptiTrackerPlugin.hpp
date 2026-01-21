#pragma once
#include "../../include/common/ICollector.hpp"
#include "../../include/utils/TimerManager.hpp"
#include "../mspti/mspti_tracker.hpp"
#include <atomic>
#include <string>

class MsptiPlugin : public ICollector {
  public:
    MsptiPlugin() { pluginName_ = PluginNameType::MSPTI_PLUGIN.data(); }
    bool start(const json &params, int duration) override {
        uint32_t mask = MSPTI_EVENT_NONE;
        if (params.contains("event")) {
            std::string events = params["event"];
            if (events.find("marker") != std::string::npos)
                mask |= MSPTI_EVENT_MARKER;
            if (events.find("kernel") != std::string::npos)
                mask |= MSPTI_EVENT_KERNEL;
            if (events.find("api") != std::string::npos)
                mask |= MSPTI_EVENT_API;
        }
        if (mask == MSPTI_EVENT_NONE)
            mask = MSPTI_EVENT_MARKER;

        MSPTITracker::getInstance().setEventMask(mask);

        if (active_.load()) {
            systrace::utils::TimerManager::getInstance().stopTimer(get_id());
        } else {
            active_.store(true);
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
            MSPTITracker::getInstance().setEventMask(MSPTI_EVENT_NONE);
            active_.store(false);
            systrace::utils::TimerManager::getInstance().stopTimer(get_id());
        }
        stop_latched_.clear(std::memory_order_release);
    }

  private:
    std::atomic<bool> active_{false};
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
};