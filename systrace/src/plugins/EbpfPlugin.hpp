#include "../../include/common/ICollector.hpp"
#include "../../include/utils/TimerManager.hpp"
#include "../os/os_probe.h"
#include <iostream>
#include <atomic>

extern "C" {
    void os_probe_enable_event(os_probe_type_e type);
    void os_probe_disable_event(os_probe_type_e type);
}

class MemoryPlugin : public ICollector {
    public:
        std::string get_id() const override { return "Memory"; }
    
        bool start(const json& params) override {
            bool expected = false;
            if (!active_.compare_exchange_strong(expected, true)) {
                return true; 
            }
    
            int duration = 0;
            if (params.contains("duration")) {
                auto& v = params["duration"];
                if (v.is_number()) duration = v.get<int>();
                else if (v.is_string()) duration = std::stoi(v.get<std::string>());
            }
    
            os_probe_enable_event(OS_PROBE_MEM);
            std::cout << "[MemoryPlugin] Memory trace started." << std::endl;
    
            if (duration > 0) {
                systrace::utils::TimerManager::getInstance().startTimer(get_id(), duration, [this]() {
                    this->stop();
                });
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
                
                std::cout << "[MemoryPlugin] Memory trace stopped." << std::endl;
            }
            
            stop_latched_.clear(std::memory_order_release);
        }
    
    private:
        std::atomic<bool> active_{false};
        std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
    };

class CpuPlugin : public ICollector {
    public:
    std::string get_id() const override { return "CPU"; }

    bool start(const json& params) override {
        bool expected = false;
        if (!active_.compare_exchange_strong(expected, true)) {
            return true; 
        }

        int duration = 0;
        if (params.contains("duration")) {
            auto& v = params["duration"];
            if (v.is_number()) duration = v.get<int>();
            else if (v.is_string()) duration = std::stoi(v.get<std::string>());
        }

        os_probe_enable_event(OS_PROBE_CPU);
        std::cout << "[CPUPlugin] CPU trace started." << std::endl;

        if (duration > 0) {
            systrace::utils::TimerManager::getInstance().startTimer(get_id(), duration, [this]() {
                this->stop();
            });
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
            
            std::cout << "[CPUPlugin] CPU trace stopped." << std::endl;
        }
        
        stop_latched_.clear(std::memory_order_release);
    }

private:
    std::atomic<bool> active_{false};
    std::atomic_flag stop_latched_ = ATOMIC_FLAG_INIT;
    };