#pragma once
#include <thread>
#include <chrono>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <map>
#include <atomic>
#include <vector>

namespace systrace {
namespace utils {

class TimerManager {
public:
    static TimerManager& getInstance() {
        static TimerManager instance;
        return instance;
    }

    void startTimer(const std::string& id, int duration, std::function<void()> callback) {
        stopTimer(id);

        std::lock_guard<std::mutex> lock(mtx_);
        auto is_active = std::make_shared<std::atomic<bool>>(true);
        active_tasks_[id] = is_active;

        std::thread([this, id, duration, callback, is_active]() {
            {
                std::unique_lock<std::mutex> lk(this->cv_mtx_);
                this->cv_.wait_for(lk, std::chrono::seconds(duration), [is_active] {
                    return !is_active->load();
                });
            }

            if (is_active->load()) {
                callback();
            }

            std::lock_guard<std::mutex> clean_lock(this->mtx_);
            auto it = this->active_tasks_.find(id);
            if (it != this->active_tasks_.end() && it->second == is_active) {
                this->active_tasks_.erase(it);
            }
        }).detach();
    }

    void stopTimer(const std::string& id) {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = active_tasks_.find(id);
        if (it != active_tasks_.end()) {
            it->second->store(false);
            active_tasks_.erase(it);
            cv_.notify_all();
        }
    }

    void clearAll() {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto& pair : active_tasks_) {
            pair.second->store(false);
        }
        active_tasks_.clear();
        cv_.notify_all();
    }

private:
    TimerManager() = default;
    ~TimerManager() { clearAll(); }
    
    std::mutex mtx_;
    std::mutex cv_mtx_;
    std::condition_variable cv_;
    std::map<std::string, std::shared_ptr<std::atomic<bool>>> active_tasks_;
};

} // namespace utils
} // namespace systrace