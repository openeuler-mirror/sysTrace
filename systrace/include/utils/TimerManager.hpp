#pragma once
#include <thread>
#include <chrono>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <map>
#include <atomic>
#include <memory>
#include <string>
#include "../../include/log/logging.h"

namespace systrace {
namespace utils {

class TimerManager {
public:
    struct TimerTask {
        std::atomic<bool> active{true};
        std::mutex task_mtx;
        std::condition_variable task_cv;
    };

    static TimerManager& getInstance() {
        static TimerManager instance;
        return instance;
    }

    void startTimer(const std::string& id, int duration, std::function<void()> callback) {
        stopTimer(id);

        auto task = std::make_shared<TimerTask>();
        {
            std::lock_guard<std::mutex> lock(map_mtx_);
            active_tasks_[id] = task;
        }

        std::thread([this, id, duration, callback, task]() {
            {
                std::unique_lock<std::mutex> lk(task->task_mtx);
                task->task_cv.wait_for(lk, std::chrono::seconds(duration), [&task] {
                    return !task->active.load();
                });
            }

            if (task->active.load()) {
                callback();
            }

            std::lock_guard<std::mutex> lock(this->map_mtx_);
            auto it = this->active_tasks_.find(id);
            if (it != this->active_tasks_.end() && it->second == task) {
                this->active_tasks_.erase(it);
            }
        }).detach();
    }

    void stopTimer(const std::string& id) {
        std::shared_ptr<TimerTask> task_to_stop;
        {
            std::lock_guard<std::mutex> lock(map_mtx_);
            auto it = active_tasks_.find(id);
            if (it != active_tasks_.end()) {
                task_to_stop = it->second;
                active_tasks_.erase(it);
            }
        }

        if (task_to_stop) {
            task_to_stop->active.store(false);
            task_to_stop->task_cv.notify_one();
        }
    }

    void clearAll() {
        std::lock_guard<std::mutex> lock(map_mtx_);
        for (auto& pair : active_tasks_) {
            pair.second->active.store(false);
            pair.second->task_cv.notify_one();
        }
        active_tasks_.clear();
    }

private:
    TimerManager() = default;
    ~TimerManager() { clearAll(); }
    
    std::mutex map_mtx_;
    std::map<std::string, std::shared_ptr<TimerTask>> active_tasks_;

    TimerManager(const TimerManager&) = delete;
    TimerManager& operator=(const TimerManager&) = delete;
};

} 
}