#pragma once
#include <unordered_map>
#include <memory>
#include <thread>
#include <atomic>
#include "../../../include/common/ICollector.hpp" 
#include "../../../include/log/logging.h"
#include "../../../include/utils/util.h"

class ControlManager {
public:
    static ControlManager& getInstance();

    ControlManager(const ControlManager&) = delete;
    ControlManager& operator=(const ControlManager&) = delete;

    void register_plugin(std::shared_ptr<ICollector> col);
    void start();
    void stop();

private:
    ControlManager() = default;
    ~ControlManager();

    void uds_worker();
    std::string handle_msg(const std::string& raw);

    std::unordered_map<std::string, std::shared_ptr<ICollector>> registry_;
    std::thread server_thread_;
    std::atomic<bool> is_running_{false};
};