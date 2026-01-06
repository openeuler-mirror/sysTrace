#include "ControlManager.hpp"
#include "../../include/common/constant.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <iostream>

using CliConst = systrace::constant::Cli;

ControlManager& ControlManager::getInstance() {
    static ControlManager instance;
    return instance;
}

ControlManager::~ControlManager() {
    is_running_ = false;
    if (server_thread_.joinable()) {
        server_thread_.detach();
    }
}

void ControlManager::register_plugin(std::shared_ptr<ICollector> col) {
    if (col) registry_[col->get_id()] = col;
}

void ControlManager::start() {
    if (is_running_.exchange(true)) return;
    server_thread_ = std::thread(&ControlManager::uds_worker, this);
    server_thread_.detach();
}

void ControlManager::uds_worker() {
    std::string sock_path = std::string(CliConst::SOCK_DIR) + 
                            CliConst::SOCK_PREFIX + 
                            std::to_string(getpid()) + 
                            CliConst::SOCK_EXT;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return;

    sockaddr_un addr{.sun_family = AF_UNIX};
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    unlink(sock_path.c_str());
    if (bind(fd, (sockaddr*)&addr, sizeof(addr)) == -1) {
        close(fd);
        return;
    }

    listen(fd, 5);

    while (is_running_) {
        int cfd = accept(fd, nullptr, nullptr);
        if (cfd < 0) continue;

        char buf[CliConst::MAX_BUF_SIZE] = {0};
        if (read(cfd, buf, sizeof(buf) - 1) > 0) {
            std::string res = handle_msg(buf);
            write(cfd, res.c_str(), res.size());
        }
        close(cfd);
    }
    close(fd);
    unlink(sock_path.c_str());
}

std::string ControlManager::handle_msg(const std::string& raw) {
    try {
        auto data = json::parse(raw);
        std::string path = data.at(CliConst::KEY_PATH);
        std::string act  = data.at(CliConst::KEY_ACTION);
        json params      = data.value(CliConst::KEY_PARAMS, json::object());

        if (registry_.count(path)) {
            if (act == CliConst::ACT_ENABLE) 
                return registry_[path]->start(params) ? "ACK_OK" : "ACK_FAIL";
            if (act == CliConst::ACT_DISABLE) { 
                registry_[path]->stop(); 
                return "ACK_OK"; 
            }
        }
        return "ACK_NOT_FOUND";
    } catch (...) { 
        return "ACK_JSON_ERR"; 
    }
}