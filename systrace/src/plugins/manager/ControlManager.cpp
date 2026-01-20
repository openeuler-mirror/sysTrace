#include "ControlManager.hpp"
#include "../../../include/common/constant.h"
#include <iostream>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using CliConst = systrace::constant::Cli;

ControlManager &ControlManager::getInstance() {
    static ControlManager instance;
    return instance;
}

ControlManager::~ControlManager() { stop(); }

void ControlManager::register_plugin(std::shared_ptr<ICollector> col) {
    if (col) {
        registry_[col->get_id()] = col;
        LOG_MODULE(INFO, "Control") << "Registered plugin: " << col->get_id();
    }
}

void ControlManager::start() {
    if (is_running_.exchange(true))
        return;
    server_thread_ = std::thread(&ControlManager::uds_worker, this);
    LOG_MODULE(INFO, "Control") << "Service thread started.";
}

void ControlManager::stop() {
    if (!is_running_.exchange(false))
        return;

    std::string sock_path = std::string(CliConst::SOCK_DIR) +
                            CliConst::SOCK_PREFIX + std::to_string(getpid()) +
                            CliConst::SOCK_EXT;

    int wakeup_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (wakeup_fd >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);
        connect(wakeup_fd, (struct sockaddr *)&addr, sizeof(addr));
        close(wakeup_fd);
    }

    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    unlink(sock_path.c_str());

    for (auto &[id, plugin] : registry_) {
        plugin->stop();
    }
    registry_.clear();

    LOG_MODULE(INFO, "Control") << "Service stopped and socket unlinked.";
}

void ControlManager::uds_worker() {
    std::string sock_path = std::string(CliConst::SOCK_DIR) +
                            CliConst::SOCK_PREFIX + std::to_string(getpid()) +
                            CliConst::SOCK_EXT;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_MODULE(ERROR, "Control")
            << "Failed to create socket: " << strerror(errno);
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    unlink(sock_path.c_str());
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        LOG_MODULE(ERROR, "Control") << "Bind failed: " << strerror(errno);
        close(fd);
        return;
    }

    listen(fd, 5);
    LOG_MODULE(INFO, "Control") << "Listening on: " << sock_path;

    while (is_running_) {
        int cfd = accept(fd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (!is_running_) {
            close(cfd);
            break;
        }

        char buf[CliConst::MAX_BUF_SIZE] = {0};
        ssize_t n = read(cfd, buf, sizeof(buf) - 1);
        if (n > 0) {
            LOG_MODULE(INFO, "Control") << "Received cmd: " << buf;
            std::string res = handle_msg(buf);
            write(cfd, res.c_str(), res.size());
            LOG_MODULE(INFO, "Control") << "Response sent: " << res;
        }
        close(cfd);
    }
    close(fd);
}

std::string ControlManager::handle_msg(const std::string &raw) {
    std::string clean_raw = raw;
    try {
        while (!clean_raw.empty() &&
               (clean_raw.back() == '\0' || clean_raw.back() == '\r' ||
                clean_raw.back() == '\n' ||
                std::isspace(static_cast<unsigned char>(clean_raw.back())))) {
            clean_raw.pop_back();
        }
        if (clean_raw.empty()) {
            LOG_MODULE(ERROR, "Control")
                << "Received empty message after cleaning.";
            return "ACK_EMPTY";
        }

        auto data = json::parse(clean_raw);

        if (!data.contains(CliConst::KEY_PATH) ||
            !data.contains(CliConst::KEY_ACTION)) {
            LOG_MODULE(ERROR, "Control")
                << "Missing 'path' or 'action' in JSON: " << clean_raw;
            return "ACK_JSON_MISSING_FIELDS";
        }

        std::string path = data.at(CliConst::KEY_PATH);
        std::string act = data.at(CliConst::KEY_ACTION);
        json params = data.value(CliConst::KEY_PARAMS, json::object());

        if (registry_.count(path)) {
            bool success = false;
            if (act == CliConst::ACT_ENABLE) {
                int duration = 0;
                if (params.contains(CliConst::DURATION)) {
                    auto &v = params[CliConst::DURATION];
                    if (v.is_number())
                        duration = v.get<int>();
                    else if (v.is_string())
                        duration = std::stoi(v.get<std::string>());
                }
                LOG_MODULE(INFO, "Control")
                    << "Enabling plugin: " << path
                    << " with params: " << params.dump();
                success = registry_[path]->start(params, duration);
            } else if (act == CliConst::ACT_DISABLE) {
                LOG_MODULE(INFO, "Control") << "Disabling plugin: " << path;
                registry_[path]->stop();
                success = true;
            } else {
                LOG_MODULE(ERROR, "Control") << "Unknown action: " << act;
                return "ACK_UNKNOWN_ACTION";
            }
            return success ? "ACK_OK" : "ACK_FAIL";
        }

        LOG_MODULE(ERROR, "Control") << "Plugin not found: " << path;
        return "ACK_NOT_FOUND";

    } catch (const json::parse_error &e) {
        LOG_MODULE(ERROR, "Control") << "JSON Parse Error: " << e.what();
        LOG_MODULE(ERROR, "Control")
            << "[Control] Problematic Raw Data: [" << clean_raw << "]";
        LOG_MODULE(ERROR, "Control") << "[Control] Raw Data (HEX): ";
        for (unsigned char c : clean_raw)
            fprintf(stderr, "%02x ", c);
        fprintf(stderr, "\n");
        return "ACK_JSON_ERR";
    } catch (const std::exception &e) {
        LOG_MODULE(ERROR, "Control") << "Exception: " << e.what();
        return "ACK_INTERNAL_ERR";
    }
}
