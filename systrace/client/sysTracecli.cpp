#include <iostream>
#include <glob.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "../include/common/constant.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using CliConst = systrace::constant::Cli;

class TraceCLI {
public:
    void broadcast(const std::string& act, const std::string& path, const json& p) {
        json payload;
        payload[CliConst::KEY_ACTION] = act;
        payload[CliConst::KEY_PATH]   = path;
        payload[CliConst::KEY_PARAMS] = p;

        std::string msg = payload.dump();

        glob_t g_res;
        std::string pattern = std::string(CliConst::SOCK_DIR) +
                              CliConst::SOCK_PREFIX + "*" + 
                              CliConst::SOCK_EXT;

        if (glob(pattern.c_str(), 0, nullptr, &g_res) != 0) {
            std::cout << "[WARN] No active instances found." << std::endl;
            return;
        }

        for (size_t i = 0; i < g_res.gl_pathc; ++i) {
            std::string s_path = g_res.gl_pathv[i];
            send_to_uds(s_path, msg);
        }
        globfree(&g_res);
    }

private:
    void send_to_uds(const std::string& s_path, const std::string& msg) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un addr{.sun_family = AF_UNIX};
        strncpy(addr.sun_path, s_path.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(fd, (sockaddr*)&addr, sizeof(addr)) == 0) {
            send(fd, msg.c_str(), msg.size(), 0);
            char buf[256] = {0};
            recv(fd, buf, sizeof(buf) - 1, 0);
            std::cout << "[ACK] " << s_path << ": " << buf << std::endl;
        }
        close(fd);
    }
};

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "Usage: sysTrace_cli <action> <path> [k=v ...]" << std::endl;
        return 1;
    }
    
    std::string act = argv[1];
    std::string path = argv[2];
    
    json params = json::object();
    for (int i = 3; i < argc; ++i) {
        std::string s = argv[i];
        size_t pos = s.find('=');
        if (pos != std::string::npos) {
            params[s.substr(0, pos)] = s.substr(pos + 1);
        }
    }

    TraceCLI().broadcast(act, path, params);
    return 0;
}