#include "../include/common/constant.h"
#include <algorithm>
#include <glob.h>
#include <iomanip>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>

using json = nlohmann::json;
using CliConst = systrace::constant::Cli;

struct PluginArg {
    std::string syntax;
    std::string description;
};

struct PluginInfo {
    std::string name;
    std::string description;
    std::vector<PluginArg> specificArgs;
};

class UsageHelper {
  public:
    static void print() {
        std::vector<PluginArg> commonArgs = {
            {"duration=<sec>", "Capture duration in seconds (0 for infinite)"}};

        std::vector<PluginInfo> plugins = {
            {"MSPTI",
             "NVIDIA/Atlas Activity Tracing (HCCL, Kernels)",
             {{"event=<types>", "Comma-separated: marker, kernel, api"}}},
            {"IO", "Disk and Network I/O Latency/Throughput", {}},
            {"CPU", "CPU Utilization and Context Switch Trace", {}},
            {"Memory", "Memory Allocation and Leak Detection", {}}};

        std::cout << "\033[1;36m"
                  << "========================================================="
                  << "\033[0m\n";

        std::cout << "\033[1;33mUSAGE:\033[0m\n";
        std::cout << "  sysTrace_cli <action> <plugin> [key=value ...]\n\n";

        std::cout << "\033[1;33mACTIONS:\033[0m\n";
        std::cout << "  \033[1;32menable\033[0m   Start or update a "
                     "plugin's configuration\n";
        std::cout << "  \033[1;32mdisable\033[0m  Stop a plugin and flush "
                     "data to disk\n\n";

        std::cout << "\033[1;33mCOMMON PARAMETERS:\033[0m\n";
        for (const auto &arg : commonArgs) {
            std::cout << "  " << std::left << std::setw(18) << arg.syntax
                      << "- " << arg.description << "\n";
        }
        std::cout << "\n";

        std::cout << "\033[1;33mPLUGINS & SPECIFIC PARAMETERS:\033[0m\n";
        for (const auto &p : plugins) {
            std::cout << "  \033[1;34m" << std::left << std::setw(12) << p.name
                      << "\033[0m" << p.description << "\n";
            for (const auto &arg : p.specificArgs) {
                std::cout << "    " << std::left << std::setw(16) << arg.syntax
                          << "- " << arg.description << "\n";
            }
            std::cout << "\n";
        }

        std::cout << "\033[1;33mEXAMPLES:\033[0m\n";
        std::cout << "  sysTrace_cli enable MSPTI event=marker,kernel,api "
                     "duration=10\n";
        std::cout << "  sysTrace_cli enable IO duration=10\n";
        std::cout << "  sysTrace_cli enable Memory duration=10\n";
        std::cout << "  sysTrace_cli disable CPU\n";
        std::cout << "\033[1;36m"
                  << "========================================================="
                  << "\033[0m" << std::endl;
    }
};

class TraceCLI {
  public:
    void broadcast(const std::string &act, const std::string &path,
                   const json &p) {
        json payload;
        payload[CliConst::KEY_ACTION] = act;
        payload[CliConst::KEY_PATH] = path;
        payload[CliConst::KEY_PARAMS] = p;

        std::string msg = payload.dump();

        glob_t g_res;
        std::string pattern = std::string(CliConst::SOCK_DIR) +
                              CliConst::SOCK_PREFIX + "*" + CliConst::SOCK_EXT;

        if (glob(pattern.c_str(), 0, nullptr, &g_res) != 0) {
            std::cout << "\033[1;31m[ERROR]\033[0m No active sysTrace "
                         "instances found."
                      << std::endl;
            return;
        }

        for (size_t i = 0; i < g_res.gl_pathc; ++i) {
            send_to_uds(g_res.gl_pathv[i], msg);
        }
        globfree(&g_res);
    }

  private:
    void send_to_uds(const std::string &s_path, const std::string &msg) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
            return;

        sockaddr_un addr{.sun_family = AF_UNIX};
        strncpy(addr.sun_path, s_path.c_str(), sizeof(addr.sun_path) - 1);

        struct timeval tv {
            1, 0
        };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

        if (connect(fd, (sockaddr *)&addr, sizeof(addr)) == 0) {
            send(fd, msg.c_str(), msg.size(), 0);
            char buf[256] = {0};
            if (recv(fd, buf, sizeof(buf) - 1, 0) > 0) {
                std::cout << "\033[1;32m[ACK]\033[0m " << s_path << ": " << buf
                          << std::endl;
            } else {
                std::cout << "\033[1;33m[MSG]\033[0m Command sent to " << s_path
                          << " (No response)" << std::endl;
            }
        }
        close(fd);
    }
};

int main(int argc, char **argv) {
    if (argc < 3) {
        UsageHelper::print();
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