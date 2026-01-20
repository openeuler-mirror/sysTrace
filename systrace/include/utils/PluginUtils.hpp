#pragma once

#include <bpf/bpf.h>
#include <cstdio>
#include <cstring>
#include <elfutils/libdwfl.h>
#include <fcntl.h>
#include <gelf.h>
#include <iostream>
#include <string>
#include <unistd.h>

namespace systrace {
namespace pluginutils {

class PluginUtils {

  public:
    static inline std::vector<int>
    split_pid_string(const std::string &pid_str) {
        std::vector<int> pids;
        std::stringstream ss(pid_str);
        std::string token;

        while (std::getline(ss, token, ',')) {
            token.erase(std::remove_if(token.begin(), token.end(), isspace),
                        token.end());
            if (token.empty()) {
                continue;
            }
            pids.push_back(std::stoi(token));
        }
        return pids;
    }
};

} // namespace pluginutils
} // namespace systrace