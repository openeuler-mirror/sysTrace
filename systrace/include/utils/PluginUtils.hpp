#pragma once

#include <bpf/bpf.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <gelf.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/sysinfo.h>
#include <unistd.h>
using json = nlohmann::json;

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
    static inline void write_file(const std::string &path,
                                  const std::string &content) {
        int fd = open(path.c_str(), O_WRONLY | O_TRUNC);
        if (fd < 0) {
            throw std::runtime_error("[TraceUtils] Open failed: " + path +
                                     " (errno: " + strerror(errno) + ")");
        }

        ssize_t ret = write(fd, content.c_str(), content.length());
        if (ret < 0) {
            int saved_errno = errno;
            close(fd);
            throw std::runtime_error("[TraceUtils] Write failed: " + path +
                                     " (content: " + content +
                                     ", error: " + strerror(saved_errno) + ")");
        }

        fsync(fd);
        close(fd);
    }

    static inline std::vector<std::string> split_string(const std::string &str,
                                                        char delimiter = ',') {
        std::vector<std::string> result;
        std::stringstream ss(str);
        std::string item;
        while (std::getline(ss, item, delimiter)) {
            item.erase(0, item.find_first_not_of(" \t"));
            item.erase(item.find_last_not_of(" \t") + 1);
            if (!item.empty()) {
                result.push_back(item);
            }
        }
        return result;
    }

    static inline std::string ensure_ftrace_path() {
        const char *paths[] = {"/sys/kernel/tracing/",
                               "/sys/kernel/debug/tracing/"};
        for (const char *p : paths) {
            if (access((std::string(p) + "tracing_on").c_str(), F_OK) == 0)
                return p;
        }
        system("mount -t tracefs nodev /sys/kernel/tracing > /dev/null 2>&1");
        if (access("/sys/kernel/tracing/tracing_on", F_OK) == 0)
            return "/sys/kernel/tracing/";
        throw std::runtime_error(
            "[TraceUtils] Failed to find valid ftrace path!");
    }

    static inline int get_cpu_count() {
#ifdef _GNU_SOURCE
        return get_nprocs_conf();
#else
        int count = 0;
        std::ifstream cpuinfo("/proc/cpuinfo");
        std::string line;
        while (std::getline(cpuinfo, line)) {
            if (line.substr(0, 9) == "processor")
                count++;
        }
        return count > 0 ? count : 1;
#endif
    }

    static inline bool parse_cpu_list(const std::string &input,
                                      std::vector<int> &cpus) {
        cpus.clear();
        int cpu_count = get_cpu_count();
        int max_cpu = cpu_count - 1;

        std::stringstream ss(input);
        std::string part;
        while (std::getline(ss, part, ',')) {
            part.erase(std::remove(part.begin(), part.end(), ' '), part.end());
            if (part.empty())
                continue;

            size_t dash_pos = part.find('-');
            if (dash_pos != std::string::npos) {
                int start = atoi(part.substr(0, dash_pos).c_str());
                int end = atoi(part.substr(dash_pos + 1).c_str());
                if (start < 0 || end > max_cpu || start > end) {
                    std::cerr << "[Error] Invalid CPU range: " << part
                              << " (Valid range: 0-" << max_cpu << ")";
                    return false;
                }
                for (int cpu = start; cpu <= end; ++cpu)
                    cpus.push_back(cpu);
            } else {
                int cpu = atoi(part.c_str());
                if (cpu < 0 || cpu > max_cpu) {
                    std::cerr << "[Error] Invalid CPU number: " << part
                              << " (Valid range: 0-" << max_cpu << ")";
                    return false;
                }
                cpus.push_back(cpu);
            }
        }

        std::sort(cpus.begin(), cpus.end());
        cpus.erase(std::unique(cpus.begin(), cpus.end()), cpus.end());
        return !cpus.empty();
    }

    static inline std::string generate_cpu_mask(const std::vector<int> &cpus) {
        int cpu_count = get_cpu_count();
        int group_count = (cpu_count + 31) / 32;
        std::vector<uint32_t> mask_groups(group_count, 0);

        for (int cpu : cpus) {
            int group_idx = cpu / 32;
            int bit_idx = cpu % 32;
            int reversed_group = (group_count - 1) - group_idx;
            mask_groups[reversed_group] |= (1 << bit_idx);
        }

        std::string mask;
        char buf[9];
        for (size_t i = 0; i < mask_groups.size(); ++i) {
            snprintf(buf, sizeof(buf), "%08X", mask_groups[i]);
            mask += buf;
            if (i < mask_groups.size() - 1)
                mask += ",";
        }
        return mask;
    }

    static inline bool safe_parse_boolean(const nlohmann::json &j) {
        if (j.is_boolean()) {
            return j.get<bool>();
        } else if (j.is_string()) {
            std::string s = j.get<std::string>();
            std::transform(s.begin(), s.end(), s.begin(), ::tolower);
            return (s == "true" || s == "1");
        }
        throw std::invalid_argument(
            "Boolean parsing failed: Only boolean/string type (true/false/1/0) "
            "is supported");
    }
};

} // namespace pluginutils
} // namespace systrace