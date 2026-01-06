#pragma once

enum LogLevel
{
    INFO,
    WARNING,
    ERROR,
    FATAL
};

#define LOG(level)                                                             \
    if (level == INFO)                                                         \
        std::cerr << "[INFO] ";                                                \
    else if (level == WARNING)                                                 \
        std::cerr << "[WARNING] ";                                             \
    else if (level == ERROR)                                                   \
        std::cerr << "[ERROR] ";                                               \
    else if (level == FATAL)                                                   \
        std::cerr << "[FATAL] ";                                               \
    std::cerr

#define STLOG(level)                                                           \
    LOG(level) << ::systrace::util::config::GlobalConfig::Instance().rank_str

namespace systrace
{
void setLoggingPath();
}