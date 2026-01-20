#include "logging.h"
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <filesystem>

namespace systrace {
namespace log {

LogStream *g_main_log_stream = nullptr;
LogLevel g_min_log_level = INFO;

static LogLevel getLogLevelFromEnv() {
    const char *env_val = getenv("SYSTRACE_LOG_LEVEL");
    if (!env_val)
        return INFO;

    std::string level_str = env_val;

    for (auto &c : level_str)
        c = toupper(c);

    if (level_str == "DEBUG")
        return DEBUG;
    if (level_str == "WARN")
        return WARNING;
    if (level_str == "INFO")
        return INFO;
    if (level_str == "ERROR")
        return ERROR;
    if (level_str == "FATAL")
        return FATAL;

    return INFO;
}

LogStream::LogStream(std::ostream &console_stream)
    : console_(console_stream), file_enabled_(false) {
    const char *r_str = getenv("RANK");
    if (!r_str)
        r_str = getenv("RANK_ID");
    rank_str_ = r_str ? r_str : "";

    static bool level_initialized = false;
    if (!level_initialized) {
        g_min_log_level = getLogLevelFromEnv();
        level_initialized = true;
    }
}

LogStream &getLogStream() {
    static LogStream instance(std::cerr);
    if (g_main_log_stream == nullptr) {
        g_main_log_stream = &instance;
    }
    return *g_main_log_stream;
}

const char *getLogLevelTag(LogLevel level) {
    switch (level) {
    case DEBUG:
        return "DEBUG";
    case WARNING:
        return "WARN";
    case INFO:
        return "INFO";
    case ERROR:
        return "ERROR";
    case FATAL:
        return "FATAL";
    default:
        return "UNKNOWN";
    }
}

bool LogStream::setLogFile(const std::string &file_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_path.empty())
        return false;
    if (log_file_.is_open())
        log_file_.close();

    std::filesystem::path path(file_path);
    std::filesystem::path dir = path.parent_path();
    if (!dir.empty() && !std::filesystem::exists(dir)) {
        try {
            std::filesystem::create_directories(dir);
        } catch (...) { return false; }
    }
    log_file_.open(file_path, std::ios::app);
    file_enabled_ = log_file_.is_open();
    return file_enabled_;
}

void LogStream::closeLogFile() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (log_file_.is_open())
        log_file_.close();
    file_enabled_ = false;
}
} // namespace log

void setLoggingPath(const std::string &file_path) {
    log::getLogStream().setLogFile(file_path);
}

void closeLoggingFile() { log::getLogStream().closeLogFile(); }

void setMinLogLevel(LogLevel level) { log::g_min_log_level = level; }
} // namespace systrace

extern "C" {
void systrace_set_min_log_level(int level) {
    systrace::setMinLogLevel(static_cast<LogLevel>(level));
}

static void systrace_log_impl(LogLevel level, const char *module,
                              const char *format, va_list args) {
    systrace::log::LogLine line(systrace::log::getLogStream(), level, module);
    if (line.isEnabled()) {
        char buffer[4096];
        vsnprintf(buffer, sizeof(buffer), format, args);

        line << "[" << systrace::log::getLogLevelTag(level) << "] " << buffer;
    }
}

void systrace_log_info(const char *module, const char *format, ...) {
    va_list args;
    va_start(args, format);
    systrace_log_impl(INFO, module, format, args);
    va_end(args);
}
void systrace_log_warning(const char *module, const char *format, ...) {
    va_list args;
    va_start(args, format);
    systrace_log_impl(WARNING, module, format, args);
    va_end(args);
}
void systrace_log_error(const char *module, const char *format, ...) {
    va_list args;
    va_start(args, format);
    systrace_log_impl(ERROR, module, format, args);
    va_end(args);
}
void systrace_log_fatal(const char *module, const char *format, ...) {
    va_list args;
    va_start(args, format);
    systrace_log_impl(FATAL, module, format, args);
    va_end(args);
}
void systrace_log_debug(const char *module, const char *format, ...) {
    va_list args;
    va_start(args, format);
    systrace_log_impl(DEBUG, module, format, args);
    va_end(args);
}
}