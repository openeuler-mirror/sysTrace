#include "logging.h"
#include <algorithm>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <sstream>

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
        return WARN;
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
    case WARN:
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

bool LogStream::setLogFile(const std::string &base_dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (base_dir.empty())
        return false;

    if (log_file_.is_open())
        log_file_.close();

    std::filesystem::path dir(base_dir);
    try {
        if (!std::filesystem::exists(dir)) {
            std::filesystem::create_directories(dir);
        }
    } catch (...) { return false; }

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << "sysTrace_"
       << std::put_time(std::localtime(&in_time_t), "%Y%m%d_%H%M%S") << ".log";

    std::filesystem::path actual_file_path = dir / ss.str();

    log_file_.open(actual_file_path, std::ios::app);
    file_enabled_ = log_file_.is_open();

    if (file_enabled_) {
        try {
            std::filesystem::path symlink_path = dir / "sysTrace_latest.log";

            if (std::filesystem::exists(symlink_path) ||
                std::filesystem::is_symlink(symlink_path)) {
                std::filesystem::remove(symlink_path);
            }

            std::filesystem::create_symlink(
                std::filesystem::absolute(actual_file_path), symlink_path);
            std::cout << "[LOG] Symlink created: " << symlink_path << " -> "
                      << actual_file_path << std::endl;

        } catch (const std::exception &e) {
            std::cerr << "[LOG] Symlink error: " << e.what() << std::endl;
        }
    }

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
void systrace_log_warn(const char *module, const char *format, ...) {
    va_list args;
    va_start(args, format);
    systrace_log_impl(WARN, module, format, args);
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