#include "logging.h"
#include <cstdarg>
#include <cstdio>
#include <filesystem>

namespace systrace {
namespace log {

LogStream *g_main_log_stream = nullptr;

LogStream::LogStream(std::ostream &console_stream)
    : console_(console_stream), file_enabled_(false) {
    const char *r_str = getenv("RANK");
    if (!r_str)
        r_str = getenv("RANK_ID");
    rank_str_ = r_str ? r_str : "";
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
    case INFO:
        return "[INFO] ";
    case WARNING:
        return "[WARNING] ";
    case ERROR:
        return "[ERROR] ";
    case FATAL:
        return "[FATAL] ";
    default:
        return "[UNKNOWN] ";
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
} // namespace systrace

extern "C" {
static void systrace_log_impl(LogLevel level, const char *module,
                              const char *format, va_list args) {
    char buffer[4096];
    vsnprintf(buffer, sizeof(buffer), format, args);

    systrace::log::LogLine line(systrace::log::getLogStream(), module);
    line << systrace::log::getLogLevelTag(level) << buffer;
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
}